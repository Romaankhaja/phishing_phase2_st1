from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime
import logging
import os
import socket
import time
from typing import Any
from urllib.parse import urlparse

import pandas as pd

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

from .config import (
    APPLICATION_ID,
    ASN_DB_PATH,
    CITY_DB_PATH,
    FINAL_OUTPUT,
    resolve_ray_runtime_config,
    resolve_stage1_http_config,
)
from .geoip_utils import enrich_with_geoip
from .reliability import CheckpointStore, RunContext, make_record_key, stage_result_patch, utc_now_iso
from .config import RAY_DEBUG_MODE

logger = logging.getLogger(__name__)

_RAY_PRIMITIVES: dict[str, Any] | None = None
_DEBUG_MODE: bool = RAY_DEBUG_MODE


def _is_debug_mode() -> bool:
    """Check if Ray debug mode is enabled (env or config)."""
    return _DEBUG_MODE or os.getenv("PHISHING_RAY_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def _browser_hardened_flags_enabled() -> bool:
    return os.getenv("PHISHING_RAY_BROWSER_HARDENED_FLAGS", "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_hash_browser_launch_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"headless": True}
    if _browser_hardened_flags_enabled():
        kwargs["args"] = [
            "--disable-background-networking",
            "--disable-background-timer-throttling",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-features=Translate,BackForwardCache,MediaRouter,OptimizationHints",
            "--disable-gpu",
            "--disable-renderer-backgrounding",
            "--disable-sync",
            "--mute-audio",
            "--no-default-browser-check",
            "--no-first-run",
        ]
    return kwargs


def _is_browser_lifecycle_error(exc: BaseException | None) -> bool:
    if exc is None:
        return False
    text = f"{exc.__class__.__name__}: {exc}".lower()
    return any(
        marker in text
        for marker in (
            "targetclosederror",
            "browsercontext.new_page",
            "target page, context or browser has been closed",
            "browser has been closed",
            "context has been closed",
            "page has been closed",
            "playwright is closed",
            "connection closed",
        )
    )


def debug_ray_resource_snapshot() -> dict[str, Any]:
    """Dump Ray cluster vs available resources for stall diagnosis."""
    try:
        ray = _import_ray()
        if not ray.is_initialized():
            return {"status": "ray_not_initialized"}
        cluster = ray.cluster_resources()
        available = ray.available_resources()
        return {
            "cluster_cpu": cluster.get("CPU", 0),
            "available_cpu": available.get("CPU", 0),
            "used_cpu": round(cluster.get("CPU", 0) - available.get("CPU", 0), 2),
            "cluster_memory_gb": round(cluster.get("memory", 0) / (1024**3), 2),
            "available_memory_gb": round(available.get("memory", 0) / (1024**3), 2),
            "cluster_object_store_gb": round(cluster.get("object_store_memory", 0) / (1024**3), 2),
            "available_object_store_gb": round(available.get("object_store_memory", 0) / (1024**3), 2),
        }
    except Exception as exc:
        return {"error": str(exc)}


@dataclass(slots=True)
class UrlRecord:
    raw_url: str
    normalized_url: str
    source_workbook: str = ""


@dataclass(slots=True)
class Stage0BatchResult:
    normalized_urls: list[str]
    prefetch_results: list[dict[str, Any]]
    elapsed_ms: float


@dataclass(slots=True)
class Stage1AnalysisRecord:
    raw_url: str
    normalized_url: str
    source_workbook: str
    analysis: dict[str, Any]


@dataclass(slots=True)
class HashRenderArtifact:
    raw_url: str
    normalized_url: str
    source_workbook: str
    prefetch_metrics: dict[str, Any]
    stage1_analysis: dict[str, Any]


@dataclass(slots=True)
class HashDecisionRecord:
    results: list[dict[str, Any]]
    review_results: list[dict[str, Any]]
    decision_rows: list[dict[str, Any]]
    metrics: dict[str, Any]


@dataclass(slots=True)
class ClassificationRecord:
    output_record: dict[str, Any] | None
    review_row: dict[str, Any] | None
    stage2_debug_row: dict[str, Any]
    stage3_debug_row: dict[str, Any]
    checkpoint_patch: dict[str, Any]
    stage_event: dict[str, Any]
    classification: str
    flagged_output: bool
    review_sink: bool


def _import_ray():
    try:
        import ray
    except ImportError as exc:
        raise RuntimeError("Ray is required for the hash_only runtime. Install dependencies from requirements.txt.") from exc
    return ray


def ensure_ray_initialized(*, runtime_config: dict[str, Any] | None = None):
    ray = _import_ray()
    if ray.is_initialized():
        return ray
    runtime_config = resolve_ray_runtime_config(runtime_config)
    address = str(runtime_config.get("address", "") or "").strip()
    _debug = _is_debug_mode()
    init_kwargs = {
        "ignore_reinit_error": True,
        "log_to_driver": _debug,  # Enable in debug mode to see worker logs
        "include_dashboard": False,
    }
    if _debug:
        logger.info("[RAY-DEBUG] Ray init with log_to_driver=True for deep diagnostics")
    requested_local_mode = bool(runtime_config.get("local_mode", False))
    if requested_local_mode:
        logger.warning(
            "Ray local_mode requested, but this pipeline uses async actors and Ray does not support async actors in local mode; forcing local_mode=False"
        )
    init_kwargs["local_mode"] = False
    if not address and psutil is not None:
        try:
            available_memory = int(psutil.virtual_memory().available)
            ray_budget_ratio = 0.35 if bool(runtime_config.get("very_low_memory_mode")) else 0.45 if bool(runtime_config.get("low_memory_mode")) else 0.55
            ray_budget = max(384 * 1024 * 1024, int(available_memory * ray_budget_ratio))
            object_store_memory = max(128 * 1024 * 1024, min(256 * 1024 * 1024, int(ray_budget * 0.35)))
            task_memory = max(256 * 1024 * 1024, ray_budget - object_store_memory)
            init_kwargs["object_store_memory"] = int(object_store_memory)
            init_kwargs["_memory"] = int(task_memory)
            logger.info(
                "Initializing local Ray | available_ram_gb=%.2f | low_memory=%s | local_mode=%s | object_store_mb=%d | task_memory_mb=%d",
                available_memory / (1024 ** 3),
                bool(runtime_config.get("low_memory_mode")),
                bool(runtime_config.get("local_mode")),
                int(object_store_memory / (1024 ** 2)),
                int(task_memory / (1024 ** 2)),
            )
        except Exception:
            logger.exception("Failed to derive conservative local Ray memory settings; falling back to Ray defaults")
    if address:
        init_kwargs["address"] = address
        logger.info("Connecting to Ray cluster | address=%s", address)
    ray.init(**init_kwargs)
    return ray


def shutdown_ray_runtime() -> None:
    ray = _import_ray()
    if ray.is_initialized():
        ray.shutdown()


async def _ray_get(ref, *, _label: str = ""):
    ray = _import_ray()
    if _is_debug_mode():
        t0 = time.perf_counter()
        result = await asyncio.to_thread(ray.get, ref)
        elapsed = time.perf_counter() - t0
        if elapsed > 30.0:
            logger.warning(
                "[RAY-DEBUG] _ray_get slow | label=%s | elapsed=%.1fs — possible resource stall",
                _label or "unknown", elapsed,
            )
        return result
    return await asyncio.to_thread(ray.get, ref)


async def _ray_wait(refs: list[Any], *, num_returns: int = 1, timeout: float | None = None):
    if not refs:
        return [], []
    ray = _import_ray()
    if _is_debug_mode():
        t0 = time.perf_counter()
        ready, not_ready = await asyncio.to_thread(ray.wait, refs, num_returns=num_returns, timeout=timeout)
        elapsed = time.perf_counter() - t0
        if not ready and elapsed > 5.0:
            logger.warning(
                "[RAY-DEBUG] _ray_wait returned EMPTY | waited=%.1fs | pending_refs=%d | resources=%s",
                elapsed, len(refs), debug_ray_resource_snapshot(),
            )
        return ready, not_ready
    return await asyncio.to_thread(ray.wait, refs, num_returns=num_returns, timeout=timeout)


def _ray_context_dict(run_context: RunContext | dict[str, Any] | None) -> dict[str, Any] | None:
    if run_context is None:
        return None
    if isinstance(run_context, dict):
        return dict(run_context)
    return asdict(run_context)


def _run_context_from_value(run_context: RunContext | dict[str, Any] | None) -> RunContext | None:
    if run_context is None:
        return None
    if isinstance(run_context, RunContext):
        return run_context
    return RunContext(**dict(run_context))


class _MetricsActorImpl:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._latency: dict[str, list[float]] = {}

    def increment(self, name: str, amount: float = 1.0) -> None:
        self._counters[name] = float(self._counters.get(name, 0.0) or 0.0) + float(amount)

    def gauge(self, name: str, value: float) -> None:
        self._gauges[name] = float(value)

    def observe_latency(self, name: str, value_ms: float) -> None:
        bucket = self._latency.setdefault(name, [])
        bucket.append(float(value_ms))
        if len(bucket) > 256:
            del bucket[:-256]

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "latency_ms": {
                key: {
                    "count": len(values),
                    "avg": (sum(values) / len(values)) if values else 0.0,
                    "max": max(values) if values else 0.0,
                }
                for key, values in self._latency.items()
            },
        }


class _CheckpointWriterActorImpl:
    def __init__(self, run_context: dict[str, Any]) -> None:
        self._context = _run_context_from_value(run_context)
        if self._context is None:
            raise ValueError("run_context is required")
        self._store = CheckpointStore(self._context)

    def update_manifest(self, **patch: Any) -> None:
        self._store.update_manifest(**patch)

    def ensure_url_results(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            self._store.ensure_url_result(
                raw_url=str(record.get("raw_url", "") or ""),
                normalized_url=str(record.get("normalized_url", "") or ""),
                source_workbook=str(record.get("source_workbook", "") or ""),
            )

    def upsert_url_result(self, patch: dict[str, Any]) -> None:
        self._store.upsert_url_result(patch)

    def append_stage_event(self, event: dict[str, Any]) -> None:
        self._store.append_stage_event(event)

    def append_stage_metric(self, snapshot: dict[str, Any]) -> None:
        self._store.append_stage_metric(snapshot)

    def append_stall_event(self, event: dict[str, Any]) -> None:
        self._store.append_stall_event(event)

    def update_worker_heartbeat(
        self,
        *,
        stage_name: str,
        worker_id: str,
        record_key: str,
        state: str,
        task_kind: str = "",
        item_age_s: float = 0.0,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._store.update_worker_heartbeat(
            stage_name=stage_name,
            worker_id=worker_id,
            record_key=record_key,
            state=state,
            task_kind=task_kind,
            item_age_s=item_age_s,
            details=details,
        )

    def clear_worker_heartbeat(self, *, stage_name: str, worker_id: str) -> None:
        self._store.clear_worker_heartbeat(stage_name=stage_name, worker_id=worker_id)

    def get_completed_record_keys(self) -> set[str]:
        return self._store.get_completed_record_keys()

    def get_terminal_submission_records(self) -> list[dict[str, Any]]:
        return self._store.get_terminal_submission_records()

    def get_backlog_snapshot(self) -> dict[str, Any]:
        return self._store.snapshot_backlog()

    def export_all(self) -> None:
        self._store.export_all(best_effort=True)

    def mark_completed(self) -> None:
        self._store.mark_completed()
        self._store.export_all(best_effort=True)

    def mark_failed(self, *, stage: str, error_type: str = "", error_message: str = "") -> None:
        self._store.update_manifest(
            status="failed",
            completed_at=utc_now_iso(),
            fatal_stage=stage,
            fatal_error_type=error_type,
            fatal_error_message=error_message,
        )
        self._store.export_all(best_effort=True)

    def close(self) -> None:
        self._store.close()


class _LookupCacheActorImpl:
    def __init__(self) -> None:
        self._rdap: dict[str, dict[str, Any]] = {}
        self._dns: dict[str, dict[str, Any]] = {}

    def get_rdap(self, domain: str) -> dict[str, Any] | None:
        return self._rdap.get(str(domain or "").strip().lower())

    def put_rdap(self, domain: str, payload: dict[str, Any]) -> None:
        self._rdap[str(domain or "").strip().lower()] = dict(payload or {})

    def get_dns(self, domain: str) -> dict[str, Any] | None:
        return self._dns.get(str(domain or "").strip().lower())

    def put_dns(self, domain: str, payload: dict[str, Any]) -> None:
        self._dns[str(domain or "").strip().lower()] = dict(payload or {})


class _WhoisCoordinatorActorImpl:
    def __init__(self, requests_per_minute: int = 20) -> None:
        self._interval_seconds = 60.0 / max(1, int(requests_per_minute))
        self._next_ready_monotonic = 0.0

    async def acquire(self) -> None:
        now = time.monotonic()
        delay = max(0.0, self._next_ready_monotonic - now)
        self._next_ready_monotonic = max(self._next_ready_monotonic, now) + self._interval_seconds
        if delay > 0:
            await asyncio.sleep(delay)


class _Stage1FetchActorImpl:
    def __init__(self, stage1_http_config: dict[str, Any]) -> None:
        import httpx

        self._config = resolve_stage1_http_config(stage1_http_config)
        limits = httpx.Limits(
            max_connections=max(
                1,
                int(
                    self._config.get(
                        "stage1_http_connection_limit",
                        self._config.get("http_concurrency", self._config.get("concurrency", 24)),
                    )
                ),
            ),
            max_keepalive_connections=max(
                1,
                int(self._config.get("stage1_http_keepalive_limit", self._config.get("concurrency", 24))),
            ),
        )
        timeout = httpx.Timeout(self._config["get_timeout"], connect=self._config["connect_timeout"])
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            limits=limits,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ray-stage1-fetch/1.0)"},
        )

    async def warm(self) -> dict[str, Any]:
        return {
            "ready": True,
            "connection_limit": int(self._config.get("stage1_http_connection_limit", 0) or 0),
            "keepalive_limit": int(self._config.get("stage1_http_keepalive_limit", 0) or 0),
        }

    async def fetch(self, record: dict[str, Any]) -> dict[str, Any]:
        from .stage1_http_analyzer import fetch_stage1_http_artifacts

        started = time.perf_counter()
        payload = await fetch_stage1_http_artifacts(
            str(record.get("raw_url", "") or ""),
            self._client,
            config=self._config,
        )
        return {
            "record": dict(record),
            "payload": payload,
            "elapsed_ms": max(0.0, (time.perf_counter() - started) * 1000.0),
        }

    async def close(self) -> None:
        await self._client.aclose()


class _Stage1EnrichActorImpl:
    def __init__(self, stage1_http_config: dict[str, Any], lookup_cache: Any | None = None) -> None:
        import httpx

        self._config = resolve_stage1_http_config(stage1_http_config)
        self._lookup_cache = lookup_cache
        self._client = httpx.AsyncClient(
            timeout=self._config["rdap_timeout"],
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ray-stage1-enrich/1.0)"},
        )

    async def warm(self) -> dict[str, Any]:
        return {
            "ready": True,
            "rdap_timeout": float(self._config.get("rdap_timeout", 0.0) or 0.0),
        }

    async def _cache_get(self, kind: str, key: str) -> dict[str, Any] | None:
        if self._lookup_cache is None:
            return None
        ray = _import_ray()
        method = self._lookup_cache.get_rdap if kind == "rdap" else self._lookup_cache.get_dns
        return await asyncio.to_thread(ray.get, method.remote(key))

    async def _cache_put(self, kind: str, key: str, payload: dict[str, Any]) -> None:
        if self._lookup_cache is None:
            return
        method = self._lookup_cache.put_rdap if kind == "rdap" else self._lookup_cache.put_dns
        method.remote(key, payload)

    async def enrich(self, record: dict[str, Any], result: dict[str, Any], dns_prefetch: dict[str, Any] | None = None) -> dict[str, Any]:
        from .rdap_utils import lookup_rdap
        from .stage1_http_analyzer import (
            _age_days_from_creation,
            _fetch_tls_summary,
            _normalize_host,
            _resolve_dns_answers,
            get_stage1_entity_context,
            lookup_geoip_summary,
            score_stage1_http_signals,
        )

        started = time.perf_counter()
        enriched = dict(result or {})
        final_domain = _normalize_host(
            enriched.get("final_domain") or urlparse(str(enriched.get("final_landing_url") or "")).netloc
        )
        original_domain = _normalize_host(
            enriched.get("original_domain") or urlparse(str(enriched.get("normalized_url") or "")).netloc
        )
        if final_domain:
            same_domain_reuse = bool(dns_prefetch) and final_domain == original_domain
            dns_info = None
            if same_domain_reuse:
                dns_info = dict(dns_prefetch or {})
            else:
                dns_info = await self._cache_get("dns", final_domain)
                if dns_info is None:
                    dns_info = await _resolve_dns_answers(final_domain, float(self._config["dns_timeout"]))
                    await self._cache_put("dns", final_domain, dns_info)
            if isinstance(dns_info, dict):
                resolved_ips = dns_info.get("resolved_ips", [])
                if isinstance(resolved_ips, str):
                    resolved_ips = [item.strip() for item in resolved_ips.split(";") if item.strip()]
                enriched["resolved_ips"] = list(resolved_ips or [])
                enriched["dns_answer_count"] = int(dns_info.get("dns_answer_count", len(enriched["resolved_ips"])) or 0)
                if enriched["resolved_ips"]:
                    geoip = lookup_geoip_summary(enriched["resolved_ips"][0])
                    enriched["asn"] = geoip.get("asn")
                    enriched["asn_org"] = str(geoip.get("asn_org") or "")
                    enriched["country"] = str(geoip.get("country") or "")

            rdap_info = await self._cache_get("rdap", final_domain)
            if rdap_info is None:
                rdap_info = await lookup_rdap(
                    final_domain,
                    client=self._client,
                    timeout=float(self._config["rdap_timeout"]),
                )
                await self._cache_put("rdap", final_domain, rdap_info)
            if isinstance(rdap_info, dict):
                creation_date = rdap_info.get("creation_date")
                enriched["rdap_creation_date"] = creation_date
                enriched["rdap_age_days"] = _age_days_from_creation(creation_date)

            tls_info = await _fetch_tls_summary(final_domain, float(self._config["tls_timeout"]))
            if isinstance(tls_info, dict):
                enriched["cert_cn"] = str(tls_info.get("cert_cn") or "")
                enriched["cert_san"] = list(tls_info.get("cert_san") or [])
                enriched["cert_issuer"] = str(tls_info.get("cert_issuer") or "")

        entity_context, ordered_entities = get_stage1_entity_context()
        enriched.update(
            score_stage1_http_signals(
                enriched,
                entity_context=entity_context,
                ordered_entities=ordered_entities,
                config=self._config,
            )
        )
        return {
            "record": dict(record),
            "result": enriched,
            "elapsed_ms": max(0.0, (time.perf_counter() - started) * 1000.0),
        }

    async def close(self) -> None:
        await self._client.aclose()


class _HashBrowserActorImpl:
    def __init__(self, tabs_per_actor: int, per_host_limit: int) -> None:
        self._tabs_per_actor = max(1, int(tabs_per_actor))
        self._per_host_limit = max(1, int(per_host_limit))
        self._lock = asyncio.Lock()
        self._page_semaphore = asyncio.Semaphore(self._tabs_per_actor)
        self._playwright = None
        self._browser = None
        self._context = None
        self._active_fetch_limiter = None
        self._host_limiter = None
        self._context_resets = 0
        self._render_retries = 0
        self._render_retry_exhausted = 0
        self._pages_rendered = 0
        self._recycle_threshold = 250

    async def _reset_browser(self, *, reason: str = "") -> None:
        async with self._lock:
            for cleanup in (
                self._context.close if self._context is not None else None,
                self._browser.close if self._browser is not None else None,
                self._playwright.stop if self._playwright is not None else None,
            ):
                if cleanup is None:
                    continue
                try:
                    await cleanup()
                except Exception:
                    pass
            self._playwright = None
            self._browser = None
            self._context = None
            self._active_fetch_limiter = None
            self._host_limiter = None
            self._context_resets += 1
            if _is_debug_mode() or reason:
                logger.warning(
                    "Hash browser actor reset | reason=%s | tabs_per_actor=%d | resets=%d",
                    str(reason or "unknown"),
                    self._tabs_per_actor,
                    self._context_resets,
                )

    async def _ensure_browser(self) -> None:
        if self._browser is not None:
            return
        async with self._lock:
            if self._browser is not None:
                return
            from . import comparison
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            launch_kwargs = _resolve_hash_browser_launch_kwargs()
            if _is_debug_mode():
                logger.info(
                    "[RAY-DEBUG] Hash browser launch | hardened_flags=%s | kwargs=%s",
                    _browser_hardened_flags_enabled(),
                    launch_kwargs,
                )
            self._browser = await self._playwright.chromium.launch(**launch_kwargs)
            self._context = await self._browser.new_context(ignore_https_errors=True, service_workers="block")
            await self._context.route("**/*", comparison._route_nonessential_requests)
            self._context.set_default_navigation_timeout(comparison.SCRAPER_NAV_TIMEOUT_MS)
            self._context.set_default_timeout(comparison.SCRAPER_SCREENSHOT_TIMEOUT_MS)
            self._active_fetch_limiter = comparison._AdaptiveFetchLimiter(self._tabs_per_actor)
            self._host_limiter = comparison._PerHostLimiter(self._per_host_limit)

    async def warm(self) -> dict[str, Any]:
        await self._ensure_browser()
        return {
            "ready": True,
            "tabs_per_actor": self._tabs_per_actor,
            "browser_context_resets": self._context_resets,
            "browser_render_retries": self._render_retries,
            "browser_render_retry_exhausted": self._render_retry_exhausted,
        }

    async def render(self, artifact: dict[str, Any]) -> dict[str, Any]:
        from . import comparison

        await self._ensure_browser()
        async with self._page_semaphore:
            self._pages_rendered += 1
            if self._pages_rendered >= self._recycle_threshold and not self._page_semaphore.locked():
                await self._reset_browser(reason="periodic_context_flush")
                self._pages_rendered = 0

            browser_retry_taken = False
            for attempt_index in range(2):
                page = None
                try:
                    await self._ensure_browser()
                    page = await self._context.new_page()
                    payload = await comparison._render_hash_payload_on_page(
                        str(artifact.get("raw_url", "") or artifact.get("normalized_url", "")),
                        page,
                        self._active_fetch_limiter,
                        self._host_limiter,
                        prefetch_metrics=dict(artifact.get("prefetch_metrics", {}) or {}),
                        stage1_analysis=dict(artifact.get("stage1_analysis", {}) or {}),
                    )
                    if browser_retry_taken:
                        payload["_browser_context_reset"] = True
                        payload["_browser_render_retry"] = True
                    return payload
                except Exception as exc:
                    if attempt_index == 0 and _is_browser_lifecycle_error(exc):
                        browser_retry_taken = True
                        self._render_retries += 1
                        await self._reset_browser(reason=f"render_retry:{type(exc).__name__}")
                        continue
                    if browser_retry_taken:
                        self._render_retry_exhausted += 1
                        raise RuntimeError(f"browser_actor_failure_after_retry: {exc}") from exc
                    raise
                finally:
                    if page is not None and not page.is_closed():
                        try:
                            await asyncio.wait_for(page.close(), timeout=3.0)
                        except Exception:
                            await self._reset_browser(reason="stuck_page_close")
            raise RuntimeError("browser_actor_failure_after_retry: render loop exhausted")

    async def stats(self) -> dict[str, Any]:
        return {
            "ready": bool(self._browser is not None and self._context is not None),
            "tabs_per_actor": self._tabs_per_actor,
            "browser_context_resets": int(self._context_resets),
            "browser_render_retries": int(self._render_retries),
            "browser_render_retry_exhausted": int(self._render_retry_exhausted),
        }

    async def close(self) -> None:
        await self._reset_browser(reason="close")


class _OcrWorkerActorImpl:
    def __init__(self, max_batch_size: int = 32, max_batch_delay_ms: int = 25) -> None:
        self._max_batch_size = max(1, int(max_batch_size))
        self._max_batch_delay_seconds = max(0.001, float(max_batch_delay_ms) / 1000.0)
        self._request_queue: asyncio.Queue[Any] = asyncio.Queue()
        self._closed = False
        self._prewarmed = False
        self._batches_processed = 0
        self._items_processed = 0
        self._last_batch_size = 0
        self._drain_task = asyncio.create_task(self._drain_loop())

    def _warm_reader(self) -> None:
        from .visual_features import _get_ocr_reader

        _get_ocr_reader()

    async def warm(self) -> dict[str, Any]:
        if not self._prewarmed:
            await asyncio.to_thread(self._warm_reader)
            self._prewarmed = True
        return self.stats()

    async def extract(self, request: dict[str, Any]) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("OCR worker is closed")
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        await self._request_queue.put((dict(request or {}), future))
        return await future

    async def _drain_loop(self) -> None:
        while True:
            item = await self._request_queue.get()
            if item is None:
                break
            batch = [item]
            deadline = time.perf_counter() + self._max_batch_delay_seconds
            stop_requested = False
            while len(batch) < self._max_batch_size:
                timeout = deadline - time.perf_counter()
                if timeout <= 0:
                    break
                try:
                    next_item = await asyncio.wait_for(self._request_queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    break
                if next_item is None:
                    stop_requested = True
                    break
                batch.append(next_item)
            await self._process_batch(batch)
            if stop_requested:
                break

    async def _process_batch(self, batch: list[Any]) -> None:
        if not batch:
            return
        if not self._prewarmed:
            await self.warm()
        from . import pipeline as pipeline_module

        self._batches_processed += 1
        self._items_processed += len(batch)
        self._last_batch_size = len(batch)
        for request, future in batch:
            if future.cancelled():
                continue
            try:
                result = await pipeline_module._extract_hash_only_ocr_tvc(
                    str(request.get("domain_url", "") or ""),
                    str(request.get("screenshot_path", "") or ""),
                    shortlisted_cse=str(request.get("shortlisted_cse", "") or ""),
                    shortlisted_domain=str(request.get("shortlisted_domain", "") or ""),
                    html_text=str(request.get("html_text", "") or ""),
                )
            except Exception as exc:
                if not future.done():
                    future.set_exception(exc)
            else:
                if not future.done():
                    future.set_result(result)

    def stats(self) -> dict[str, Any]:
        return {
            "ready": bool(self._prewarmed),
            "max_batch_size": int(self._max_batch_size),
            "batch_delay_ms": int(round(self._max_batch_delay_seconds * 1000.0)),
            "queue_depth": int(self._request_queue.qsize()),
            "batches_processed": int(self._batches_processed),
            "items_processed": int(self._items_processed),
            "last_batch_size": int(self._last_batch_size),
        }

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._request_queue.put(None)
        await self._drain_task


class _HashOnlyClassifierActorImpl:
    def __init__(self, failed_fetch_suspected_min: float | None = None, failed_fetch_review_min: float | None = None) -> None:
        import httpx

        self._failed_fetch_suspected_min = failed_fetch_suspected_min
        self._failed_fetch_review_min = failed_fetch_review_min
        self._client = httpx.AsyncClient(follow_redirects=True, timeout=10.0)
        self._infrastructure_cache: dict[str, dict[str, Any]] = {
            "resolved_ip_by_host": {},
            "rdap_by_host": {},
            "whois_by_host": {},
            "dns_by_host": {},
            "geoip_by_ip": {},
        }
        self._models_load_attempted = False
        self._brand_model = None
        self._domain_model = None
        self._brand_classes: list[str] = []
        self._source_classes: list[str] = []
        self._feature_cols: list[str] = []
        self._scaler = None
        self._imputer = None

    def _ensure_models_loaded(self) -> None:
        if self._models_load_attempted:
            return
        self._models_load_attempted = True
        try:
            from .model_utils import load_models_and_preproc

            (
                self._brand_model,
                self._domain_model,
                brand_label_encoder,
                self._source_classes,
                self._feature_cols,
                self._scaler,
                self._imputer,
            ) = load_models_and_preproc()
            self._brand_classes = list(getattr(brand_label_encoder, "classes_", []))
        except Exception:
            self._brand_model = None
            self._domain_model = None
            self._brand_classes = []
            self._source_classes = []
            self._feature_cols = []
            self._scaler = None
            self._imputer = None

    async def warm(self) -> dict[str, Any]:
        return {
            "ready": True,
            "brand_model_loaded": bool(self._brand_model is not None),
            "domain_model_loaded": bool(self._domain_model is not None),
        }

    async def classify_row(self, row: dict[str, Any], sequence_number: int, ocr_worker: Any, whois_actor: Any) -> dict[str, Any]:
        from . import pipeline as pipeline_module

        fetch_status = str(row.get("fetch_status", "fetched") or "fetched").strip().lower()
        if fetch_status in {"fetched", "fetched_visual_missing"} and not pipeline_module._requires_registration_only_enrichment(row):
            self._ensure_models_loaded()
        return await _classify_hash_only_row_impl(
            row=row,
            sequence_number=sequence_number,
            client=self._client,
            brand_model=self._brand_model,
            domain_model=self._domain_model,
            brand_classes=self._brand_classes,
            source_classes=self._source_classes,
            feature_cols=self._feature_cols,
            scaler=self._scaler,
            imputer=self._imputer,
            failed_fetch_suspected_min=self._failed_fetch_suspected_min,
            failed_fetch_review_min=self._failed_fetch_review_min,
            ocr_worker=ocr_worker,
            whois_actor=whois_actor,
            infrastructure_cache=self._infrastructure_cache,
        )

    async def close(self) -> None:
        await self._client.aclose()


def _stage0_batch_task_impl(normalized_urls: list[str], lexical_eval_config: tuple[int, float]) -> dict[str, Any]:
    from . import comparison

    started = time.perf_counter()
    results = comparison._compute_prefetch_lexical_state_batch(normalized_urls, lexical_eval_config)
    return asdict(
        Stage0BatchResult(
            normalized_urls=list(normalized_urls),
            prefetch_results=list(results),
            elapsed_ms=max(0.0, (time.perf_counter() - started) * 1000.0),
        )
    )


def _stage1_parse_task_impl(record: dict[str, Any], payload: dict[str, Any], stage1_http_config: dict[str, Any]) -> dict[str, Any]:
    from .stage1_http_analyzer import (
        get_stage1_entity_context,
        parse_stage1_html_payload,
        score_stage1_http_signals,
        should_enrich_stage1_result,
    )

    config = resolve_stage1_http_config(stage1_http_config)
    result = dict(payload.get("result") or {})
    html_bytes = payload.get("html_bytes") or b""
    response_encoding = payload.get("response_encoding")
    normalized_url = str(record.get("normalized_url", "") or result.get("normalized_url", ""))
    if html_bytes:
        result.update(
            parse_stage1_html_payload(
                html_bytes,
                charset=response_encoding,
                final_url=result.get("final_landing_url") or normalized_url,
                max_html_bytes=int(config["max_html_bytes"]),
            )
        )
    entity_context, ordered_entities = get_stage1_entity_context()
    result.update(
        score_stage1_http_signals(
            result,
            entity_context=entity_context,
            ordered_entities=ordered_entities,
            config=config,
        )
    )
    return {
        "record": dict(record),
        "result": result,
        "should_enrich": bool(should_enrich_stage1_result(result, config=config)),
    }


async def _hash_enrich_task_async_impl(render_payload: dict[str, Any], prefetch_metrics: dict[str, Any], stage1_analysis: dict[str, Any], scoring_config: dict[str, Any]) -> dict[str, Any]:
    import aiohttp

    from . import comparison

    connector = aiohttp.TCPConnector(limit=comparison.HASH_AUX_HTTP_LIMIT, ttl_dns_cache=300)
    session = aiohttp.ClientSession(connector=connector)
    try:
        return await comparison._enrich_render_payload_for_hashing(
            render_payload,
            aio_session=session,
            scoring_config=scoring_config,
            prefetch_metrics=prefetch_metrics,
            stage1_analysis=stage1_analysis,
        )
    finally:
        await session.close()


def _hash_enrich_task_impl(render_payload: dict[str, Any], prefetch_metrics: dict[str, Any], stage1_analysis: dict[str, Any], scoring_config: dict[str, Any]) -> dict[str, Any]:
    return asyncio.run(
        _hash_enrich_task_async_impl(
            render_payload,
            prefetch_metrics,
            stage1_analysis,
            scoring_config,
        )
    )


def _hash_finalize_batch_task_impl(batch: list[dict[str, Any]], threshold: float, scoring_config: dict[str, Any]) -> dict[str, Any]:
    from . import comparison

    metrics = {
        "processed": 0,
        "hashed_success": 0,
        "fetch_failed": 0,
        "fetch_timed_out": 0,
        "final_matches_above_threshold": 0,
        "finalized": 0,
        "gpu_batches_flushed": 1,
        "gpu_items_scored": 0,
        "avg_gpu_batch_size": float(len(batch)),
    }
    results: list[dict[str, Any]] = []
    review_results: list[dict[str, Any]] = []
    decision_rows: list[dict[str, Any]] = []
    for payload in batch:
        comparison._finalize_scored_hash_payload(
            payload,
            payload["cpu_scores"],
            payload["cpu_denominators"],
            metrics,
            results,
            review_results,
            decision_rows,
            threshold,
            scoring_config,
        )
        metrics["gpu_items_scored"] += 1
    parity_mismatches = comparison._validate_ray_hash_finalize_transport(
        decision_rows=decision_rows,
        results=results,
        review_results=review_results,
    )
    metrics["transport_parity_mismatches"] = len(parity_mismatches)
    if parity_mismatches:
        logger.error(
            "Ray hash finalize transport mismatch | mismatches=%d | sample=%s",
            len(parity_mismatches),
            parity_mismatches[:2],
        )
    return asdict(
        HashDecisionRecord(
            results=results,
            review_results=review_results,
            decision_rows=decision_rows,
            metrics=metrics,
        )
    )


def _get_ray_primitives() -> dict[str, Any]:
    global _RAY_PRIMITIVES
    if _RAY_PRIMITIVES is not None:
        return _RAY_PRIMITIVES
    ray = _import_ray()
    stage0_task_cpu = 1.0
    light_task_cpu = 0.5
    finalize_task_cpu = 1.0
    logger.info(
        "[RAY-DEBUG] Registering Ray primitives | stage0_cpu=%.2f | light_task_cpu=%.2f | finalize_cpu=%.2f | debug_mode=%s",
        stage0_task_cpu, light_task_cpu, finalize_task_cpu, _is_debug_mode(),
    )
    _RAY_PRIMITIVES = {
        "ray": ray,
        "MetricsActor": ray.remote(num_cpus=0, max_concurrency=64)(_MetricsActorImpl),
        "CheckpointWriterActor": ray.remote(num_cpus=0, max_concurrency=8)(_CheckpointWriterActorImpl),
        "LookupCacheActor": ray.remote(num_cpus=0, max_concurrency=32)(_LookupCacheActorImpl),
        "WhoisCoordinatorActor": ray.remote(num_cpus=0, max_concurrency=32)(_WhoisCoordinatorActorImpl),
        "Stage1FetchActor": ray.remote(_Stage1FetchActorImpl),
        "Stage1EnrichActor": ray.remote(_Stage1EnrichActorImpl),
        "HashBrowserActor": ray.remote(_HashBrowserActorImpl),
        "OcrWorkerActor": ray.remote(num_cpus=1, max_concurrency=64)(_OcrWorkerActorImpl),
        "HashOnlyClassifierActor": ray.remote(num_cpus=1)(_HashOnlyClassifierActorImpl),
        "stage0_batch_task": ray.remote(num_cpus=stage0_task_cpu)(_stage0_batch_task_impl),
        "stage1_parse_task": ray.remote(num_cpus=light_task_cpu)(_stage1_parse_task_impl),
        "hash_enrich_task": ray.remote(num_cpus=light_task_cpu)(_hash_enrich_task_impl),
        "hash_finalize_batch_task": ray.remote(num_cpus=finalize_task_cpu)(_hash_finalize_batch_task_impl),
    }
    return _RAY_PRIMITIVES


async def _log_metrics_periodically(
    metrics_actor: Any,
    stop_event: asyncio.Event,
    label: str,
    interval_seconds: float,
    *,
    checkpoint_actor: Any | None = None,
    stage_name: str = "",
    metric_kind: str = "snapshot",
    details_getter: Any | None = None,
    resource_snapshot_getter: Any | None = None,
    emit_logs: bool = True,
) -> None:
    while not stop_event.is_set():
        try:
            snapshot = await _ray_get(metrics_actor.snapshot.remote())
            resource_snapshot = (
                dict(resource_snapshot_getter() or {})
                if callable(resource_snapshot_getter)
                else debug_ray_resource_snapshot()
            )
            details = (
                dict(details_getter() or {})
                if callable(details_getter)
                else {}
            )
            if checkpoint_actor is not None:
                checkpoint_actor.append_stage_metric.remote(
                    {
                        "emitted_at": utc_now_iso(),
                        "label": label,
                        "stage_name": stage_name or label,
                        "metric_kind": metric_kind,
                        "counters": dict(snapshot.get("counters") or {}),
                        "gauges": dict(snapshot.get("gauges") or {}),
                        "latency_ms": dict(snapshot.get("latency_ms") or {}),
                        "resource_snapshot": resource_snapshot,
                        "details": details,
                    }
                )
            if emit_logs:
                logger.info("Ray %s metrics | snapshot=%s | resources=%s | details=%s", label, snapshot, resource_snapshot, details)
        except Exception:
            logger.exception("Failed to snapshot Ray metrics for %s", label)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=max(1.0, interval_seconds))
        except asyncio.TimeoutError:
            pass


def _build_shortlist_stage_event(
    *,
    run_context: RunContext | None,
    raw_url: str,
    normalized_url: str,
    source_workbook: str,
    stage_name: str,
    worker_id: str,
    started_at: str,
    started_monotonic: float,
    status: str,
    retry_count: int = 0,
    timeout_flag: bool = False,
    error_type: str = "",
    error_message: str = "",
    fallback_taken: str = "",
) -> dict[str, Any] | None:
    if run_context is None:
        return None
    return {
        "run_id": run_context.run_id,
        "record_key": make_record_key(normalized_url, source_workbook),
        "source_workbook": source_workbook,
        "normalized_url": normalized_url,
        "stage_name": stage_name,
        "attempt_index": max(1, int(retry_count) + 1),
        "worker_id": worker_id,
        "started_at": started_at,
        "finished_at": utc_now_iso(),
        "duration_ms": int(max(0.0, (time.perf_counter() - started_monotonic) * 1000.0)),
        "status": status,
        "error_type": error_type,
        "error_message": error_message,
        "retry_count": int(retry_count),
        "timeout_flag": int(bool(timeout_flag)),
        "fallback_taken": fallback_taken,
    }


def _build_shortlist_patch(
    *,
    run_context: RunContext | None,
    raw_url: str,
    normalized_url: str,
    source_workbook: str,
    stage_name: str,
    stage_status: str,
    current_stage: str,
    retry_count: int = 0,
    timeout_hit: bool = False,
    fallback_taken: str = "",
    worker_id: str = "",
    error_type: str = "",
    error_message: str = "",
    final_pipeline_status: str | None = None,
    failure_reason: str = "",
) -> dict[str, Any] | None:
    if run_context is None:
        return None
    return stage_result_patch(
        run_id=run_context.run_id,
        raw_url=raw_url,
        normalized_url=normalized_url,
        source_workbook=source_workbook,
        stage_name=stage_name,
        stage_status=stage_status,
        current_stage=current_stage,
        retry_count=retry_count,
        timeout_hit=timeout_hit,
        fallback_taken=fallback_taken,
        worker_id=worker_id,
        error_type=error_type,
        error_message=error_message,
        final_pipeline_status=final_pipeline_status,
        failure_reason=failure_reason,
    )


async def _flush_finalize_buffer(
    *,
    finalize_buffer: list[dict[str, Any]],
    pending: dict[Any, tuple[str, Any]],
    threshold: float,
    scoring_config: dict[str, Any],
) -> None:
    if not finalize_buffer:
        return
    primitives = _get_ray_primitives()
    batch = list(finalize_buffer)
    ref = primitives["hash_finalize_batch_task"].remote(batch, threshold, scoring_config)
    first_record_key = next(
        (str(item.get("record_key", "") or "") for item in batch if str(item.get("record_key", "") or "").strip()),
        "",
    )
    pending[ref] = (
        "hash_finalize",
        {
            "size": len(batch),
            "progress_keys": [str(item.get("progress_key", "") or "") for item in batch if str(item.get("progress_key", "") or "")],
            "record_key": first_record_key,
            "worker_id": f"hash-finalize-{(first_record_key or 'batch')[:8]}",
            "submitted_monotonic": time.perf_counter(),
        },
    )
    finalize_buffer.clear()


async def run_hashing_shortlist_with_ray(
    url_list,
    *,
    threshold: float,
    domain_similarity_threshold: float,
    high_confidence_threshold: float,
    medium_confidence_threshold: float,
    typo_top_k: int,
    typo_min_score: float,
    lexical_pass_min_score: float,
    weights: dict[str, float] | None = None,
    shortlist_debug_csv: str | None = None,
    url_sources: dict | None = None,
    keep_stage1_suspected: bool = False,
    keep_fetch_failed_strict_lexical: bool = False,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
    run_context: RunContext | None = None,
    checkpoint_store=None,
    resume: bool = False,
    force_reprocess: bool = False,
    progress_mode: str | None = None,
):
    from .ray_shortlist_runtime import run_hashing_shortlist_with_ray_impl

    return await run_hashing_shortlist_with_ray_impl(
        url_list,
        threshold=threshold,
        domain_similarity_threshold=domain_similarity_threshold,
        high_confidence_threshold=high_confidence_threshold,
        medium_confidence_threshold=medium_confidence_threshold,
        typo_top_k=typo_top_k,
        typo_min_score=typo_min_score,
        lexical_pass_min_score=lexical_pass_min_score,
        weights=weights,
        shortlist_debug_csv=shortlist_debug_csv,
        url_sources=url_sources,
        keep_stage1_suspected=keep_stage1_suspected,
        keep_fetch_failed_strict_lexical=keep_fetch_failed_strict_lexical,
        stage1_escalate_total_threshold=stage1_escalate_total_threshold,
        stage1_brand_min=stage1_brand_min,
        stage1_credential_min=stage1_credential_min,
        stage1_low_band_min=stage1_low_band_min,
        stage1_hard_trigger_brand_min=stage1_hard_trigger_brand_min,
        run_context=run_context,
        checkpoint_store=checkpoint_store,
        resume=resume,
        force_reprocess=force_reprocess,
        progress_mode=progress_mode,
    )


async def _classify_hash_only_row_impl(**kwargs: Any) -> dict[str, Any]:
    from .ray_classify_runtime import classify_hash_only_row_impl

    return await classify_hash_only_row_impl(**kwargs)


async def run_hash_only_pipeline_with_ray(**kwargs: Any) -> pd.DataFrame:
    from .ray_classify_runtime import run_hash_only_pipeline_with_ray_impl

    return await run_hash_only_pipeline_with_ray_impl(**kwargs)
