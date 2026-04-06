from __future__ import annotations

import asyncio
import csv
import logging
import os
import time
from collections import Counter
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver

from .config import OUTPUT_DIR
from .reliability import (
    CheckpointStore,
    ProgressTracker,
    RunContext,
    STAGE_EVENT_COLUMNS,
    StageWatchdog,
    async_with_timeout_and_retry,
    make_record_key,
    normalize_exception,
    stage_result_patch,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

DEFAULT_DNS_TIMEOUT = 5.0
DEFAULT_DNS_RETRIES = 2
DEFAULT_AUDIT_PATH = os.path.join(OUTPUT_DIR, "dns_gate_audit.csv")
DEFAULT_FALLBACK_NAMESERVERS = ("1.1.1.1", "8.8.8.8")
_AUDIT_FIELDNAMES = [
    "target_url",
    "source_workbook",
    "hostname",
    "resolved_ips",
    "dns_status",
    "decision",
    "attempts",
    "retry_count",
    "retry_success",
    "resolver_profile",
]


def _read_env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        logger.warning("Invalid integer override for %s=%r; using %d", name, raw, default)
        return default


DEFAULT_MIN_WORKERS = _read_env_int("PHISHING_DNS_GATE_MIN_WORKERS", 128)
DEFAULT_MAX_WORKERS = _read_env_int("PHISHING_DNS_GATE_MAX_WORKERS", 384)


def normalize_url(url: str) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        return "https://" + text.lstrip("/")
    return text


def _resolve_dns_worker_count(target_count: int, max_workers: int | None = None) -> int:
    if max_workers is not None:
        return max(1, min(target_count, int(max_workers))) if target_count > 0 else 1

    if target_count <= 0:
        return 1

    cpu_count = os.cpu_count() or 4
    multiplier = 12 if cpu_count >= 32 else 8
    adaptive = max(DEFAULT_MIN_WORKERS, min(DEFAULT_MAX_WORKERS, cpu_count * multiplier))
    return max(1, min(target_count, adaptive))


def _build_resolver(timeout: float, nameservers: tuple[str, ...] | list[str] | None = None) -> dns.asyncresolver.Resolver:
    use_system = not nameservers
    resolver = dns.asyncresolver.Resolver(configure=use_system)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


async def _resolve_single_url_once(
    target_url: str,
    semaphore: asyncio.Semaphore,
    resolver: dns.asyncresolver.Resolver,
    timeout: float,
) -> dict:
    normalized_url = normalize_url(target_url)
    hostname = (urlparse(normalized_url).hostname or "").lower()

    if not normalized_url or not hostname:
        return {
            "target_url": target_url,
            "hostname": hostname,
            "resolved_ips": "",
            "dns_status": "invalid_host",
            "decision": "rejected",
        }

    try:
        async with semaphore:
            a_task = resolver.resolve(hostname, "A", lifetime=timeout)
            aaaa_task = resolver.resolve(hostname, "AAAA", lifetime=timeout)
            answers = await asyncio.gather(
                a_task,
                aaaa_task,
                return_exceptions=True,
            )

        resolved_ips: set[str] = set()
        saw_timeout = False
        saw_resolver_error = False

        for answer in answers:
            if isinstance(answer, Exception):
                if isinstance(answer, dns.resolver.NoAnswer):
                    continue
                if isinstance(answer, dns.resolver.NXDOMAIN):
                    return {
                        "target_url": target_url,
                        "hostname": hostname,
                        "resolved_ips": "",
                        "dns_status": "dns_error",
                        "decision": "rejected",
                    }
                if isinstance(answer, dns.exception.Timeout):
                    saw_timeout = True
                    continue
                if isinstance(answer, (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout)):
                    saw_resolver_error = True
                    continue
                saw_resolver_error = True
                continue

            for item in answer:
                text = getattr(item, "address", None) or item.to_text()
                if text:
                    resolved_ips.add(text)

        if resolved_ips:
            return {
                "target_url": target_url,
                "hostname": hostname,
                "resolved_ips": ";".join(sorted(resolved_ips)),
                "dns_status": "resolved",
                "decision": "accepted",
            }

        if saw_timeout:
            return {
                "target_url": target_url,
                "hostname": hostname,
                "resolved_ips": "",
                "dns_status": "timeout",
                "decision": "rejected",
            }

        return {
            "target_url": target_url,
            "hostname": hostname,
            "resolved_ips": "",
            "dns_status": "resolver_error" if saw_resolver_error else "no_records",
            "decision": "rejected",
        }
    except (UnicodeError, ValueError):
        dns_status = "dns_error"
    except dns.exception.Timeout:
        dns_status = "timeout"
    except dns.resolver.NXDOMAIN:
        dns_status = "dns_error"
    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        dns_status = "resolver_error"
    except Exception:
        dns_status = "resolver_error"

    return {
        "target_url": target_url,
        "hostname": hostname,
        "resolved_ips": "",
        "dns_status": dns_status,
            "decision": "rejected",
        }


async def _resolve_single_url(
    target_url: str,
    semaphore: asyncio.Semaphore,
    primary_resolver: dns.asyncresolver.Resolver,
    timeout: float,
    retries: int = DEFAULT_DNS_RETRIES,
    fallback_resolver: dns.asyncresolver.Resolver | None = None,
) -> dict:
    retry_budget = max(0, int(retries))
    final_row = None

    for attempt in range(retry_budget + 1):
        use_fallback = attempt > 0 and fallback_resolver is not None
        resolver = fallback_resolver if use_fallback else primary_resolver
        row = await _resolve_single_url_once(
            target_url=target_url,
            semaphore=semaphore,
            resolver=resolver,
            timeout=timeout,
        )
        row["attempts"] = attempt + 1
        row["retry_count"] = attempt
        row["retry_success"] = False
        row["resolver_profile"] = "fallback" if use_fallback else "default"
        final_row = row

        if row.get("decision") == "accepted":
            row["retry_success"] = attempt > 0
            return row

        dns_status = str(row.get("dns_status", ""))
        is_retryable = dns_status in {"timeout", "resolver_error"}
        if not is_retryable:
            return row

    return final_row or {
        "target_url": target_url,
        "hostname": "",
        "resolved_ips": "",
        "dns_status": "resolver_error",
        "decision": "rejected",
        "attempts": retry_budget + 1,
        "retry_count": retry_budget,
        "retry_success": False,
        "resolver_profile": "default",
    }


async def _gate_urls_for_hashing_async(
    target_urls: list[str],
    timeout: float,
    max_workers: int | None,
    retries: int = DEFAULT_DNS_RETRIES,
    fallback_nameservers: tuple[str, ...] | list[str] | None = DEFAULT_FALLBACK_NAMESERVERS,
    source_workbook_map: dict[str, str] | None = None,
    run_context: RunContext | None = None,
    checkpoint_store: CheckpointStore | None = None,
    audit_output_path: str = DEFAULT_AUDIT_PATH,
) -> tuple[list[str], list[dict]]:
    if not target_urls:
        return [], []

    retries = max(0, int(retries))
    worker_count = _resolve_dns_worker_count(len(target_urls), max_workers=max_workers)
    semaphore = asyncio.Semaphore(worker_count)
    resolver = _build_resolver(timeout)
    fallback_resolver = None
    if fallback_nameservers:
        try:
            fallback_resolver = _build_resolver(timeout, nameservers=fallback_nameservers)
        except Exception:
            fallback_resolver = None

    source_workbook_map = dict(source_workbook_map or {})
    progress = ProgressTracker(total=len(target_urls))
    progress_metrics = {
        "accepted": 0,
        "rejected": 0,
        "timeout": 0,
        "retry_success": 0,
    }
    active_workers: dict[str, str] = {}
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    for target_url in target_urls:
        await queue.put(target_url)
    for _ in range(worker_count):
        await queue.put(None)

    audit_rows: list[dict] = []
    audit_lock = asyncio.Lock()

    try:
        from tqdm import tqdm

        progress_bar = tqdm(
            total=len(target_urls),
            desc="DNS gate",
            unit="url",
            leave=True,
            dynamic_ncols=True,
        )
    except ImportError:
        progress_bar = None

    async def _progress_monitor() -> None:
        if progress_bar is None:
            return
        last_completed = 0
        while True:
            await asyncio.sleep(0.5)
            completed = progress.completed
            if completed > last_completed:
                progress_bar.update(completed - last_completed)
                last_completed = completed
            progress_bar.set_postfix(
                {
                    "act": len(active_workers),
                    "q": queue.qsize(),
                    "ok": progress_metrics["accepted"],
                    "rej": progress_metrics["rejected"],
                    "tout": progress_metrics["timeout"],
                },
                refresh=False,
            )
            if completed >= len(target_urls):
                break

    monitor_task = asyncio.create_task(_progress_monitor()) if progress_bar is not None else None

    async def _append_audit_row(row: dict) -> None:
        async with audit_lock:
            audit_rows.append(dict(row))
            if checkpoint_store is not None:
                checkpoint_store.maybe_export()

    async def _worker(worker_index: int) -> None:
        worker_id = f"dns-{worker_index}"
        while True:
            target_url = await queue.get()
            if target_url is None:
                queue.task_done()
                break
            normalized_url = normalize_url(target_url)
            source_workbook = source_workbook_map.get(normalized_url, "")
            record_key = make_record_key(normalized_url, source_workbook)
            stage_started_at = utc_now_iso()
            started_monotonic = time.perf_counter()
            active_workers[worker_id] = normalized_url
            try:
                if checkpoint_store is not None:
                    checkpoint_store.update_worker_heartbeat(
                        stage_name="dns",
                        worker_id=worker_id,
                        record_key=record_key,
                        state="running",
                        details={"url": normalized_url},
                    )
                row, retry_count, timeout_hit = await async_with_timeout_and_retry(
                    lambda: _resolve_single_url(
                        target_url=target_url,
                        semaphore=semaphore,
                        primary_resolver=resolver,
                        timeout=timeout,
                        retries=retries,
                        fallback_resolver=fallback_resolver,
                    ),
                    timeout=max(timeout * max(1, retries + 1) + 2.0, timeout + 2.0),
                    max_retries=0,
                )
                row["source_workbook"] = source_workbook
                await _append_audit_row(row)
                if row.get("decision") == "accepted":
                    progress_metrics["accepted"] += 1
                else:
                    progress_metrics["rejected"] += 1
                if row.get("dns_status") == "timeout":
                    progress_metrics["timeout"] += 1
                if row.get("retry_success"):
                    progress_metrics["retry_success"] += 1
                if checkpoint_store is not None and run_context is not None:
                    final_status = None
                    if row.get("decision") == "accepted":
                        final_status = "dns_accepted"
                    elif row.get("dns_status") in {"dns_error", "invalid_host", "no_records"}:
                        final_status = "dns_rejected"
                    checkpoint_store.upsert_url_result(
                        stage_result_patch(
                            run_id=run_context.run_id,
                            raw_url=target_url,
                            normalized_url=normalized_url,
                            source_workbook=source_workbook,
                            stage_name="dns",
                            stage_status=str(row.get("dns_status", "resolver_error")),
                            current_stage="dns",
                            retry_count=int(row.get("retry_count", retry_count) or retry_count),
                            timeout_hit=bool(timeout_hit or row.get("dns_status") == "timeout"),
                            worker_id=worker_id,
                            final_pipeline_status=final_status,
                            failure_reason=str(row.get("dns_status", "")) if row.get("decision") != "accepted" else None,
                        )
                    )
                    checkpoint_store.append_stage_event(
                        {
                            "run_id": run_context.run_id,
                            "record_key": record_key,
                            "source_workbook": source_workbook,
                            "normalized_url": normalized_url,
                            "stage_name": "dns",
                            "attempt_index": int(row.get("attempts", 1) or 1),
                            "worker_id": worker_id,
                            "started_at": stage_started_at,
                            "finished_at": utc_now_iso(),
                            "duration_ms": int(max(0.0, (time.perf_counter() - started_monotonic) * 1000.0)),
                            "status": str(row.get("dns_status", "resolver_error")),
                            "error_type": "" if row.get("decision") == "accepted" else str(row.get("dns_status", "")),
                            "error_message": "" if row.get("decision") == "accepted" else str(row.get("dns_status", "")),
                            "retry_count": int(row.get("retry_count", retry_count) or retry_count),
                            "timeout_flag": int(bool(timeout_hit or row.get("dns_status") == "timeout")),
                            "fallback_taken": "",
                        }
                    )
                progress.mark_completed(
                    final_status="dns_accepted" if row.get("decision") == "accepted" else "dns_rejected"
                )
            except Exception as exc:
                error = normalize_exception(exc)
                failed_row = {
                    "target_url": target_url,
                    "source_workbook": source_workbook,
                    "hostname": (urlparse(normalized_url).hostname or "").lower(),
                    "resolved_ips": "",
                    "dns_status": "resolver_error",
                    "decision": "rejected",
                    "attempts": retries + 1,
                    "retry_count": retries,
                    "retry_success": False,
                    "resolver_profile": "default",
                }
                await _append_audit_row(failed_row)
                progress_metrics["rejected"] += 1
                if checkpoint_store is not None and run_context is not None:
                    checkpoint_store.upsert_url_result(
                        stage_result_patch(
                            run_id=run_context.run_id,
                            raw_url=target_url,
                            normalized_url=normalized_url,
                            source_workbook=source_workbook,
                            stage_name="dns",
                            stage_status="failed",
                            current_stage="dns",
                            retry_count=retries,
                            timeout_hit=False,
                            worker_id=worker_id,
                            error_type=error["error_type"],
                            error_message=error["error_message"],
                            final_pipeline_status="dns_rejected",
                            failure_reason=error["error_message"],
                        )
                    )
                    checkpoint_store.append_stage_event(
                        {
                            "run_id": run_context.run_id,
                            "record_key": record_key,
                            "source_workbook": source_workbook,
                            "normalized_url": normalized_url,
                            "stage_name": "dns",
                            "attempt_index": retries + 1,
                            "worker_id": worker_id,
                            "started_at": stage_started_at,
                            "finished_at": utc_now_iso(),
                            "duration_ms": int(max(0.0, (time.perf_counter() - started_monotonic) * 1000.0)),
                            "status": "failed",
                            "error_type": error["error_type"],
                            "error_message": error["error_message"],
                            "retry_count": retries,
                            "timeout_flag": 0,
                            "fallback_taken": "",
                        }
                    )
                progress.mark_completed(final_status="dns_rejected")
                logger.warning(
                    "DNS gate worker failure | worker=%s | url=%s | %s: %s",
                    worker_id,
                    target_url,
                    error["error_type"],
                    error["error_message"],
                )
            finally:
                active_workers.pop(worker_id, None)
                if checkpoint_store is not None:
                    try:
                        checkpoint_store.clear_worker_heartbeat(stage_name="dns", worker_id=worker_id)
                    except Exception:
                        logger.exception("Failed to clear DNS worker heartbeat for %s", worker_id)
                queue.task_done()

    watchdog = StageWatchdog(
        stage_name="dns",
        progress_tracker=progress,
        checkpoint_store=checkpoint_store,
        warn_after_seconds=run_context.watchdog_warning_seconds if run_context is not None else 60,
        stall_after_seconds=run_context.stall_threshold_seconds if run_context is not None else 180,
        queue_size_getter=queue.qsize,
        active_summary_getter=lambda: {"workers": worker_count},
        logger_instance=logger,
    )
    workers = [asyncio.create_task(_worker(index)) for index in range(worker_count)]
    watchdog.start()
    try:
        join_timeout = max(
            run_context.stall_threshold_seconds if run_context is not None else 180,
            30,
        )
        await asyncio.wait_for(queue.join(), timeout=join_timeout)
        await asyncio.gather(*workers)
    except asyncio.TimeoutError as exc:
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise RuntimeError("DNS gate worker pool stalled before draining the queue") from exc
    finally:
        if monitor_task is not None:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
        if progress_bar is not None:
            completed = progress.completed
            if completed > progress_bar.n:
                progress_bar.update(completed - progress_bar.n)
            progress_bar.set_postfix(
                {
                    "act": len(active_workers),
                    "q": queue.qsize(),
                    "ok": progress_metrics["accepted"],
                    "rej": progress_metrics["rejected"],
                    "tout": progress_metrics["timeout"],
                },
                refresh=False,
            )
            progress_bar.close()
        await watchdog.stop()
        write_dns_gate_audit(audit_rows, output_path=audit_output_path)

    accepted_urls = [
        row["target_url"]
        for row in audit_rows
        if row["decision"] == "accepted"
    ]
    status_counts = Counter(str(row.get("dns_status", "")) for row in audit_rows)
    retry_success_count = sum(1 for row in audit_rows if row.get("retry_success"))
    logger.info(
        "DNS gate details | urls=%d | kept=%d | timeout=%.1fs | retries=%d | workers=%d | "
        "resolved=%d timeout=%d resolver_error=%d no_records=%d dns_error=%d retry_success=%d",
        len(target_urls),
        len(accepted_urls),
        timeout,
        retries,
        worker_count,
        status_counts.get("resolved", 0),
        status_counts.get("timeout", 0),
        status_counts.get("resolver_error", 0),
        status_counts.get("no_records", 0),
        status_counts.get("dns_error", 0),
        retry_success_count,
    )
    return accepted_urls, audit_rows


def write_dns_gate_audit(
    audit_rows: list[dict],
    output_path: str = DEFAULT_AUDIT_PATH,
) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=_AUDIT_FIELDNAMES,
        )
        writer.writeheader()
        writer.writerows(audit_rows)


def gate_urls_for_hashing(
    target_urls: list[str],
    timeout: float = DEFAULT_DNS_TIMEOUT,
    audit_output_path: str = DEFAULT_AUDIT_PATH,
    max_workers: int | None = None,
    retries: int = DEFAULT_DNS_RETRIES,
    fallback_nameservers: tuple[str, ...] | list[str] | None = DEFAULT_FALLBACK_NAMESERVERS,
) -> tuple[list[str], list[dict]]:
    accepted_urls, audit_rows = asyncio.run(
        _gate_urls_for_hashing_async(
            target_urls,
            timeout=timeout,
            max_workers=max_workers,
            retries=retries,
            fallback_nameservers=fallback_nameservers,
        )
    )
    write_dns_gate_audit(audit_rows, output_path=audit_output_path)
    logger.info(
        "DNS gate kept %d/%d URLs at %.1fs timeout (retries=%d)",
        len(accepted_urls),
        len(target_urls),
        timeout,
        retries,
    )
    return accepted_urls, audit_rows
