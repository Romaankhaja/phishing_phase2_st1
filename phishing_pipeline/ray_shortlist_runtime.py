from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import asdict
import logging
import time
from typing import Any

from .config import resolve_ray_runtime_config, resolve_stage1_http_config, RAY_DEBUG_MODE
from .progress_display import (
    build_compact_postfix,
    build_timing_postfix,
    managed_progress_bar,
    progress_bars_enabled,
    resolve_progress_mode,
    tqdm_logging_redirect,
)
from .reliability import (
    ProgressTracker,
    RunContext,
    get_run_artifact_path,
    make_record_key,
    sync_run_artifact,
    utc_now_iso,
)
from .ray_runtime import (
    HashRenderArtifact,
    _build_shortlist_patch,
    _build_shortlist_stage_event,
    _flush_finalize_buffer,
    _get_ray_primitives,
    _is_debug_mode,
    _log_metrics_periodically,
    _ray_context_dict,
    _ray_get,
    _ray_wait,
    debug_ray_resource_snapshot,
    ensure_ray_initialized,
)

logger = logging.getLogger(__name__)


def _build_shortlist_progress_record_key(normalized_url: str, source_workbook: str, ordinal: int) -> str:
    return f"{make_record_key(normalized_url, source_workbook)}::{max(0, int(ordinal))}"


def _mark_shortlist_progress_completion(
    progress_tracker: ProgressTracker,
    completed_record_keys: set[str],
    record_key: str,
    *,
    final_status: str,
) -> bool:
    key = str(record_key or "").strip()
    if not key or key in completed_record_keys:
        return False
    completed_record_keys.add(key)
    progress_tracker.mark_completed(final_status=final_status)
    return True


def _build_shortlist_progress_postfix(
    *,
    progress_tracker: ProgressTracker,
    started_monotonic: float,
    stage0_processed: int,
    stage0_hits: int,
    stage0_misses: int,
    stage1_inflight: int,
    stage1_backlog: int,
    render_queue_depth: int,
    aux_queue_depth: int,
    finalize_queue_depth: int,
    active_hash_concurrency: int,
    match_count: int,
    phase: str,
) -> dict[str, str]:
    fields = build_timing_postfix(
        completed=progress_tracker.completed,
        total=progress_tracker.total,
        started_monotonic=started_monotonic,
        rate_key="urls/s",
    )
    fields.update(
        {
            "stage0": f"{int(stage0_processed)},{int(stage0_hits)},{int(stage0_misses)}",
            "stage1": f"{int(stage1_inflight)},{int(stage1_backlog)}",
            "hash": f"{int(render_queue_depth)},{int(aux_queue_depth)},{int(finalize_queue_depth)}",
            "active": int(active_hash_concurrency),
            "match": int(match_count),
            "phase": str(phase or "running"),
        }
    )
    return build_compact_postfix(fields)


async def run_hashing_shortlist_with_ray_impl(
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
    del checkpoint_store

    from . import comparison
    from .rdap_utils import get_rdap_metrics_snapshot, reset_rdap_state

    ensure_ray_initialized()
    primitives = _get_ray_primitives()
    runtime_config = resolve_ray_runtime_config()
    debug_mode = _is_debug_mode()
    progress_mode = resolve_progress_mode(progress_mode, execution_backend="ray")
    progress_enabled = progress_bars_enabled(progress_mode)
    telemetry_mode = str(getattr(run_context, "telemetry_mode", "sampled") or "sampled").strip().lower()
    logger.info(
        "Ray shortlist startup | urls=%d | progress_mode=%s | ram={total_gb=%s,available_gb=%s} | local_mode=%s | low_memory=%s | server_mode=%s | prewarm=%s | actors={stage1_fetch=%d,stage1_enrich=%d,hash_browser=%d,classify=%d} | stage0={batch_size=%d,inflight=%d} | backpressure={stage1_cap=%d,hash_cap=%d} | hash={tabs_per_actor=%d,finalize_batch=%d}",
        len(url_list),
        progress_mode,
        runtime_config.get("detected_total_ram_gb", "NA"),
        runtime_config.get("detected_available_ram_gb", "NA"),
        bool(runtime_config.get("local_mode")),
        bool(runtime_config.get("low_memory_mode")),
        bool(runtime_config.get("server_mode")),
        bool(runtime_config.get("prewarm_actors")),
        int(runtime_config["stage1_fetch_actors"]),
        int(runtime_config["stage1_enrich_actors"]),
        int(runtime_config["hash_browser_actors"]),
        int(runtime_config["classify_actors"]),
        int(runtime_config["stage0_batch_size"]),
        int(runtime_config["stage0_inflight"]),
        int(runtime_config.get("stage1_pending_cap", 0) or 0),
        int(runtime_config.get("hash_pending_cap", 0) or 0),
        int(runtime_config["hash_tabs_per_actor"]),
        int(runtime_config["hash_finalize_batch"]),
    )
    scoring_config = comparison._resolve_scoring_config(
        weights=weights,
        domain_similarity_threshold=domain_similarity_threshold,
        high_confidence_threshold=high_confidence_threshold,
        medium_confidence_threshold=medium_confidence_threshold,
        typo_top_k=typo_top_k,
        typo_min_score=typo_min_score,
        lexical_pass_min_score=lexical_pass_min_score,
        keep_stage1_suspected=keep_stage1_suspected,
        keep_fetch_failed_strict_lexical=keep_fetch_failed_strict_lexical,
        stage1_escalate_total_threshold=stage1_escalate_total_threshold,
        stage1_brand_min=stage1_brand_min,
        stage1_credential_min=stage1_credential_min,
        stage1_low_band_min=stage1_low_band_min,
        stage1_hard_trigger_brand_min=stage1_hard_trigger_brand_min,
    )
    stage1_http_config = resolve_stage1_http_config(scoring_config["stage1_http_config"])
    actor_stage1_http_config = resolve_stage1_http_config(stage1_http_config)
    stage1_fetch_actor_count = max(1, int(runtime_config["stage1_fetch_actors"]))
    total_connection_budget = min(
        int(actor_stage1_http_config.get("stage1_http_connection_limit", 24) or 24),
        int(runtime_config.get("stage1_http_connection_cap", 24) or 24),
    )
    total_keepalive_budget = min(
        int(actor_stage1_http_config.get("stage1_http_keepalive_limit", 12) or 12),
        int(runtime_config.get("stage1_http_keepalive_cap", 12) or 12),
    )
    actor_stage1_http_config["stage1_http_connection_limit"] = max(
        4,
        (total_connection_budget + stage1_fetch_actor_count - 1) // stage1_fetch_actor_count,
    )
    actor_stage1_http_config["stage1_http_keepalive_limit"] = max(
        2,
        (total_keepalive_budget + stage1_fetch_actor_count - 1) // stage1_fetch_actor_count,
    )
    source_workbook_map = comparison._resolve_source_workbook_map(url_sources)
    trace_record_key = str(getattr(run_context, "trace_record_key", "") or "")
    trace_url = comparison.normalize_url(str(getattr(run_context, "trace_url", "") or "")) if run_context is not None else ""
    capture_full_render_trace = debug_mode or telemetry_mode in {"full", "debug"}
    checkpoint_actor = (
        primitives["CheckpointWriterActor"].remote(_ray_context_dict(run_context))
        if run_context is not None
        else None
    )
    metrics_actor = primitives["MetricsActor"].remote()
    lookup_cache_actor = primitives["LookupCacheActor"].remote()
    stage1_fetch_actors: list[Any] = []
    stage1_enrich_actors: list[Any] = []
    hash_browser_actors: list[Any] = []
    prewarm_actors = bool(runtime_config.get("prewarm_actors", False))
    prewarm_mode = str(runtime_config.get("prewarm_mode", "full") or "full").strip().lower()
    logger.info("Ray shortlist control actors created | checkpoint=%s", bool(checkpoint_actor))

    input_urls = list(url_list)
    t0 = time.perf_counter()
    log_path = comparison._configure_hashing_log(
        get_run_artifact_path(run_context, "hashing_log", comparison.HASHING_LOG_PATH)
    )
    logger.info("Hashing log: %s", log_path)
    reset_rdap_state()

    checkpoint_completed_record_keys = set()
    if checkpoint_actor is not None and resume and not force_reprocess:
        checkpoint_completed_record_keys = await _ray_get(checkpoint_actor.get_completed_record_keys.remote())

    shortlist_progress = ProgressTracker(total=len(input_urls))
    progress_completed_record_keys: set[str] = set()
    pending_records_by_url: dict[str, list[dict[str, str]]] = {}
    metric_urls: list[str] = []
    seen_metric_urls: set[str] = set()
    ensure_records: list[dict[str, Any]] = []
    stage0_skipped = 0
    for ordinal, raw_url in enumerate(input_urls):
        normalized_url = comparison.normalize_url(raw_url)
        source_workbook = source_workbook_map.get(normalized_url, "")
        progress_record_key = _build_shortlist_progress_record_key(normalized_url, source_workbook, ordinal)
        ensure_records.append(
            {"raw_url": raw_url, "normalized_url": normalized_url, "source_workbook": source_workbook}
        )
        if (
            run_context is not None
            and make_record_key(normalized_url, source_workbook) in checkpoint_completed_record_keys
        ):
            stage0_skipped += 1
            _mark_shortlist_progress_completion(
                shortlist_progress,
                progress_completed_record_keys,
                progress_record_key,
                final_status="resume_skip",
            )
            continue
        pending_records_by_url.setdefault(normalized_url, []).append(
            {
                "raw_url": raw_url,
                "source_workbook": source_workbook,
                "progress_key": progress_record_key,
            }
        )
        if normalized_url and normalized_url not in seen_metric_urls:
            seen_metric_urls.add(normalized_url)
            metric_urls.append(normalized_url)
    if checkpoint_actor is not None:
        checkpoint_actor.ensure_url_results.remote(ensure_records)

    prefetch_metrics_map: dict[str, dict[str, Any]] = {}
    dns_prefetch_map: dict[str, dict[str, Any]] = {}
    stage1_analysis_map: dict[str, dict[str, Any]] = {}
    lexical_reject_urls: set[str] = set()
    decision_rows: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    review_results: list[dict[str, Any]] = []
    prefetch_admitted_failures: list[dict[str, Any]] = []
    render_trace_rows: list[dict[str, Any]] = []
    render_trace_written = False
    metrics = {
        "processed": 0,
        "render_completed": 0,
        "aux_completed": 0,
        "finalized": 0,
        "hashed_success": 0,
        "fetch_failed": 0,
        "fetch_timed_out": 0,
        "final_matches_above_threshold": 0,
        "gpu_batches_flushed": 0,
        "gpu_items_scored": 0,
        "avg_gpu_batch_size": 0.0,
        "gpu_queue_depth": 0,
        "render_queue_depth": 0,
        "aux_queue_depth": 0,
        "stage_elapsed_s": 0.0,
        "active_fetch_limit": int(runtime_config["hash_tabs_per_actor"]) * max(1, int(runtime_config["hash_browser_actors"])),
        "worker_nodes_alive": len(hash_browser_actors),
        "live_page_workers": 0,
        "phase": "running",
        "hash_execution_mode": "ray",
        "render_rescue_attempted": 0,
        "render_rescue_applied": 0,
    }
    stage1_progress = {
        "escalated": 0,
        "failed": 0,
        "head_only": 0,
        "fetched": 0,
        "fallback_dns": 0,
        "timeout": 0,
        "dns_hit_gate_accepted": 0,
        "dns_hit_gate_passthrough": 0,
        "dns_gate_accepted": 0,
        "dns_gate_filtered": 0,
    }
    stage0_hits = 0
    stage0_misses = 0
    lex_eval_config = (int(scoring_config["typo_top_k"]), float(scoring_config["lexical_pass_min_score"]))
    stage0_batch_size = int(runtime_config["stage0_batch_size"])
    stage0_inflight = int(runtime_config["stage0_inflight"])
    stage1_pending_cap = int(runtime_config.get("stage1_pending_cap", max(1, int(runtime_config["stage1_fetch_actors"]))))
    hash_pending_cap = int(runtime_config.get("hash_pending_cap", max(1, int(runtime_config["hash_browser_actors"]))))
    stage1_fetch_actor_max_concurrency = int(runtime_config.get("stage1_fetch_actor_max_concurrency", 4) or 4)
    stage1_enrich_actor_max_concurrency = int(runtime_config.get("stage1_enrich_actor_max_concurrency", 4) or 4)
    dynamic_control_enabled = bool(runtime_config.get("enable_dynamic_control", True))
    target_cpu_utilization = float(runtime_config.get("target_cpu_utilization", 0.82) or 0.82)
    cpu_headroom_cores = max(1, int(runtime_config.get("cpu_headroom_cores", 6) or 6))
    severe_available_cpu_floor = max(1.0, float(max(1, cpu_headroom_cores - 2)))
    healthy_available_cpu_floor = float(cpu_headroom_cores + 2)
    control_interval_seconds = 2.0
    stage0_inflight_floor = min(stage0_inflight, 4 if runtime_config.get("server_mode") and not runtime_config.get("low_memory_mode") else 1)
    stage1_fetch_limit_cap = max(1, int(runtime_config["stage1_fetch_actors"]) * stage1_fetch_actor_max_concurrency)
    stage1_fetch_limit_floor = min(
        stage1_fetch_limit_cap,
        24 if runtime_config.get("server_mode") and not runtime_config.get("low_memory_mode") else max(1, int(runtime_config["stage1_fetch_actors"])),
    )
    hash_active_pages_cap = max(1, int(runtime_config["hash_browser_actors"]) * int(runtime_config["hash_tabs_per_actor"]))
    hash_active_pages_floor = min(
        hash_active_pages_cap,
        4 if runtime_config.get("server_mode") and not runtime_config.get("low_memory_mode") else max(1, int(runtime_config["hash_tabs_per_actor"])),
    )
    pending: dict[Any, tuple[str, Any]] = {}
    stage1_backlog: deque[dict[str, Any]] = deque()
    hash_backlog: deque[tuple[str, str, str, str]] = deque()
    remaining_stage0_urls = list(metric_urls)
    browser_actor_index = 0
    fetch_actor_index = 0
    enrich_actor_index = 0
    finalize_buffer: list[dict[str, Any]] = []
    stage0_batches_completed = 0
    stage0_latency_sum_ms = 0.0
    stage0_warmup_logged = False
    # --- Debug heartbeat state ---
    _debug_pending_submit_times: dict[Any, tuple[str, float]] = {}  # ref -> (kind, submit_monotonic)
    _debug_last_heartbeat = time.perf_counter()
    _debug_heartbeat_interval = 10.0  # seconds
    _debug_consecutive_empty_waits = 0
    _debug_stall_warning_threshold = 6  # ~60s of consecutive empty waits
    _debug_last_stall_event = 0.0
    progress_stop = asyncio.Event()
    controller_state: dict[str, Any] = {
        "enabled": dynamic_control_enabled,
        "stage0_live_inflight": stage0_inflight,
        "stage0_inflight_floor": stage0_inflight_floor,
        "stage0_inflight_cap": stage0_inflight,
        "stage1_live_fetch_limit": min(stage1_fetch_limit_cap, max(stage1_fetch_limit_floor, stage1_pending_cap)),
        "stage1_fetch_limit_floor": stage1_fetch_limit_floor,
        "stage1_fetch_limit_cap": stage1_fetch_limit_cap,
        "hash_live_active_pages": hash_active_pages_cap,
        "hash_active_pages_floor": hash_active_pages_floor,
        "hash_active_pages_cap": hash_active_pages_cap,
        "action": "init",
        "reason": "startup",
        "available_cpu": 0.0,
        "cpu_utilization": 0.0,
        "event_loop_lag_ms": 0.0,
        "checkpoint_pending_rows": 0,
        "healthy_streak": 0,
        "timeout_ratio": 0.0,
        "stage1_pressure_ratio": 0.0,
        "hash_pressure_ratio": 0.0,
        "progress_completed": 0,
        "target_cpu_utilization": target_cpu_utilization,
        "cpu_headroom_cores": cpu_headroom_cores,
    }
    metrics["active_fetch_limit"] = int(controller_state["hash_live_active_pages"])

    def _should_capture_render_trace(artifact: dict[str, Any], render_payload: dict[str, Any] | None = None) -> bool:
        if capture_full_render_trace:
            return True
        resolved_artifact = dict(artifact or {})
        resolved_payload = dict(render_payload or {})
        normalized_url = str(
            resolved_artifact.get("normalized_url", "")
            or resolved_payload.get("normalized_url", resolved_payload.get("url", ""))
            or ""
        ).strip().lower()
        source_workbook = str(
            resolved_artifact.get("source_workbook", "")
            or resolved_payload.get("source_workbook", "")
            or source_workbook_map.get(normalized_url, "")
        )
        record_key = str(resolved_artifact.get("record_key", "") or make_record_key(normalized_url, source_workbook))
        if trace_record_key and record_key == trace_record_key:
            return True
        return bool(trace_url and normalized_url == trace_url)

    def _stage_name_for_task(kind: str) -> str:
        if kind == "stage0_batch":
            return "stage0"
        if kind.startswith("stage1_"):
            return "stage1"
        return "hash"

    def _ensure_debug_submit_times() -> None:
        now = time.perf_counter()
        for ref, (kind, context) in list(pending.items()):
            if id(ref) in _debug_pending_submit_times:
                continue
            submitted_monotonic = now
            if isinstance(context, dict):
                submitted_monotonic = float(context.get("submitted_monotonic", now) or now)
            _debug_pending_submit_times[id(ref)] = (kind, submitted_monotonic)

    def _track_pending(ref: Any, kind: str, context: dict[str, Any]) -> None:
        submitted_monotonic = float(context.get("submitted_monotonic", time.perf_counter()) or time.perf_counter())
        context["submitted_monotonic"] = submitted_monotonic
        pending[ref] = (kind, context)
        _debug_pending_submit_times[id(ref)] = (kind, submitted_monotonic)

    def _build_heartbeat_payload(kind: str, context: Any, *, now: float) -> dict[str, Any] | None:
        context_dict = dict(context or {}) if isinstance(context, dict) else {}
        record = dict(context_dict.get("record") or {}) if "record" in context_dict else context_dict
        worker_id = str(context_dict.get("worker_id", "") or record.get("worker_id", "") or "")
        if not worker_id:
            return None
        normalized_url = str(record.get("normalized_url", "") or record.get("url", "") or "").strip().lower()
        source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
        details = {
            "normalized_url": normalized_url,
            "stage0_remaining": len(remaining_stage0_urls),
            "stage1_backlog": len(stage1_backlog),
            "hash_backlog": len(hash_backlog),
            "finalize_queue": len(finalize_buffer),
        }
        if kind == "stage0_batch":
            details["batch_size"] = len(list(context_dict.get("normalized_urls") or []))
        record_key = str(context_dict.get("record_key", "") or record.get("record_key", "") or "")
        if not record_key and normalized_url:
            record_key = make_record_key(normalized_url, source_workbook)
        return {
            "stage_name": _stage_name_for_task(kind),
            "worker_id": worker_id,
            "record_key": record_key,
            "task_kind": kind,
            "item_age_s": max(0.0, now - float(context_dict.get("submitted_monotonic", now) or now)),
            "details": details,
        }

    async def _record_checkpoint(patch: dict[str, Any] | None, event: dict[str, Any] | None) -> None:
        if checkpoint_actor is None:
            return
        if patch is not None:
            checkpoint_actor.upsert_url_result.remote(patch)
        if event is not None:
            checkpoint_actor.append_stage_event.remote(event)

    def _ensure_stage1_fetch_actors() -> None:
        if stage1_fetch_actors:
            return
        stage1_fetch_actors.extend(
            [
                primitives["Stage1FetchActor"].options(
                    num_cpus=0.25,
                    max_concurrency=stage1_fetch_actor_max_concurrency,
                ).remote(actor_stage1_http_config)
                for _ in range(int(runtime_config["stage1_fetch_actors"]))
            ]
        )
        logger.info("Ray shortlist fetch actors created | count=%d", len(stage1_fetch_actors))

    def _ensure_stage1_enrich_actors() -> None:
        if stage1_enrich_actors:
            return
        stage1_enrich_actors.extend(
            [
                primitives["Stage1EnrichActor"].options(
                    num_cpus=0.25,
                    max_concurrency=stage1_enrich_actor_max_concurrency,
                ).remote(actor_stage1_http_config, lookup_cache_actor)
                for _ in range(int(runtime_config["stage1_enrich_actors"]))
            ]
        )
        logger.info("Ray shortlist enrich actors created | count=%d", len(stage1_enrich_actors))

    def _ensure_hash_browser_actors() -> None:
        if hash_browser_actors:
            return
        hash_browser_actors.extend(
            [
                primitives["HashBrowserActor"].options(
                    num_cpus=1 if runtime_config.get("server_mode") else 0.5,
                    max_concurrency=int(runtime_config["hash_tabs_per_actor"]),
                ).remote(
                    int(runtime_config["hash_tabs_per_actor"]),
                    int(stage1_http_config.get("stage1_per_host_limit", 4) or 4),
                )
                for _ in range(int(runtime_config["hash_browser_actors"]))
            ]
        )
        metrics["active_fetch_limit"] = int(runtime_config["hash_tabs_per_actor"]) * max(1, len(hash_browser_actors))
        metrics["worker_nodes_alive"] = len(hash_browser_actors)
        logger.info("Ray shortlist browser actors created | count=%d", len(hash_browser_actors))

    async def _prewarm_actor_pools() -> None:
        if not prewarm_actors:
            return
        _ensure_stage1_fetch_actors()
        warm_refs = [actor.warm.remote() for actor in stage1_fetch_actors]
        if prewarm_mode == "full":
            _ensure_stage1_enrich_actors()
            _ensure_hash_browser_actors()
            warm_refs.extend(actor.warm.remote() for actor in stage1_enrich_actors)
            warm_refs.extend(actor.warm.remote() for actor in hash_browser_actors)
        if not warm_refs:
            return
        logger.info(
            "Ray shortlist prewarming actors | mode=%s | fetch=%d | enrich=%d | browser=%d",
            prewarm_mode,
            len(stage1_fetch_actors),
            len(stage1_enrich_actors),
            len(hash_browser_actors),
        )
        await _ray_get(warm_refs)
        logger.info("Ray shortlist actor prewarm complete")

    await _prewarm_actor_pools()

    def _should_attempt_hash_render_rescue(artifact: dict[str, Any], render_payload: dict[str, Any]) -> bool:
        stage1_analysis = dict(artifact.get("stage1_analysis", {}) or {})
        prefetch_metrics = dict(artifact.get("prefetch_metrics", {}) or {})
        lexical_hit = bool(stage1_analysis.get("lexical_hit", False) or prefetch_metrics.get("strict_lexical_hit", False))
        fetch_status = str(render_payload.get("fetch_status", "") or "").strip().lower()
        if not lexical_hit or fetch_status not in {"fetched", "fetched_visual_missing"}:
            return False
        return comparison._looks_like_noninformative_hash_render(
            title_text=str(render_payload.get("html_title_text", "") or ""),
            visible_text_excerpt=str(render_payload.get("visible_text_excerpt", "") or ""),
            html_content=str(render_payload.get("html_content", "") or ""),
        )

    async def _attempt_hash_render_rescue(
        artifact: dict[str, Any],
        render_payload: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any] | None, bool, str]:
        nonlocal fetch_actor_index

        _ensure_stage1_fetch_actors()
        record = {
            "raw_url": str(artifact.get("raw_url", "") or artifact.get("normalized_url", "")),
            "normalized_url": str(artifact.get("normalized_url", "") or artifact.get("raw_url", "")),
            "source_workbook": str(artifact.get("source_workbook", "") or ""),
        }
        actor = stage1_fetch_actors[fetch_actor_index % len(stage1_fetch_actors)]
        fetch_actor_index += 1
        rescue_fetch = await _ray_get(actor.fetch.remote(record))
        rescue_payload = dict((rescue_fetch or {}).get("payload") or {})
        parsed = await _ray_get(primitives["stage1_parse_task"].remote(record, rescue_payload, stage1_http_config))
        rescue_result = dict((parsed or {}).get("result") or {})
        merged_payload, applied = comparison._merge_stage1_rescue_into_hash_render_payload(render_payload, rescue_result)
        rescue_reason = ""
        if applied:
            rescue_reason = "stage1_http_rescue"
            merged_stage1_analysis = {**comparison._stage1_signal_defaults(), **dict(artifact.get("stage1_analysis", {}) or {}), **rescue_result}
            artifact["stage1_analysis"] = merged_stage1_analysis
        return merged_payload, rescue_result, applied, rescue_reason

    def _pending_count(*kinds: str) -> int:
        wanted = set(kinds)
        return sum(1 for kind, _ in pending.values() if kind in wanted)

    stop_metrics = asyncio.Event()
    metrics_task = asyncio.create_task(
        _log_metrics_periodically(
            metrics_actor,
            stop_metrics,
            "shortlist",
            float(runtime_config["metrics_interval_seconds"]),
            checkpoint_actor=checkpoint_actor,
            stage_name="shortlist",
            details_getter=lambda: {
                "controller": {
                    "enabled": bool(controller_state.get("enabled", False)),
                    "stage0_live_inflight": int(controller_state.get("stage0_live_inflight", 0) or 0),
                    "stage0_inflight_cap": int(controller_state.get("stage0_inflight_cap", 0) or 0),
                    "stage1_live_fetch_limit": int(controller_state.get("stage1_live_fetch_limit", 0) or 0),
                    "stage1_fetch_limit_cap": int(controller_state.get("stage1_fetch_limit_cap", 0) or 0),
                    "hash_live_active_pages": int(controller_state.get("hash_live_active_pages", 0) or 0),
                    "hash_active_pages_cap": int(controller_state.get("hash_active_pages_cap", 0) or 0),
                    "available_cpu": float(controller_state.get("available_cpu", 0.0) or 0.0),
                    "cpu_utilization": float(controller_state.get("cpu_utilization", 0.0) or 0.0),
                    "event_loop_lag_ms": float(controller_state.get("event_loop_lag_ms", 0.0) or 0.0),
                    "checkpoint_pending_rows": int(controller_state.get("checkpoint_pending_rows", 0) or 0),
                    "action": str(controller_state.get("action", "") or ""),
                    "reason": str(controller_state.get("reason", "") or ""),
                    "healthy_streak": int(controller_state.get("healthy_streak", 0) or 0),
                    "timeout_ratio": float(controller_state.get("timeout_ratio", 0.0) or 0.0),
                    "stage1_pressure_ratio": float(controller_state.get("stage1_pressure_ratio", 0.0) or 0.0),
                    "hash_pressure_ratio": float(controller_state.get("hash_pressure_ratio", 0.0) or 0.0),
                    "completed": int(shortlist_progress.completed),
                    "target_cpu_utilization": float(controller_state.get("target_cpu_utilization", 0.0) or 0.0),
                    "cpu_headroom_cores": int(controller_state.get("cpu_headroom_cores", 0) or 0),
                },
                "stage0": {
                    "hits": stage0_hits,
                    "misses": stage0_misses,
                    "skipped": stage0_skipped,
                    "remaining": len(remaining_stage0_urls),
                },
                "stage1": {
                    "progress": dict(stage1_progress),
                    "pending": _pending_count("stage1_fetch", "stage1_parse", "stage1_enrich"),
                    "backlog": len(stage1_backlog),
                    "fetch_actors": len(stage1_fetch_actors),
                    "enrich_actors": len(stage1_enrich_actors),
                },
                "hash": {
                    "pending": _pending_count("hash_render", "hash_enrich", "hash_finalize"),
                    "backlog": len(hash_backlog),
                    "render_queue_depth": metrics.get("render_queue_depth", 0),
                    "aux_queue_depth": metrics.get("aux_queue_depth", 0),
                    "finalize_queue_depth": len(finalize_buffer),
                    "browser_actors": len(hash_browser_actors),
                    "render_trace_rows": len(render_trace_rows),
                },
                "matches": int(metrics.get("final_matches_above_threshold", 0) or 0),
            },
            resource_snapshot_getter=debug_ray_resource_snapshot,
            emit_logs=not progress_enabled,
        )
    )

    async def _schedule_hash_admission(raw_url: str, normalized_url: str, source_workbook: str, progress_key: str) -> None:
        nonlocal browser_actor_index
        _ensure_hash_browser_actors()
        record_key = make_record_key(normalized_url, source_workbook)
        actor_slot = browser_actor_index % len(hash_browser_actors)
        artifact = asdict(
            HashRenderArtifact(
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                prefetch_metrics=dict(prefetch_metrics_map.get(normalized_url, {}) or {}),
                stage1_analysis=dict(stage1_analysis_map.get(normalized_url, {}) or {}),
            )
        )
        artifact["progress_key"] = progress_key
        artifact["record_key"] = record_key
        artifact["worker_id"] = f"hash-browser-{actor_slot}-{record_key[:8] or 'item'}"
        artifact["submitted_monotonic"] = time.perf_counter()
        actor = hash_browser_actors[actor_slot]
        browser_actor_index += 1
        _track_pending(actor.render.remote(artifact), "hash_render", artifact)
        await _record_checkpoint(
            _build_shortlist_patch(
                run_context=run_context,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="hash",
                stage_status="admitted",
                current_stage="hash",
                worker_id="ray-hash-admit",
            ),
            _build_shortlist_stage_event(
                run_context=run_context,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="hash",
                worker_id="ray-hash-admit",
                started_at=utc_now_iso(),
                started_monotonic=time.perf_counter(),
                status="admitted",
            ),
        )

    async def _admit_to_hash(raw_url: str, normalized_url: str, source_workbook: str, progress_key: str) -> None:
        hash_backlog.append((raw_url, normalized_url, source_workbook, progress_key))

    async def _schedule_stage1_fetch(record: dict[str, Any]) -> None:
        nonlocal fetch_actor_index
        _ensure_stage1_fetch_actors()
        record = dict(record)
        normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(record.get("raw_url", "")))
        source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
        record_key = make_record_key(normalized_url, source_workbook)
        actor_slot = fetch_actor_index % len(stage1_fetch_actors)
        actor = stage1_fetch_actors[actor_slot]
        fetch_actor_index += 1
        record["normalized_url"] = normalized_url
        record["source_workbook"] = source_workbook
        record["record_key"] = record_key
        record["worker_id"] = f"stage1-fetch-{actor_slot}-{record_key[:8] or 'item'}"
        record["submitted_monotonic"] = time.perf_counter()
        _track_pending(actor.fetch.remote(record), "stage1_fetch", record)

    async def _submit_stage1_fetch(record: dict[str, Any]) -> None:
        stage1_backlog.append(dict(record))

    async def _drain_backlogs() -> None:
        while (
            hash_backlog
            and _pending_count("hash_render", "hash_enrich", "hash_finalize") < hash_pending_cap
            and _pending_count("hash_render") < int(controller_state.get("hash_live_active_pages", hash_active_pages_cap) or hash_active_pages_cap)
        ):
            raw_url, normalized_url, source_workbook, progress_key = hash_backlog.popleft()
            await _schedule_hash_admission(raw_url, normalized_url, source_workbook, progress_key)
        while (
            stage1_backlog
            and _pending_count("stage1_fetch", "stage1_parse", "stage1_enrich") < stage1_pending_cap
            and _pending_count("stage1_fetch") < int(controller_state.get("stage1_live_fetch_limit", stage1_fetch_limit_cap) or stage1_fetch_limit_cap)
        ):
            await _schedule_stage1_fetch(stage1_backlog.popleft())

    async def _record_hash_fetch_outcome(payload_outcome: dict[str, Any], artifact: dict[str, Any] | None = None) -> None:
        decision_row = payload_outcome.get("decision_row")
        if decision_row is not None:
            decision_rows.append(decision_row)
        admitted_prefetch_match = payload_outcome.get("admitted_prefetch_match")
        if admitted_prefetch_match is not None:
            metrics["final_matches_above_threshold"] += 1
            prefetch_admitted_failures.append(admitted_prefetch_match)
        metric_key = str(payload_outcome.get("metric_key", "fetch_failed") or "fetch_failed")
        metrics[metric_key] += 1
        metrics["processed"] += 1
        metrics["finalized"] += 1
        if artifact is not None:
            _mark_shortlist_progress_completion(
                shortlist_progress,
                progress_completed_record_keys,
                str(artifact.get("progress_key", "") or ""),
                final_status=metric_key,
            )

    async def _finalize_stage1(record: dict[str, Any], analysis: dict[str, Any]) -> None:
        raw_url = str(record.get("raw_url", "") or "")
        normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(raw_url))
        source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
        progress_key = str(record.get("progress_key", "") or "")
        prefetch_metrics = prefetch_metrics_map.get(normalized_url, {})
        fallback_taken = ""
        if (
            str(analysis.get("fetch_status", "")).strip().lower() == "failed"
            and run_context is not None
            and run_context.stage1_failure_policy == "route_to_dns"
            and comparison._should_rescue_stage1_failure_to_hashing(
                prefetch_metrics,
                analysis,
                scoring_config=scoring_config,
            )
        ):
            fallback_taken = "targeted_stage1_failure_rescue"
            analysis["fallback_taken"] = fallback_taken
            analysis["escalate_to_hashing"] = True
            analysis["escalate_reason"] = fallback_taken
        final_analysis = {**comparison._stage1_signal_defaults(), **analysis}
        fetch_status = str(final_analysis.get("fetch_status", "")).strip().lower()
        if not final_analysis.get("stage1_reasons") and fetch_status == "failed":
            final_analysis["stage1_reasons"] = "stage1_fetch_failed"
            final_analysis["escalate_reason"] = "stage1_fetch_failed"
            final_analysis["stage1_error_type"] = str(final_analysis.get("stage1_error_type") or final_analysis.get("fetch_error_type") or "stage1_fetch_failed")
            final_analysis["stage1_error_message"] = str(final_analysis.get("stage1_error_message") or final_analysis.get("fetch_error_detail") or "fetch attempts exhausted")
        stage1_analysis_map[normalized_url] = final_analysis
        if bool(final_analysis.get("escalate_to_hashing")):
            stage1_progress["escalated"] += 1
            await _admit_to_hash(raw_url, normalized_url, source_workbook, progress_key)
        else:
            _mark_shortlist_progress_completion(
                shortlist_progress,
                progress_completed_record_keys,
                progress_key,
                final_status=fetch_status or "filtered_lexical_miss",
            )
        if fetch_status == "failed":
            stage1_progress["failed"] += 1
        elif fetch_status == "head_only":
            stage1_progress["head_only"] += 1
        elif fetch_status in {"fetched", "fetched_visual_missing"}:
            stage1_progress["fetched"] += 1
        if bool(final_analysis.get("stage1_timeout_hit", False)):
            stage1_progress["timeout"] += 1
        if fallback_taken:
            stage1_progress["fallback_dns"] += 1
        await _record_checkpoint(
            _build_shortlist_patch(
                run_context=run_context,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="stage1",
                stage_status="escalated" if bool(final_analysis.get("escalate_to_hashing")) else (fetch_status or "failed"),
                current_stage="stage1",
                retry_count=int(final_analysis.get("stage1_retry_count", 0) or 0),
                timeout_hit=bool(final_analysis.get("stage1_timeout_hit", False)),
                fallback_taken=fallback_taken,
                worker_id="ray-stage1",
                error_type=str(final_analysis.get("stage1_error_type", "") or final_analysis.get("fetch_error_type", "")),
                error_message=str(final_analysis.get("stage1_error_message", "") or final_analysis.get("fetch_error_detail", "")),
                final_pipeline_status=None if bool(final_analysis.get("escalate_to_hashing")) or fallback_taken else "filtered_lexical_miss",
                failure_reason=str(final_analysis.get("stage1_reasons", "") or final_analysis.get("fetch_error_detail", "")),
            ),
            _build_shortlist_stage_event(
                run_context=run_context,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="stage1",
                worker_id="ray-stage1",
                started_at=str(record.get("stage_started_at", "") or utc_now_iso()),
                started_monotonic=float(record.get("started_monotonic", time.perf_counter()) or time.perf_counter()),
                status="escalated" if bool(final_analysis.get("escalate_to_hashing")) else (fetch_status or "failed"),
                retry_count=int(final_analysis.get("stage1_retry_count", 0) or 0),
                timeout_flag=bool(final_analysis.get("stage1_timeout_hit", False)),
                error_type=str(final_analysis.get("stage1_error_type", "") or final_analysis.get("fetch_error_type", "")),
                error_message=str(final_analysis.get("stage1_error_message", "") or final_analysis.get("fetch_error_detail", "")),
                fallback_taken=fallback_taken,
            ),
        )

    async def _handle_stage_error(kind: str, context: Any, exc: BaseException) -> None:
        error_type = type(exc).__name__
        error_message = str(exc)
        if kind in {"stage1_fetch", "stage1_parse", "stage1_enrich"}:
            record = dict(context.get("record", context))
            await _finalize_stage1(
                record,
                {
                    "normalized_url": str(record.get("normalized_url", "") or ""),
                    "fetch_status": "failed",
                    "fetch_error_type": error_type,
                    "fetch_error_detail": error_message,
                    "stage1_error_type": error_type,
                    "stage1_error_message": error_message,
                    "stage1_reasons": "stage1_task_failed",
                },
            )
            return
        if kind in {"hash_render", "hash_enrich"}:
            artifact = dict(context)
            payload_outcome = comparison._handle_stage1_fetch_payload(
                {
                    "url": str(artifact.get("raw_url", "") or artifact.get("normalized_url", "")),
                    "normalized_url": str(artifact.get("normalized_url", "") or artifact.get("raw_url", "")),
                    "final_landing_url": "",
                    "screenshot_path": "",
                    "visual_status": "failed",
                    "fetch_status": "failed",
                    "fetch_error_type": error_type,
                    "fetch_error_detail": error_message,
                    "source_workbook": str(artifact.get("source_workbook", "") or ""),
                },
                str(artifact.get("normalized_url", "") or artifact.get("raw_url", "")),
                dict(artifact.get("prefetch_metrics", {}) or {}),
                scoring_config,
                stage1_analysis=dict(artifact.get("stage1_analysis", {}) or {}),
            )
            await _record_hash_fetch_outcome(payload_outcome, artifact)
            return
        raise exc

    def _refresh_progress_bar(progress_bar: Any | None) -> None:
        if progress_bar is None:
            return
        completed = shortlist_progress.completed
        if completed > progress_bar.n:
            progress_bar.update(completed - progress_bar.n)
        render_queue_depth = sum(1 for pending_kind, _ in pending.values() if pending_kind == "hash_render") + len(hash_backlog)
        aux_queue_depth = sum(1 for pending_kind, _ in pending.values() if pending_kind == "hash_enrich")
        finalize_queue_depth = len(finalize_buffer) + sum(
            1 for pending_kind, _ in pending.values() if pending_kind == "hash_finalize"
        )
        progress_bar.set_postfix(
            _build_shortlist_progress_postfix(
                progress_tracker=shortlist_progress,
                started_monotonic=t0,
                stage0_processed=stage0_hits + stage0_misses,
                stage0_hits=stage0_hits,
                stage0_misses=stage0_misses,
                stage1_inflight=_pending_count("stage1_fetch", "stage1_parse", "stage1_enrich"),
                stage1_backlog=len(stage1_backlog),
                render_queue_depth=render_queue_depth,
                aux_queue_depth=aux_queue_depth,
                finalize_queue_depth=finalize_queue_depth,
                active_hash_concurrency=int(controller_state.get("hash_live_active_pages", 0) or 0),
                match_count=int(metrics.get("final_matches_above_threshold", 0) or 0),
                phase=str(metrics.get("phase", "running") or "running"),
            ),
            refresh=False,
        )
        progress_bar.refresh()

    async def _progress_monitor(progress_bar: Any | None) -> None:
        if progress_bar is None:
            return
        while not progress_stop.is_set():
            _refresh_progress_bar(progress_bar)
            try:
                await asyncio.wait_for(progress_stop.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass

    heartbeat_stop = asyncio.Event()
    heartbeat_workers: set[tuple[str, str]] = set()
    controller_stop = asyncio.Event()

    async def _heartbeat_monitor() -> None:
        nonlocal heartbeat_workers
        if checkpoint_actor is None:
            return
        while not heartbeat_stop.is_set():
            now = time.perf_counter()
            active_workers: set[tuple[str, str]] = set()
            for kind, context in list(pending.values()):
                heartbeat = _build_heartbeat_payload(kind, context, now=now)
                if heartbeat is None:
                    continue
                stage_name = str(heartbeat.get("stage_name", "") or "shortlist")
                worker_id = str(heartbeat.get("worker_id", "") or "")
                active_workers.add((stage_name, worker_id))
                checkpoint_actor.update_worker_heartbeat.remote(
                    stage_name=stage_name,
                    worker_id=worker_id,
                    record_key=str(heartbeat.get("record_key", "") or ""),
                    state="running",
                    task_kind=str(heartbeat.get("task_kind", "") or ""),
                    item_age_s=float(heartbeat.get("item_age_s", 0.0) or 0.0),
                    details=dict(heartbeat.get("details") or {}),
                )
            for stage_name, worker_id in sorted(heartbeat_workers - active_workers):
                checkpoint_actor.clear_worker_heartbeat.remote(stage_name=stage_name, worker_id=worker_id)
            heartbeat_workers = active_workers
            try:
                await asyncio.wait_for(heartbeat_stop.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                pass

    logging_redirect_ctx = tqdm_logging_redirect(progress_enabled)
    progress_bar_ctx = managed_progress_bar(
        enabled=progress_enabled,
        desc="Ray shortlist",
        total=len(input_urls),
        unit="url",
        position=0,
    )
    logging_redirect_ctx.__enter__()
    progress_bar = progress_bar_ctx.__enter__()
    progress_task = asyncio.create_task(_progress_monitor(progress_bar)) if progress_bar is not None else None
    heartbeat_task = asyncio.create_task(_heartbeat_monitor()) if checkpoint_actor is not None else None

    async def _control_monitor() -> None:
        if not dynamic_control_enabled and checkpoint_actor is None:
            return
        last_tick = time.perf_counter()
        last_checkpoint_flush = last_tick
        last_completed = shortlist_progress.completed
        last_timeout_count = int(stage1_progress.get("timeout", 0) or 0) + int(metrics.get("fetch_timed_out", 0) or 0)
        while not controller_stop.is_set():
            try:
                await asyncio.wait_for(controller_stop.wait(), timeout=control_interval_seconds)
                break
            except asyncio.TimeoutError:
                pass
            now = time.perf_counter()
            expected_tick = last_tick + control_interval_seconds
            event_loop_lag_ms = max(0.0, (now - expected_tick) * 1000.0)
            last_tick = now
            resource_snapshot = debug_ray_resource_snapshot()
            available_cpu = float(resource_snapshot.get("available_cpu", 0.0) or 0.0)
            cluster_cpu = float(resource_snapshot.get("cluster_cpu", 0.0) or 0.0)
            used_cpu = float(resource_snapshot.get("used_cpu", 0.0) or 0.0)
            cpu_utilization = max(0.0, min(1.0, used_cpu / cluster_cpu)) if cluster_cpu > 0 else 0.0
            stage1_pending = _pending_count("stage1_fetch", "stage1_parse", "stage1_enrich")
            hash_pending = _pending_count("hash_render", "hash_enrich", "hash_finalize")
            stage1_pressure_ratio = max(
                stage1_pending / max(1, stage1_pending_cap),
                len(stage1_backlog) / max(1, stage1_pending_cap),
            )
            hash_pressure_ratio = max(
                hash_pending / max(1, hash_pending_cap),
                len(hash_backlog) / max(1, hash_pending_cap),
            )
            completed_now = shortlist_progress.completed
            completed_delta = max(0, completed_now - last_completed)
            last_completed = completed_now
            timeout_count = int(stage1_progress.get("timeout", 0) or 0) + int(metrics.get("fetch_timed_out", 0) or 0)
            timeout_delta = max(0, timeout_count - last_timeout_count)
            last_timeout_count = timeout_count
            timeout_ratio = float(timeout_delta / max(1, completed_delta)) if completed_delta or timeout_delta else 0.0
            checkpoint_backlog: dict[str, Any] = {}
            if checkpoint_actor is not None:
                try:
                    checkpoint_backlog = dict(await _ray_get(checkpoint_actor.get_backlog_snapshot.remote()) or {})
                except Exception:
                    logger.exception("Failed to snapshot checkpoint backlog for shortlist controller")
                if (now - last_checkpoint_flush) >= 10.0:
                    checkpoint_actor.export_all.remote()
                    last_checkpoint_flush = now
            checkpoint_pending_rows = int(checkpoint_backlog.get("pending_rows_total", 0) or 0)
            severe_reasons: list[str] = []
            if available_cpu < severe_available_cpu_floor:
                severe_reasons.append("cpu_headroom_low")
            if available_cpu < float(cpu_headroom_cores) and cpu_utilization > min(0.99, target_cpu_utilization + 0.12):
                severe_reasons.append("cpu_utilization")
            if event_loop_lag_ms > 250.0:
                severe_reasons.append("event_loop_lag")
            if stage1_pressure_ratio > 0.75:
                severe_reasons.append("stage1_pressure")
            if len(finalize_buffer) > (2 * max(1, int(runtime_config["hash_finalize_batch"]))):
                severe_reasons.append("hash_finalize_backlog")
            if timeout_ratio > 0.25:
                severe_reasons.append("timeout_ratio")
            if checkpoint_pending_rows > 20000:
                severe_reasons.append("checkpoint_backlog")
            healthy_window = (
                available_cpu > healthy_available_cpu_floor
                and cpu_utilization < min(0.99, target_cpu_utilization + 0.05)
                and event_loop_lag_ms < 100.0
                and stage1_pressure_ratio < 0.50
                and hash_pressure_ratio < 0.50
                and timeout_ratio < 0.10
                and checkpoint_pending_rows < 5000
            )
            action = "hold"
            reason = "steady"
            if dynamic_control_enabled and severe_reasons:
                controller_state["healthy_streak"] = 0
                changed = False
                if int(controller_state["stage0_live_inflight"]) > stage0_inflight_floor:
                    controller_state["stage0_live_inflight"] = max(stage0_inflight_floor, int(controller_state["stage0_live_inflight"]) - 1)
                    changed = True
                if int(controller_state["stage1_live_fetch_limit"]) > stage1_fetch_limit_floor:
                    controller_state["stage1_live_fetch_limit"] = max(stage1_fetch_limit_floor, int(controller_state["stage1_live_fetch_limit"]) - 8)
                    changed = True
                if int(controller_state["hash_live_active_pages"]) > hash_active_pages_floor:
                    controller_state["hash_live_active_pages"] = max(hash_active_pages_floor, int(controller_state["hash_live_active_pages"]) - 2)
                    changed = True
                action = "downshift" if changed else "hold"
                reason = ",".join(severe_reasons[:3])
            elif dynamic_control_enabled and healthy_window:
                controller_state["healthy_streak"] = int(controller_state.get("healthy_streak", 0) or 0) + 1
                if int(controller_state["healthy_streak"]) >= 2:
                    controller_state["healthy_streak"] = 0
                    changed = False
                    if int(controller_state["stage0_live_inflight"]) < stage0_inflight:
                        controller_state["stage0_live_inflight"] = min(stage0_inflight, int(controller_state["stage0_live_inflight"]) + 1)
                        changed = True
                    if int(controller_state["stage1_live_fetch_limit"]) < stage1_fetch_limit_cap:
                        controller_state["stage1_live_fetch_limit"] = min(stage1_fetch_limit_cap, int(controller_state["stage1_live_fetch_limit"]) + 8)
                        changed = True
                    if int(controller_state["hash_live_active_pages"]) < hash_active_pages_cap:
                        controller_state["hash_live_active_pages"] = min(hash_active_pages_cap, int(controller_state["hash_live_active_pages"]) + 2)
                        changed = True
                    action = "upshift" if changed else "hold"
                    reason = "healthy_window"
                else:
                    action = "hold"
                    reason = "healthy_window_pending"
            elif dynamic_control_enabled:
                controller_state["healthy_streak"] = 0
            else:
                action = "hold"
                reason = "dynamic_control_disabled"
            controller_state.update(
                {
                    "action": action,
                    "reason": reason,
                    "available_cpu": round(available_cpu, 3),
                    "cpu_utilization": round(cpu_utilization, 3),
                    "event_loop_lag_ms": round(event_loop_lag_ms, 3),
                    "checkpoint_pending_rows": checkpoint_pending_rows,
                    "timeout_ratio": round(timeout_ratio, 3),
                    "stage1_pressure_ratio": round(stage1_pressure_ratio, 3),
                    "hash_pressure_ratio": round(hash_pressure_ratio, 3),
                    "progress_completed": int(completed_now),
                }
            )
            metrics["active_fetch_limit"] = int(controller_state.get("hash_live_active_pages", hash_active_pages_cap) or hash_active_pages_cap)

    control_task = asyncio.create_task(_control_monitor()) if (checkpoint_actor is not None or dynamic_control_enabled) else None
    _refresh_progress_bar(progress_bar)

    try:
        while remaining_stage0_urls or pending or finalize_buffer or stage1_backlog or hash_backlog:
            await _drain_backlogs()
            while remaining_stage0_urls:
                inflight_stage0 = sum(1 for kind, _ in pending.values() if kind == "stage0_batch")
                if inflight_stage0 >= int(controller_state.get("stage0_live_inflight", stage0_inflight) or stage0_inflight):
                    break
                if _pending_count("stage1_fetch", "stage1_parse", "stage1_enrich") >= stage1_pending_cap:
                    break
                if _pending_count("hash_render", "hash_enrich", "hash_finalize") >= hash_pending_cap:
                    break
                if _pending_count("stage1_fetch") >= int(controller_state.get("stage1_live_fetch_limit", stage1_fetch_limit_cap) or stage1_fetch_limit_cap):
                    break
                if _pending_count("hash_render") >= int(controller_state.get("hash_live_active_pages", hash_active_pages_cap) or hash_active_pages_cap):
                    break
                # NOTE: We intentionally do NOT block stage0 on hash_backlog size.
                # hash_backlog is a lightweight FIFO queue; blocking stage0 (cheap
                # lexical work) on slow hash_render causes cascade stalls.
                if len(stage1_backlog) >= stage1_pending_cap:
                    break
                batch = remaining_stage0_urls[:stage0_batch_size]
                remaining_stage0_urls = remaining_stage0_urls[stage0_batch_size:]
                _track_pending(
                    primitives["stage0_batch_task"].remote(batch, lex_eval_config),
                    "stage0_batch",
                    {
                        "normalized_urls": list(batch),
                        "worker_id": f"stage0-batch-{stage0_batches_completed + inflight_stage0 + 1}",
                        "submitted_monotonic": time.perf_counter(),
                    },
                )
                if not stage0_warmup_logged:
                    logger.info(
                        "Ray shortlist Stage0 warmup | submitted initial lexical batches=%d | batch_size=%d | first completion can take a while on Windows due to worker import cost",
                        min(int(controller_state.get("stage0_live_inflight", stage0_inflight) or stage0_inflight), max(1, (len(metric_urls) + stage0_batch_size - 1) // stage0_batch_size)),
                        stage0_batch_size,
                    )
                    stage0_warmup_logged = True
            if not pending:
                await _drain_backlogs()
                await _flush_finalize_buffer(
                    finalize_buffer=finalize_buffer,
                    pending=pending,
                    threshold=threshold,
                    scoring_config=scoring_config,
                )
                _ensure_debug_submit_times()
                if not pending:
                    break
            ready, _ = await _ray_wait(list(pending.keys()), num_returns=min(8, len(pending)), timeout=1.0)
            if not ready:
                metrics["stage_elapsed_s"] = time.perf_counter() - t0
                _debug_consecutive_empty_waits += 1
                # --- Debug heartbeat on stall ---
                now_mono = time.perf_counter()
                if _is_debug_mode() and (now_mono - _debug_last_heartbeat) >= _debug_heartbeat_interval:
                    _debug_last_heartbeat = now_mono
                    kind_counts: dict[str, int] = {}
                    oldest_ages: dict[str, float] = {}
                    for ref, (kind, _) in pending.items():
                        kind_counts[kind] = kind_counts.get(kind, 0) + 1
                        submit_time = _debug_pending_submit_times.get(id(ref), (kind, now_mono))[1]
                        age = now_mono - submit_time
                        if kind not in oldest_ages or age > oldest_ages[kind]:
                            oldest_ages[kind] = round(age, 1)
                    resources = debug_ray_resource_snapshot()
                    available_cpu = resources.get("available_cpu", -1)
                    is_cpu_exhausted = isinstance(available_cpu, (int, float)) and available_cpu < 0.5
                    # Use INFO for normal slow progress, WARNING only for real issues
                    if is_cpu_exhausted:
                        logger.error(
                            "[RAY-DEBUG] ⚠️ CPU EXHAUSTION DEADLOCK | elapsed=%.0fs | empty_waits=%d "
                            "| available_cpu=%.1f | pending=%d by_kind=%s | oldest_age=%s "
                            "| backlogs: stage1=%d hash=%d finalize=%d stage0_remaining=%d",
                            now_mono - t0, _debug_consecutive_empty_waits,
                            available_cpu, len(pending), kind_counts, oldest_ages,
                            len(stage1_backlog), len(hash_backlog), len(finalize_buffer), len(remaining_stage0_urls),
                        )
                    else:
                        logger.info(
                            "[RAY-DEBUG] ⏳ Progress heartbeat | elapsed=%.0fs | pending=%d by_kind=%s "
                            "| oldest_age=%s | backlogs: stage1=%d hash=%d finalize=%d stage0_remaining=%d "
                            "| cpu=%.1f/%.1f",
                            now_mono - t0, len(pending), kind_counts, oldest_ages,
                            len(stage1_backlog), len(hash_backlog), len(finalize_buffer), len(remaining_stage0_urls),
                            resources.get("available_cpu", 0), resources.get("cluster_cpu", 0),
                        )
                    if (
                        checkpoint_actor is not None
                        and (is_cpu_exhausted or _debug_consecutive_empty_waits >= _debug_stall_warning_threshold)
                        and (now_mono - _debug_last_stall_event) >= _debug_heartbeat_interval
                    ):
                        _debug_last_stall_event = now_mono
                        checkpoint_actor.append_stall_event.remote(
                            {
                                "emitted_at": utc_now_iso(),
                                "label": "ray_shortlist_empty_wait",
                                "stage_name": "shortlist",
                                "severity": "error" if is_cpu_exhausted else "warning",
                                "message": (
                                    "Ray shortlist empty wait with CPU exhaustion"
                                    if is_cpu_exhausted
                                    else "Ray shortlist waiting on pending work without completions"
                                ),
                                "resource_snapshot": resources,
                                "details": {
                                    "elapsed_s": round(max(0.0, now_mono - t0), 3),
                                    "consecutive_empty_waits": _debug_consecutive_empty_waits,
                                    "pending_by_kind": kind_counts,
                                    "oldest_age_s": oldest_ages,
                                    "stage1_backlog": len(stage1_backlog),
                                    "hash_backlog": len(hash_backlog),
                                    "finalize_queue": len(finalize_buffer),
                                    "stage0_remaining": len(remaining_stage0_urls),
                                },
                            }
                        )
                _refresh_progress_bar(progress_bar)
                continue
            _debug_consecutive_empty_waits = 0  # Reset on successful wait
            for ref in ready:
                kind, context = pending.pop(ref)
                _debug_pending_submit_times.pop(id(ref), None)  # Clean up debug tracking
                heartbeat = _build_heartbeat_payload(kind, context, now=time.perf_counter())
                if checkpoint_actor is not None and heartbeat is not None:
                    checkpoint_actor.clear_worker_heartbeat.remote(
                        stage_name=str(heartbeat.get("stage_name", "") or "shortlist"),
                        worker_id=str(heartbeat.get("worker_id", "") or ""),
                    )
                try:
                    payload = await _ray_get(ref)
                except Exception as exc:
                    await _handle_stage_error(kind, context, exc)
                    continue
                if kind == "stage0_batch":
                    stage0_batches_completed += 1
                    stage0_latency_sum_ms += float(payload.get("elapsed_ms", 0.0) or 0.0)
                    lexical_hit_records: list[dict[str, Any]] = []
                    lexical_miss_records: list[dict[str, Any]] = []
                    for normalized_url, prefetch_metrics in zip(payload.get("normalized_urls", []), payload.get("prefetch_results", [])):
                        prefetch_row = dict(prefetch_metrics or {})
                        prefetch_row["source_workbook"] = source_workbook_map.get(normalized_url, prefetch_row.get("source_workbook", ""))
                        prefetch_metrics_map[normalized_url] = prefetch_row
                        for record_entry in pending_records_by_url.get(normalized_url, []):
                            raw_url = str(record_entry.get("raw_url", "") or "")
                            source_workbook = str(record_entry.get("source_workbook", "") or "")
                            progress_key = str(record_entry.get("progress_key", "") or "")
                            stage_started_at = utc_now_iso()
                            stage_started_monotonic = time.perf_counter()
                            if comparison._passes_lexical_gate(prefetch_row):
                                stage0_hits += 1
                                await _record_checkpoint(
                                    _build_shortlist_patch(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", stage_status="lexical_hit", current_stage="stage0", worker_id="ray-stage0"),
                                    _build_shortlist_stage_event(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", worker_id="ray-stage0", started_at=stage_started_at, started_monotonic=stage_started_monotonic, status="lexical_hit"),
                                )
                                lexical_hit_records.append(
                                    {
                                        "raw_url": raw_url,
                                        "normalized_url": normalized_url,
                                        "source_workbook": source_workbook,
                                        "stage_started_at": stage_started_at,
                                        "started_monotonic": stage_started_monotonic,
                                        "progress_key": progress_key,
                                    }
                                )
                            else:
                                stage0_misses += 1
                                await _record_checkpoint(
                                    _build_shortlist_patch(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", stage_status="filtered_lexical_miss", current_stage="stage0", worker_id="ray-stage0"),
                                    _build_shortlist_stage_event(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", worker_id="ray-stage0", started_at=stage_started_at, started_monotonic=stage_started_monotonic, status="filtered_lexical_miss"),
                                )
                                lexical_miss_records.append(
                                    {
                                        "raw_url": raw_url,
                                        "normalized_url": normalized_url,
                                        "source_workbook": source_workbook,
                                        "stage_started_at": stage_started_at,
                                        "started_monotonic": stage_started_monotonic,
                                        "progress_key": progress_key,
                                    }
                                )
                    if lexical_hit_records:
                        dns_gate_result = await comparison._dns_gate_lexical_miss_records(
                            lexical_hit_records,
                            stage1_http_config=stage1_http_config,
                        )
                        hit_dns_prefetch_map = dict(dns_gate_result.get("dns_prefetch_map") or {})
                        stage1_progress["dns_hit_gate_accepted"] = int(stage1_progress.get("dns_hit_gate_accepted", 0) or 0) + int(dns_gate_result.get("stats", {}).get("accepted", 0) or 0)
                        stage1_progress["dns_hit_gate_passthrough"] = int(stage1_progress.get("dns_hit_gate_passthrough", 0) or 0) + int(dns_gate_result.get("stats", {}).get("rejected", 0) or 0)
                        for record in dns_gate_result["accepted_records"]:
                            raw_url = str(record.get("raw_url", "") or "")
                            normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(raw_url))
                            source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
                            progress_key = str(record.get("progress_key", "") or "")
                            stage1_state = comparison._build_lexical_stage1_state(prefetch_metrics_map.get(normalized_url, {}))
                            stage1_state.update(dict(hit_dns_prefetch_map.get(normalized_url, {}) or {}))
                            stage1_analysis_map[normalized_url] = stage1_state
                            await _record_checkpoint(
                                _build_shortlist_patch(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    stage_status="accepted",
                                    current_stage="dns_gate",
                                    worker_id="ray-dns-gate",
                                ),
                                _build_shortlist_stage_event(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    worker_id="ray-dns-gate",
                                    started_at=utc_now_iso(),
                                    started_monotonic=time.perf_counter(),
                                    status="accepted",
                                ),
                            )
                            await _admit_to_hash(raw_url, normalized_url, source_workbook, progress_key)
                        for record in dns_gate_result["rejected_records"]:
                            raw_url = str(record.get("raw_url", "") or "")
                            normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(raw_url))
                            source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
                            progress_key = str(record.get("progress_key", "") or "")
                            analysis = comparison._build_dns_failed_lexical_stage1_state(
                                prefetch_metrics_map.get(normalized_url, {}),
                                raw_url=raw_url,
                                normalized_url=normalized_url,
                                source_workbook=source_workbook,
                                dns_status=str(record.get("dns_status", "") or ""),
                                dns_decision=str(record.get("dns_decision", "") or "filtered"),
                                dns_answer_count=0,
                                error_message=str(record.get("error_message", "") or ""),
                            )
                            stage1_analysis_map[normalized_url] = analysis
                            _mark_shortlist_progress_completion(
                                shortlist_progress,
                                progress_completed_record_keys,
                                progress_key,
                                final_status="registration_passthrough",
                            )
                            await _record_checkpoint(
                                _build_shortlist_patch(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    stage_status="registration_passthrough",
                                    current_stage="dns_gate",
                                    worker_id="ray-dns-gate",
                                    error_type=str(analysis.get("stage1_error_type", "") or analysis.get("fetch_error_type", "")),
                                    error_message=str(analysis.get("stage1_error_message", "") or analysis.get("fetch_error_detail", "")),
                                    failure_reason=str(analysis.get("stage1_reasons", "") or "dns_not_mapped_to_ip"),
                                ),
                                _build_shortlist_stage_event(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    worker_id="ray-dns-gate",
                                    started_at=utc_now_iso(),
                                    started_monotonic=time.perf_counter(),
                                    status="registration_passthrough",
                                    error_type=str(analysis.get("stage1_error_type", "") or analysis.get("fetch_error_type", "")),
                                    error_message=str(analysis.get("stage1_error_message", "") or analysis.get("fetch_error_detail", "")),
                                ),
                            )
                    if lexical_miss_records:
                        dns_gate_result = await comparison._dns_gate_lexical_miss_records(
                            lexical_miss_records,
                            stage1_http_config=stage1_http_config,
                        )
                        dns_prefetch_map.update(dict(dns_gate_result.get("dns_prefetch_map") or {}))
                        stage1_progress["dns_gate_accepted"] = int(stage1_progress.get("dns_gate_accepted", 0) or 0) + int(dns_gate_result.get("stats", {}).get("accepted", 0) or 0)
                        stage1_progress["dns_gate_filtered"] = int(stage1_progress.get("dns_gate_filtered", 0) or 0) + int(dns_gate_result.get("stats", {}).get("rejected", 0) or 0)
                        for record in dns_gate_result["accepted_records"]:
                            raw_url = str(record.get("raw_url", "") or "")
                            normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(raw_url))
                            source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
                            progress_key = str(record.get("progress_key", "") or "")
                            await _record_checkpoint(
                                _build_shortlist_patch(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    stage_status="accepted",
                                    current_stage="dns_gate",
                                    worker_id="ray-dns-gate",
                                ),
                                _build_shortlist_stage_event(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    worker_id="ray-dns-gate",
                                    started_at=utc_now_iso(),
                                    started_monotonic=time.perf_counter(),
                                    status="accepted",
                                ),
                            )
                            await _submit_stage1_fetch(
                                {
                                    "raw_url": raw_url,
                                    "normalized_url": normalized_url,
                                    "source_workbook": source_workbook,
                                    "stage_started_at": str(record.get("stage_started_at", "") or utc_now_iso()),
                                    "started_monotonic": float(record.get("started_monotonic", time.perf_counter()) or time.perf_counter()),
                                    "progress_key": progress_key,
                                }
                            )
                        for record in dns_gate_result["rejected_records"]:
                            raw_url = str(record.get("raw_url", "") or "")
                            normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(raw_url))
                            source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
                            progress_key = str(record.get("progress_key", "") or "")
                            analysis = dict((dns_gate_result.get("analysis_by_url") or {}).get(normalized_url, {}) or {})
                            stage1_analysis_map[normalized_url] = {
                                **comparison._stage1_signal_defaults(),
                                **analysis,
                            }
                            _mark_shortlist_progress_completion(
                                shortlist_progress,
                                progress_completed_record_keys,
                                progress_key,
                                final_status="dns_gate_filtered",
                            )
                            await _record_checkpoint(
                                _build_shortlist_patch(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    stage_status="filtered_dns_inactive",
                                    current_stage="dns_gate",
                                    worker_id="ray-dns-gate",
                                    error_type=str(analysis.get("stage1_error_type", "") or analysis.get("fetch_error_type", "")),
                                    error_message=str(analysis.get("stage1_error_message", "") or analysis.get("fetch_error_detail", "")),
                                    final_pipeline_status="filtered_lexical_miss",
                                    failure_reason=str(analysis.get("stage1_reasons", "") or "dns_gate_inactive"),
                                ),
                                _build_shortlist_stage_event(
                                    run_context=run_context,
                                    raw_url=raw_url,
                                    normalized_url=normalized_url,
                                    source_workbook=source_workbook,
                                    stage_name="dns_gate",
                                    worker_id="ray-dns-gate",
                                    started_at=utc_now_iso(),
                                    started_monotonic=time.perf_counter(),
                                    status="filtered_dns_inactive",
                                    error_type=str(analysis.get("stage1_error_type", "") or analysis.get("fetch_error_type", "")),
                                    error_message=str(analysis.get("stage1_error_message", "") or analysis.get("fetch_error_detail", "")),
                                ),
                            )
                elif kind == "stage1_fetch":
                    record = dict(context)
                    _track_pending(
                        primitives["stage1_parse_task"].remote(record, payload, stage1_http_config),
                        "stage1_parse",
                        {
                            "record": record,
                            "record_key": str(record.get("record_key", "") or ""),
                            "worker_id": f"stage1-parse-{str(record.get('record_key', '') or 'item')[:8]}",
                            "submitted_monotonic": time.perf_counter(),
                        },
                    )
                elif kind == "stage1_parse":
                    record = dict(payload.get("record") or context.get("record") or {})
                    result = dict(payload.get("result") or {})
                    if bool(payload.get("should_enrich")):
                        _ensure_stage1_enrich_actors()
                        actor_slot = enrich_actor_index % len(stage1_enrich_actors)
                        actor = stage1_enrich_actors[actor_slot]
                        enrich_actor_index += 1
                        record_key = str(
                            record.get("record_key", "")
                            or make_record_key(str(record.get("normalized_url", "") or ""), str(record.get("source_workbook", "") or ""))
                        )
                        _track_pending(
                            actor.enrich.remote(record, result, dns_prefetch_map.get(record.get("normalized_url", ""), {})),
                            "stage1_enrich",
                            {
                                "record": record,
                                "record_key": record_key,
                                "worker_id": f"stage1-enrich-{actor_slot}-{record_key[:8] or 'item'}",
                                "submitted_monotonic": time.perf_counter(),
                            },
                        )
                    else:
                        await _finalize_stage1(record, result)
                elif kind == "stage1_enrich":
                    await _finalize_stage1(dict(payload.get("record") or context.get("record") or {}), dict(payload.get("result") or {}))
                elif kind == "hash_render":
                    artifact = dict(context)
                    metrics["render_completed"] += 1
                    render_payload = dict(payload or {})
                    rescue_attempted = False
                    rescue_applied = False
                    rescue_reason = ""
                    rescue_result = None
                    if _should_attempt_hash_render_rescue(artifact, render_payload):
                        metrics["render_rescue_attempted"] = int(metrics.get("render_rescue_attempted", 0) or 0) + 1
                        rescue_attempted = True
                        render_payload, rescue_result, rescue_applied, rescue_reason = await _attempt_hash_render_rescue(
                            artifact,
                            render_payload,
                        )
                        if rescue_applied:
                            metrics["render_rescue_applied"] = int(metrics.get("render_rescue_applied", 0) or 0) + 1
                    if _should_capture_render_trace(artifact, render_payload):
                        render_trace_rows.append(
                            comparison._build_ray_render_trace_row(
                                render_payload,
                                artifact=artifact,
                                rescue_attempted=rescue_attempted,
                                rescue_applied=rescue_applied,
                                rescue_reason=rescue_reason,
                                rescue_result=rescue_result,
                            )
                        )
                    if str(render_payload.get("fetch_status", "")).strip().lower() in {"fetched", "fetched_visual_missing"}:
                        record_key = str(artifact.get("record_key", "") or "")
                        _track_pending(
                            primitives["hash_enrich_task"].remote(
                                render_payload,
                                dict(artifact.get("prefetch_metrics", {}) or {}),
                                dict(artifact.get("stage1_analysis", {}) or {}),
                                scoring_config,
                            ),
                            "hash_enrich",
                            {
                                **artifact,
                                "record_key": record_key,
                                "worker_id": f"hash-enrich-{record_key[:8] or 'item'}",
                                "submitted_monotonic": time.perf_counter(),
                            },
                        )
                    else:
                        await _record_hash_fetch_outcome(
                            comparison._handle_stage1_fetch_payload(
                                render_payload,
                                str(artifact.get("normalized_url", "") or artifact.get("raw_url", "")),
                                dict(artifact.get("prefetch_metrics", {}) or {}),
                                scoring_config,
                                stage1_analysis=dict(artifact.get("stage1_analysis", {}) or {}),
                            ),
                            artifact,
                        )
                elif kind == "hash_enrich":
                    metrics["aux_completed"] += 1
                    finalize_payload = dict(payload or {})
                    finalize_payload["progress_key"] = str(
                        finalize_payload.get("progress_key", "") or context.get("progress_key", "") or ""
                    )
                    finalize_payload["record_key"] = str(
                        finalize_payload.get("record_key", "") or context.get("record_key", "") or ""
                    )
                    finalize_buffer.append(finalize_payload)
                elif kind == "hash_finalize":
                    decision = dict(payload or {})
                    results.extend(list(decision.get("results") or []))
                    review_results.extend(list(decision.get("review_results") or []))
                    decision_rows.extend(list(decision.get("decision_rows") or []))
                    for key, value in dict(decision.get("metrics") or {}).items():
                        if isinstance(value, (int, float)):
                            metrics[key] = float(metrics.get(key, 0.0) or 0.0) + float(value)
                    for progress_key in list((context or {}).get("progress_keys") or []):
                        _mark_shortlist_progress_completion(
                            shortlist_progress,
                            progress_completed_record_keys,
                            str(progress_key or ""),
                            final_status="hash_finalized",
                        )
            await _drain_backlogs()
            if finalize_buffer and not any(kind == "hash_finalize" for kind, _ in pending.values()):
                await _flush_finalize_buffer(finalize_buffer=finalize_buffer, pending=pending, threshold=threshold, scoring_config=scoring_config)
                _ensure_debug_submit_times()
            metrics["gpu_queue_depth"] = len(finalize_buffer)
            metrics["render_queue_depth"] = sum(1 for kind, _ in pending.values() if kind == "hash_render") + len(hash_backlog)
            metrics["aux_queue_depth"] = sum(1 for kind, _ in pending.values() if kind == "hash_enrich")
            metrics["stage_elapsed_s"] = time.perf_counter() - t0
            _refresh_progress_bar(progress_bar)
        if prefetch_admitted_failures:
            results.extend(prefetch_admitted_failures)
        _refresh_progress_bar(progress_bar)
        logger.info(
            "Ray shortlist complete | stage0={hits=%d,misses=%d,skipped=%d,batches=%d,avg_batch_ms=%.1f} | stage1=%s | hash={processed=%d,matched=%d}",
            stage0_hits,
            stage0_misses,
            stage0_skipped,
            stage0_batches_completed,
            stage0_latency_sum_ms / max(1, stage0_batches_completed),
            stage1_progress,
            int(metrics.get("processed", 0) or 0),
            int(metrics.get("final_matches_above_threshold", 0) or 0),
        )
        if render_trace_rows:
            trace_path = comparison._write_ray_render_trace_debug(render_trace_rows, run_context=run_context)
            logger.info("Ray shortlist render trace written to %s with %d rows", trace_path, len(render_trace_rows))
            render_trace_written = True
        logger.info("Ray shortlist RDAP metrics | %s", get_rdap_metrics_snapshot())
        return comparison._finish_hashing_shortlist_output(
            t0=t0,
            metrics=metrics,
            threshold=threshold,
            results=results,
            review_results=review_results,
            input_urls=input_urls,
            audit_rows=[],
            decision_rows=decision_rows,
            prefetch_metrics_map=prefetch_metrics_map,
            lexical_reject_urls=lexical_reject_urls,
            stage1_analysis_map=stage1_analysis_map,
            scoring_config=scoring_config,
            source_workbook_map=source_workbook_map,
            shortlist_debug_csv=shortlist_debug_csv,
            run_context=run_context,
            checkpoint_store=None,
        )
    finally:
        progress_stop.set()
        if progress_task is not None:
            await asyncio.gather(progress_task, return_exceptions=True)
        controller_stop.set()
        if control_task is not None:
            await asyncio.gather(control_task, return_exceptions=True)
        heartbeat_stop.set()
        if heartbeat_task is not None:
            await asyncio.gather(heartbeat_task, return_exceptions=True)
        if checkpoint_actor is not None:
            for stage_name, worker_id in sorted(heartbeat_workers):
                checkpoint_actor.clear_worker_heartbeat.remote(stage_name=stage_name, worker_id=worker_id)
        _refresh_progress_bar(progress_bar)
        progress_bar_ctx.__exit__(None, None, None)
        logging_redirect_ctx.__exit__(None, None, None)
        stop_metrics.set()
        await asyncio.gather(metrics_task, return_exceptions=True)
        if render_trace_rows and not render_trace_written:
            try:
                trace_path = comparison._write_ray_render_trace_debug(render_trace_rows, run_context=run_context)
                logger.info("Ray shortlist render trace written to %s with %d rows", trace_path, len(render_trace_rows))
            except Exception:
                logger.exception("Failed to write Ray shortlist render trace debug artifact")
        close_refs = [actor.close.remote() for actor in stage1_fetch_actors + stage1_enrich_actors + hash_browser_actors]
        if close_refs:
            await _ray_get(close_refs)
        if checkpoint_actor is not None:
            await _ray_get(checkpoint_actor.close.remote())
        comparison._close_hashing_log()
        sync_run_artifact(run_context, "hashing_log", src_path=log_path, best_effort=True)
