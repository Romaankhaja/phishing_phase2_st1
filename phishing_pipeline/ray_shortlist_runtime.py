from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import asdict
import logging
import time
from typing import Any

from .config import resolve_ray_runtime_config, resolve_stage1_http_config, RAY_DEBUG_MODE
from .reliability import RunContext, make_record_key, utc_now_iso
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
):
    del checkpoint_store

    from . import comparison
    from .rdap_utils import get_rdap_metrics_snapshot, reset_rdap_state

    ensure_ray_initialized()
    primitives = _get_ray_primitives()
    runtime_config = resolve_ray_runtime_config()
    logger.info(
        "Ray shortlist startup | urls=%d | ram={total_gb=%s,available_gb=%s} | local_mode=%s | low_memory=%s | server_mode=%s | prewarm=%s | actors={stage1_fetch=%d,stage1_enrich=%d,hash_browser=%d,classify=%d} | stage0={batch_size=%d,inflight=%d} | backpressure={stage1_cap=%d,hash_cap=%d} | hash={tabs_per_actor=%d,finalize_batch=%d}",
        len(url_list),
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
    logger.info("Ray shortlist control actors created | checkpoint=%s", bool(checkpoint_actor))
    stop_metrics = asyncio.Event()
    metrics_task = asyncio.create_task(
        _log_metrics_periodically(
            metrics_actor,
            stop_metrics,
            "shortlist",
            float(runtime_config["metrics_interval_seconds"]),
        )
    )

    input_urls = list(url_list)
    t0 = time.perf_counter()
    log_path = comparison._configure_hashing_log()
    logger.info("Hashing log: %s", log_path)
    reset_rdap_state()

    completed_record_keys = set()
    if checkpoint_actor is not None and resume and not force_reprocess:
        completed_record_keys = await _ray_get(checkpoint_actor.get_completed_record_keys.remote())

    pending_records_by_url: dict[str, list[tuple[str, str]]] = {}
    metric_urls: list[str] = []
    seen_metric_urls: set[str] = set()
    ensure_records: list[dict[str, Any]] = []
    stage0_skipped = 0
    for raw_url in input_urls:
        normalized_url = comparison.normalize_url(raw_url)
        source_workbook = source_workbook_map.get(normalized_url, "")
        ensure_records.append(
            {"raw_url": raw_url, "normalized_url": normalized_url, "source_workbook": source_workbook}
        )
        if run_context is not None and make_record_key(normalized_url, source_workbook) in completed_record_keys:
            stage0_skipped += 1
            continue
        pending_records_by_url.setdefault(normalized_url, []).append((raw_url, source_workbook))
        if normalized_url and normalized_url not in seen_metric_urls:
            seen_metric_urls.add(normalized_url)
            metric_urls.append(normalized_url)
    if checkpoint_actor is not None:
        checkpoint_actor.ensure_url_results.remote(ensure_records)

    prefetch_metrics_map: dict[str, dict[str, Any]] = {}
    stage1_analysis_map: dict[str, dict[str, Any]] = {}
    lexical_reject_urls: set[str] = set()
    decision_rows: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    review_results: list[dict[str, Any]] = []
    prefetch_admitted_failures: list[dict[str, Any]] = []
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
    }
    stage1_progress = {"escalated": 0, "failed": 0, "head_only": 0, "fetched": 0, "fallback_dns": 0, "timeout": 0}
    stage0_hits = 0
    stage0_misses = 0
    lex_eval_config = (int(scoring_config["typo_top_k"]), float(scoring_config["lexical_pass_min_score"]))
    stage0_batch_size = int(runtime_config["stage0_batch_size"])
    stage0_inflight = int(runtime_config["stage0_inflight"])
    stage1_pending_cap = int(runtime_config.get("stage1_pending_cap", max(1, int(runtime_config["stage1_fetch_actors"]))))
    hash_pending_cap = int(runtime_config.get("hash_pending_cap", max(1, int(runtime_config["hash_browser_actors"]))))
    stage1_fetch_actor_max_concurrency = int(runtime_config.get("stage1_fetch_actor_max_concurrency", 4) or 4)
    stage1_enrich_actor_max_concurrency = int(runtime_config.get("stage1_enrich_actor_max_concurrency", 4) or 4)
    pending: dict[Any, tuple[str, Any]] = {}
    stage1_backlog: deque[dict[str, Any]] = deque()
    hash_backlog: deque[tuple[str, str, str]] = deque()
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
        _ensure_stage1_enrich_actors()
        _ensure_hash_browser_actors()
        warm_refs = [actor.warm.remote() for actor in stage1_fetch_actors]
        warm_refs.extend(actor.warm.remote() for actor in stage1_enrich_actors)
        warm_refs.extend(actor.warm.remote() for actor in hash_browser_actors)
        if not warm_refs:
            return
        logger.info(
            "Ray shortlist prewarming actors | fetch=%d | enrich=%d | browser=%d",
            len(stage1_fetch_actors),
            len(stage1_enrich_actors),
            len(hash_browser_actors),
        )
        await _ray_get(warm_refs)
        logger.info("Ray shortlist actor prewarm complete")

    await _prewarm_actor_pools()

    def _pending_count(*kinds: str) -> int:
        wanted = set(kinds)
        return sum(1 for kind, _ in pending.values() if kind in wanted)

    async def _schedule_hash_admission(raw_url: str, normalized_url: str, source_workbook: str) -> None:
        nonlocal browser_actor_index
        _ensure_hash_browser_actors()
        artifact = asdict(
            HashRenderArtifact(
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                prefetch_metrics=dict(prefetch_metrics_map.get(normalized_url, {}) or {}),
                stage1_analysis=dict(stage1_analysis_map.get(normalized_url, {}) or {}),
            )
        )
        actor = hash_browser_actors[browser_actor_index % len(hash_browser_actors)]
        browser_actor_index += 1
        pending[actor.render.remote(artifact)] = ("hash_render", artifact)
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

    async def _admit_to_hash(raw_url: str, normalized_url: str, source_workbook: str) -> None:
        hash_backlog.append((raw_url, normalized_url, source_workbook))

    async def _schedule_stage1_fetch(record: dict[str, Any]) -> None:
        nonlocal fetch_actor_index
        _ensure_stage1_fetch_actors()
        actor = stage1_fetch_actors[fetch_actor_index % len(stage1_fetch_actors)]
        fetch_actor_index += 1
        pending[actor.fetch.remote(record)] = ("stage1_fetch", dict(record))

    async def _submit_stage1_fetch(record: dict[str, Any]) -> None:
        stage1_backlog.append(dict(record))

    async def _drain_backlogs() -> None:
        while hash_backlog and _pending_count("hash_render", "hash_enrich", "hash_finalize") < hash_pending_cap:
            raw_url, normalized_url, source_workbook = hash_backlog.popleft()
            await _schedule_hash_admission(raw_url, normalized_url, source_workbook)
        while stage1_backlog and _pending_count("stage1_fetch", "stage1_parse", "stage1_enrich") < stage1_pending_cap:
            await _schedule_stage1_fetch(stage1_backlog.popleft())

    async def _record_hash_fetch_outcome(payload_outcome: dict[str, Any]) -> None:
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

    async def _finalize_stage1(record: dict[str, Any], analysis: dict[str, Any]) -> None:
        raw_url = str(record.get("raw_url", "") or "")
        normalized_url = str(record.get("normalized_url", "") or comparison.normalize_url(raw_url))
        source_workbook = str(record.get("source_workbook", "") or source_workbook_map.get(normalized_url, ""))
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
            await _admit_to_hash(raw_url, normalized_url, source_workbook)
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
            await _record_hash_fetch_outcome(payload_outcome)
            return
        raise exc

    try:
        while remaining_stage0_urls or pending or finalize_buffer or stage1_backlog or hash_backlog:
            await _drain_backlogs()
            while remaining_stage0_urls:
                inflight_stage0 = sum(1 for kind, _ in pending.values() if kind == "stage0_batch")
                if inflight_stage0 >= stage0_inflight:
                    break
                if _pending_count("stage1_fetch", "stage1_parse", "stage1_enrich") >= stage1_pending_cap:
                    break
                if _pending_count("hash_render", "hash_enrich", "hash_finalize") >= hash_pending_cap:
                    break
                # NOTE: We intentionally do NOT block stage0 on hash_backlog size.
                # hash_backlog is a lightweight FIFO queue; blocking stage0 (cheap
                # lexical work) on slow hash_render causes cascade stalls.
                if len(stage1_backlog) >= stage1_pending_cap:
                    break
                batch = remaining_stage0_urls[:stage0_batch_size]
                remaining_stage0_urls = remaining_stage0_urls[stage0_batch_size:]
                pending[primitives["stage0_batch_task"].remote(batch, lex_eval_config)] = ("stage0_batch", {"normalized_urls": list(batch)})
                # Track submission time for debug stall detection
                for _ref in list(pending.keys()):
                    if id(_ref) not in _debug_pending_submit_times:
                        _debug_pending_submit_times[id(_ref)] = ("stage0_batch", time.perf_counter())
                if not stage0_warmup_logged:
                    logger.info(
                        "Ray shortlist Stage0 warmup | submitted initial lexical batches=%d | batch_size=%d | first completion can take a while on Windows due to worker import cost",
                        min(stage0_inflight, max(1, (len(metric_urls) + stage0_batch_size - 1) // stage0_batch_size)),
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
                continue
            _debug_consecutive_empty_waits = 0  # Reset on successful wait
            for ref in ready:
                kind, context = pending.pop(ref)
                _debug_pending_submit_times.pop(id(ref), None)  # Clean up debug tracking
                try:
                    payload = await _ray_get(ref)
                except Exception as exc:
                    await _handle_stage_error(kind, context, exc)
                    continue
                if kind == "stage0_batch":
                    stage0_batches_completed += 1
                    stage0_latency_sum_ms += float(payload.get("elapsed_ms", 0.0) or 0.0)
                    for normalized_url, prefetch_metrics in zip(payload.get("normalized_urls", []), payload.get("prefetch_results", [])):
                        prefetch_row = dict(prefetch_metrics or {})
                        prefetch_row["source_workbook"] = source_workbook_map.get(normalized_url, prefetch_row.get("source_workbook", ""))
                        prefetch_metrics_map[normalized_url] = prefetch_row
                        for raw_url, source_workbook in pending_records_by_url.get(normalized_url, []):
                            stage_started_at = utc_now_iso()
                            stage_started_monotonic = time.perf_counter()
                            if comparison._passes_lexical_gate(prefetch_row):
                                stage0_hits += 1
                                stage1_analysis_map[normalized_url] = comparison._build_lexical_stage1_state(prefetch_row)
                                await _record_checkpoint(
                                    _build_shortlist_patch(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", stage_status="lexical_hit", current_stage="stage0", worker_id="ray-stage0"),
                                    _build_shortlist_stage_event(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", worker_id="ray-stage0", started_at=stage_started_at, started_monotonic=stage_started_monotonic, status="lexical_hit"),
                                )
                                await _admit_to_hash(raw_url, normalized_url, source_workbook)
                            else:
                                stage0_misses += 1
                                lexical_reject_urls.add(normalized_url)
                                await _record_checkpoint(
                                    _build_shortlist_patch(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", stage_status="filtered_lexical_miss", current_stage="stage0", worker_id="ray-stage0"),
                                    _build_shortlist_stage_event(run_context=run_context, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="stage0", worker_id="ray-stage0", started_at=stage_started_at, started_monotonic=stage_started_monotonic, status="filtered_lexical_miss"),
                                )
                                await _submit_stage1_fetch({"raw_url": raw_url, "normalized_url": normalized_url, "source_workbook": source_workbook, "stage_started_at": stage_started_at, "started_monotonic": stage_started_monotonic})
                elif kind == "stage1_fetch":
                    record = dict(context)
                    pending[primitives["stage1_parse_task"].remote(record, payload, stage1_http_config)] = ("stage1_parse", {"record": record})
                elif kind == "stage1_parse":
                    record = dict(payload.get("record") or context.get("record") or {})
                    result = dict(payload.get("result") or {})
                    if bool(payload.get("should_enrich")):
                        _ensure_stage1_enrich_actors()
                        actor = stage1_enrich_actors[enrich_actor_index % len(stage1_enrich_actors)]
                        enrich_actor_index += 1
                        pending[actor.enrich.remote(record, result, prefetch_metrics_map.get(record.get("normalized_url", ""), {}))] = ("stage1_enrich", {"record": record})
                    else:
                        await _finalize_stage1(record, result)
                elif kind == "stage1_enrich":
                    await _finalize_stage1(dict(payload.get("record") or context.get("record") or {}), dict(payload.get("result") or {}))
                elif kind == "hash_render":
                    artifact = dict(context)
                    metrics["render_completed"] += 1
                    if str(payload.get("fetch_status", "")).strip().lower() in {"fetched", "fetched_visual_missing"}:
                        pending[primitives["hash_enrich_task"].remote(payload, dict(artifact.get("prefetch_metrics", {}) or {}), dict(artifact.get("stage1_analysis", {}) or {}), scoring_config)] = ("hash_enrich", artifact)
                    else:
                        await _record_hash_fetch_outcome(
                            comparison._handle_stage1_fetch_payload(
                                payload,
                                str(artifact.get("normalized_url", "") or artifact.get("raw_url", "")),
                                dict(artifact.get("prefetch_metrics", {}) or {}),
                                scoring_config,
                                stage1_analysis=dict(artifact.get("stage1_analysis", {}) or {}),
                            )
                        )
                elif kind == "hash_enrich":
                    metrics["aux_completed"] += 1
                    finalize_buffer.append(dict(payload or {}))
                elif kind == "hash_finalize":
                    decision = dict(payload or {})
                    results.extend(list(decision.get("results") or []))
                    review_results.extend(list(decision.get("review_results") or []))
                    decision_rows.extend(list(decision.get("decision_rows") or []))
                    for key, value in dict(decision.get("metrics") or {}).items():
                        if isinstance(value, (int, float)):
                            metrics[key] = float(metrics.get(key, 0.0) or 0.0) + float(value)
            await _drain_backlogs()
            if finalize_buffer and not any(kind == "hash_finalize" for kind, _ in pending.values()):
                await _flush_finalize_buffer(finalize_buffer=finalize_buffer, pending=pending, threshold=threshold, scoring_config=scoring_config)
            metrics["gpu_queue_depth"] = len(finalize_buffer)
            metrics["render_queue_depth"] = sum(1 for kind, _ in pending.values() if kind == "hash_render") + len(hash_backlog)
            metrics["aux_queue_depth"] = sum(1 for kind, _ in pending.values() if kind == "hash_enrich")
            metrics["stage_elapsed_s"] = time.perf_counter() - t0
        if prefetch_admitted_failures:
            results.extend(prefetch_admitted_failures)
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
        stop_metrics.set()
        await asyncio.gather(metrics_task, return_exceptions=True)
        close_refs = [actor.close.remote() for actor in stage1_fetch_actors + stage1_enrich_actors + hash_browser_actors]
        if close_refs:
            await _ray_get(close_refs)
        if checkpoint_actor is not None:
            await _ray_get(checkpoint_actor.close.remote())
        comparison._close_hashing_log()
