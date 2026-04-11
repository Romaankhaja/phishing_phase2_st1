# main_controller.py
"""
CLI controller for the phishing pipeline.
"""

import sys
import os
import argparse
import asyncio
import csv
import json
import logging
import warnings
from typing import Any

# Event loop policy on Windows
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    warnings.filterwarnings(
        "ignore",
        category=ResourceWarning,
        message=r".*unclosed transport.*",
        module=r"asyncio\.proactor_events",
    )

    class _AsyncioPipeClosedNoiseFilter(logging.Filter):
        """Suppress known-noisy Windows proactor pipe-close warnings."""

        _SUPPRESSED_FRAGMENT = "pipe closed by peer or os.write(pipe, data) raised exception"

        def filter(self, record: logging.LogRecord) -> bool:
            try:
                message = record.getMessage()
            except Exception:
                return True
            return self._SUPPRESSED_FRAGMENT not in message
    
    # Silence "Event loop is closed" error on Windows
    from functools import wraps
    from asyncio.proactor_events import _ProactorBasePipeTransport
    
    def silence_event_loop_closed(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except RuntimeError as e:
                # Ignore this specific error during shutdown
                if str(e) != 'Event loop is closed':
                    raise
        return wrapper

    _ProactorBasePipeTransport.__del__ = silence_event_loop_closed(_ProactorBasePipeTransport.__del__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

if sys.platform.startswith("win"):
    _asyncio_logger = logging.getLogger("asyncio")
    if not getattr(_asyncio_logger, "_pipe_closed_noise_filter_installed", False):
        _asyncio_logger.addFilter(_AsyncioPipeClosedNoiseFilter())
        _asyncio_logger._pipe_closed_noise_filter_installed = True


def _non_negative_float(value: str) -> float:
    fatal_stage = "controller_startup"
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Value must be numeric") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("Value must be non-negative")
    return parsed


def _probability_float(value: str) -> float:
    parsed = _non_negative_float(value)
    if parsed > 1:
        raise argparse.ArgumentTypeError("Value must be in [0, 1]")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("Value must be non-negative")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _non_negative_int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be > 0")
    return parsed


def _pipeline_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    allowed = {"hash_only", "legacy_ocr"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"pipeline mode must be one of {sorted(allowed)}")
    return normalized


def _stage_smoke_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    allowed = {"off", "fetch", "lexical", "score", "classify", "all"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"stage smoke test must be one of {sorted(allowed)}")
    return normalized


def _runtime_profile(value: str) -> str:
    normalized = str(value).strip().lower()
    from phishing_pipeline.config import RUNTIME_PROFILE_NAMES

    allowed = set(RUNTIME_PROFILE_NAMES)
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"runtime profile must be one of {sorted(allowed)}")
    return normalized


def _stage1_failure_policy(value: str) -> str:
    normalized = str(value or "").strip().lower()
    allowed = {"route_to_dns", "stop"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"stage1 failure policy must be one of {sorted(allowed)}")
    return normalized


def _telemetry_mode(value: str) -> str:
    normalized = str(value or "").strip().lower()
    allowed = {"sampled", "full", "debug"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"telemetry mode must be one of {sorted(allowed)}")
    return normalized


def _probe_runtime_resources() -> dict[str, Any]:
    from phishing_pipeline.config import probe_runtime_resources

    return probe_runtime_resources()


# UNUSED_IN_PROD_RAY_FLOW: dead wrapper after config centralization; no callers remain.
# def _resolve_auto_runtime_profile(resource_info: dict[str, Any] | None = None) -> str:
#     from phishing_pipeline.config import _resolve_auto_runtime_profile as resolve_auto_runtime_profile
#
#     return resolve_auto_runtime_profile(resource_info)


def _resolve_runtime_profile_settings(
    profile: str,
    *,
    resource_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from phishing_pipeline.config import resolve_runtime_profile

    return resolve_runtime_profile(profile, resource_info=resource_info)


def _apply_runtime_profile_env(settings: dict[str, Any]) -> None:
    from phishing_pipeline.config import apply_runtime_profile_env

    apply_runtime_profile_env(settings)


# UNUSED_IN_PROD_RAY_FLOW: dead wrapper after controller switched to direct config resolvers.
# def _apply_stage1_http_runtime_profile(stage1_http_config: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
#     from phishing_pipeline.config import resolve_stage1_http_config
#
#     resolved = resolve_stage1_http_config(stage1_http_config, runtime_profile_settings=settings)
#     stage1_http_config.clear()
#     stage1_http_config.update(resolved)
#     return stage1_http_config


# UNUSED_IN_PROD_RAY_FLOW: dead wrapper after controller switched to direct config resolvers.
# def _apply_reliability_runtime_profile(reliability_config: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
#     from phishing_pipeline.config import resolve_reliability_config
#
#     resolved = resolve_reliability_config(reliability_config, runtime_profile_settings=settings)
#     reliability_config.clear()
#     reliability_config.update(resolved)
#     return reliability_config


def _load_runtime_components() -> dict[str, Any]:
    """
    Import pipeline modules lazily.

    This avoids import-time side effects when Windows multiprocessing spawns
    worker processes and re-imports this file as ``__mp_main__``.
    """
    components: dict[str, Any] = {
        "FINAL_OUTPUT": None,
        "close_browser": None,
        "run_pipeline": None,
        "package_results": None,
        "shortlisting": None,
        "run_hashing_shortlist_async": None,
    }

    try:
        from phishing_pipeline.config import FINAL_OUTPUT
        components["FINAL_OUTPUT"] = FINAL_OUTPUT
    except Exception as exc:
        logger.warning("Could not import FINAL_OUTPUT from config: %s", exc)

    try:
        from phishing_pipeline.visual_features import close_browser
        components["close_browser"] = close_browser
    except Exception as exc:
        logger.warning("Could not import close_browser from visual_features: %s", exc)

    try:
        from phishing_pipeline import pipeline
        components["run_pipeline"] = pipeline.run_pipeline
        components["package_results"] = pipeline.package_results
        logger.info("Imported run_pipeline and package_results from pipeline.py")
    except ImportError as exc:
        logger.error("Failed to import from pipeline.py: %s", exc)
        raise

    try:
        from phishing_pipeline import shortlisting
        components["shortlisting"] = shortlisting
        logger.info("Imported shortlisting module for utils (shortlisting.py)")
    except ImportError as exc:
        logger.warning("Could not import shortlisting.py: %s", exc)

    try:
        from phishing_pipeline.comparison import run_hashing_shortlist_async
        components["run_hashing_shortlist_async"] = run_hashing_shortlist_async
        logger.info("Imported run_hashing_shortlist_async from phishing_pipeline.comparison")
    except ImportError as exc:
        logger.warning("Could not import phishing_pipeline.comparison: %s", exc)

    return components


def _load_existing_run_manifest(path: str) -> dict[str, Any] | None:
    json_path = os.path.splitext(path)[0] + ".json"
    if os.path.exists(json_path):
        try:
            with open(json_path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                metadata_json = data.get("metadata_json")
                if isinstance(metadata_json, str):
                    try:
                        data["metadata_json"] = json.loads(metadata_json)
                    except Exception:
                        data["metadata_json"] = {}
                return data
        except Exception:
            pass
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except Exception:
        return None
    if not rows:
        return None
    data = dict(rows[-1])
    metadata_json = data.get("metadata_json")
    if isinstance(metadata_json, str):
        try:
            data["metadata_json"] = json.loads(metadata_json)
        except Exception:
            data["metadata_json"] = {}
    return data


def _stable_json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _build_resume_compatibility_snapshot(
    *,
    args: argparse.Namespace,
    runtime_profile_settings: dict[str, Any],
) -> dict[str, Any]:
    return {
        "paths": {
            "shortlisting": os.path.abspath(args.shortlisting),
            "whitelist": os.path.abspath(args.whitelist),
        },
        "pipeline": {
            "pipeline_mode": args.pipeline_mode,
            "target_limit": args.target_limit,
            "limit_whitelisted": args.limit,
            "stage1_failure_policy": args.stage1_failure_policy,
            "runtime_profile": runtime_profile_settings["resolved_profile"],
            "telemetry_mode": args.telemetry_mode,
            "trace_record_key": str(args.trace_record_key or ""),
            "trace_url": str(args.trace_url or ""),
        },
        "thresholds": {
            "hashing_threshold": args.hashing_threshold,
            "domain_similarity_threshold": args.domain_sim_threshold,
            "high_confidence_threshold": args.high_confidence_threshold,
            "medium_confidence_threshold": args.medium_confidence_threshold,
            "typo_top_k": args.typo_top_k,
            "typo_min_score": args.typo_min_score,
            "lexical_pass_min_score": args.lexical_pass_min_score,
            "stage1_escalate_total_threshold": args.stage1_escalate_total_threshold,
            "stage1_brand_min": args.stage1_brand_min,
            "stage1_credential_min": args.stage1_credential_min,
            "stage1_low_band_min": args.stage1_low_band_min,
            "stage1_hard_trigger_brand_min": args.stage1_hard_trigger_brand_min,
            "keep_stage1_suspected": bool(args.keep_stage1_suspected),
            "keep_fetch_failed_strict_lexical": bool(args.keep_fetch_failed_strict_lexical),
            "failed_fetch_suspected_min": args.failed_fetch_suspected_min,
            "failed_fetch_review_min": args.failed_fetch_review_min,
        },
        "weights": {
            "domain": args.weight_domain,
            "favicon": args.weight_favicon,
            "ssl_hash": args.weight_ssl_hash,
            "html_hash": args.weight_html_hash,
            "domain_hash": args.weight_domain_hash,
            "keywords": args.weight_keywords,
        },
        "runtime_env": dict(runtime_profile_settings.get("env") or {}),
        "stage1_http_profile": dict(runtime_profile_settings.get("stage1_http") or {}),
    }


def _manifest_matches_inputs(manifest: dict[str, Any] | None, metadata: dict[str, Any]) -> bool:
    if not manifest:
        return False
    manifest_meta = manifest.get("metadata_json")
    if not isinstance(manifest_meta, dict):
        return False
    existing_signature = str(manifest_meta.get("resume_signature", "") or "").strip()
    current_signature = str(metadata.get("resume_signature", "") or "").strip()
    if existing_signature or current_signature:
        return bool(existing_signature and current_signature and existing_signature == current_signature)
    for key in ("shortlisting", "whitelist", "pipeline_mode", "target_limit", "limit_whitelisted"):
        if str(manifest_meta.get(key, "")) != str(metadata.get(key, "")):
            return False
    return True


def clear_gpu_memory():
    """Clear GPU memory before pipeline run for better performance."""
    try:
        import torch
        import gc
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
            gc.collect()
            free, total = torch.cuda.mem_get_info()
            logger.info(f"🧹 GPU memory cleared. Free: {free/1024**3:.2f} GB / {total/1024**3:.2f} GB")
        else:
            logger.info("No CUDA GPU available, skipping memory cleanup")
    except Exception as e:
        logger.warning(f"Could not clear GPU memory: {e}")


async def main():
    parser = argparse.ArgumentParser(description="Phishing Detection CLI Controller")
    
    parser.add_argument("--whitelist", type=str, default=os.path.join("data", "whitelists", "Stage_2_Legitimate_Domains_80.xlsx"),
                        help="Path to whitelist Excel file")
    parser.add_argument("--shortlisting", type=str, default=os.path.join("data", "holdout_sets"),
                        help="Folder containing shortlisting .xlsx files")
    parser.add_argument("--limit", type=int, default=None,
                        help="Number of whitelisted domains to process (default = ALL)")
    parser.add_argument("--target-limit", type=int, default=None,
                        help="Number of target URLs to load from the shortlisting Excel input before hashing")
    parser.add_argument("--pipeline-mode", type=_pipeline_mode, default="hash_only",
                        help="Pipeline mode: hash_only (default) or legacy_ocr")
    parser.add_argument("--hashing-threshold", type=_non_negative_float, default=58.0,
                        help="Minimum final shortlist score required for a match (default=58)")
    parser.add_argument("--domain-sim-threshold", type=_probability_float, default=0.80,
                        help="Minimum domain similarity in [0,1] required before domain score is counted (default=0.85)")
    parser.add_argument("--high-confidence-threshold", type=_non_negative_float, default=78.0,
                        help="Hash score threshold for High confidence band (default=78)")
    parser.add_argument("--medium-confidence-threshold", type=_non_negative_float, default=68.0,
                        help="Hash score threshold for Medium confidence band (default=68)")
    parser.add_argument("--typo-top-k", type=_positive_int, default=10,
                        help="Top-K typosquat candidate CSEs retained before deep hash scoring (default=10)")
    parser.add_argument("--typo-min-score", type=_probability_float, default=0.75,
                        help="Minimum typosquat similarity to count as typo anchor (default=0.45)")
    parser.add_argument("--lexical-pass-min-score", type=_probability_float, default=0.85,
                        help="Minimum lexical score allowed to pass Stage 1 admission even below hash threshold (default=0.85)")
    parser.add_argument("--stage1-escalate-total-threshold", type=_non_negative_int, default=None,
                        help="Override Stage1 HTTP escalate_total_threshold (default=config)")
    parser.add_argument("--stage1-brand-min", type=_non_negative_int, default=None,
                        help="Override Stage1 HTTP brand_min (default=config)")
    parser.add_argument("--stage1-credential-min", type=_non_negative_int, default=None,
                        help="Override Stage1 HTTP credential_min (default=config)")
    parser.add_argument("--stage1-low-band-min", type=_non_negative_int, default=None,
                        help="Override Stage1 HTTP low_band_min (default=config)")
    parser.add_argument("--stage1-hard-trigger-brand-min", type=_non_negative_int, default=None,
                        help="Override Stage1 HTTP hard_trigger_brand_min (default=config)")
    parser.add_argument("--keep-stage1-suspected", action="store_true",
                        help="Keep Stage1 suspected_non_escalated rows as weak holdout candidates")
    parser.add_argument("--keep-fetch-failed-strict-lexical", action="store_true",
                        help="Keep strict-lexical fetch failed/timeout rows as weak holdout candidates")
    parser.add_argument("--failed-fetch-suspected-min", type=_probability_float, default=None,
                        help="Lexical score rescue threshold for Suspected on non-fetched strict-lexical rows")
    parser.add_argument("--failed-fetch-review-min", type=_probability_float, default=None,
                        help="Lexical score rescue threshold for REVIEW_ONLY on non-fetched strict-lexical rows")
    parser.add_argument("--weight-domain", type=_non_negative_float, default=30.0,
                        help="Weight for domain similarity score contribution (default=30)")
    parser.add_argument("--weight-favicon", type=_non_negative_float, default=14.0,
                        help="Weight for favicon hash exact-match contribution (default=14)")
    parser.add_argument("--weight-ssl-hash", type=_non_negative_float, default=12.0,
                        help="Weight for SSL certificate hash exact-match contribution (default=12)")
    parser.add_argument("--weight-html-hash", type=_non_negative_float, default=6.0,
                        help="Weight for HTML hash exact-match contribution (default=6)")
    parser.add_argument("--weight-domain-hash", type=_non_negative_float, default=8.0,
                        help="Weight for domain hash exact-match contribution (default=8)")
    parser.add_argument("--weight-keywords", type=_non_negative_float, default=10.0,
                        help="Weight for keyword overlap contribution (default=10)")
    parser.add_argument("--shortlist-debug-csv", type=str, default=os.path.join("output", "stage1_lexical_debug.csv"),
                        help="Path for Stage 1 lexical/debug CSV (default=output/stage1_lexical_debug.csv)")
    parser.add_argument("--stage-smoke-test", type=_stage_smoke_mode, default="off",
                        help="Optional partial-run mode: off, fetch, lexical, score, classify, all (default=off)")
    parser.add_argument("--runtime-profile", type=_runtime_profile, default="auto",
                        help="Concurrency-only runtime preset. 'auto' is the default; 'default' is an alias for 'auto'.")
    parser.add_argument("--run-id", type=str, default=None,
                        help="Optional run identifier for reliability checkpoints and resumable outputs")
    parser.add_argument("--resume", dest="resume", action=argparse.BooleanOptionalAction, default=True,
                        help="Resume from the latest compatible incomplete run when possible (default=true)")
    parser.add_argument("--force-reprocess", action="store_true",
                        help="Ignore resume state and process all URL records again")
    parser.add_argument("--stage1-failure-policy", type=_stage1_failure_policy, default="route_to_dns",
                        help="Routing policy when cheap Stage1 HTTP analysis fails for lexical misses")
    parser.add_argument("--stall-threshold-seconds", type=_positive_int, default=180,
                        help="Watchdog threshold for no-progress detection in long-running stages (default=180)")
    parser.add_argument("--telemetry-mode", type=_telemetry_mode, default="sampled",
                        help="Observability mode: sampled (default), full, or debug")
    parser.add_argument("--trace-record-key", type=str, default=None,
                        help="Optional record_key to trace deeply without enabling deep tracing for every row")
    parser.add_argument("--trace-url", type=str, default=None,
                        help="Optional URL to trace deeply without enabling deep tracing for every row")
    parser.add_argument("--ray-debug", action="store_true",
                        help="Enable deep Ray debug logging: resource snapshots, task age tracking, stall detection heartbeats")
    args = parser.parse_args()

    # --- Activate Ray debug mode if requested ---
    if args.ray_debug or args.telemetry_mode == "debug":
        os.environ["PHISHING_RAY_DEBUG"] = "1"
        logger.info("\n" + "=" * 80)
        logger.info("🔍  RAY DEBUG MODE ENABLED")
        logger.info("    Verbose resource snapshots, pending task age tracking, and stall")
        logger.info("    heartbeats will be logged with [RAY-DEBUG] prefix.")
        logger.info("=" * 80 + "\n")

    from phishing_pipeline.config import (
        OUTPUT_DIR,
        RUN_MANIFEST_CSV,
        resolve_reliability_config,
        resolve_stage1_http_config,
    )
    from phishing_pipeline.reliability import (
        CheckpointStore,
        build_run_context,
        get_run_artifact_path,
        sync_run_artifact,
        write_run_artifact_csv,
        write_run_artifact_json,
    )

    runtime_profile_settings = _resolve_runtime_profile_settings(args.runtime_profile)
    reliability_config = resolve_reliability_config(runtime_profile_settings=runtime_profile_settings)

    reliability_metadata = {
        "shortlisting": os.path.abspath(args.shortlisting),
        "whitelist": os.path.abspath(args.whitelist),
        "pipeline_mode": args.pipeline_mode,
        "target_limit": args.target_limit,
        "limit_whitelisted": args.limit,
        "runtime_profile": args.runtime_profile,
        "telemetry_mode": args.telemetry_mode,
        "trace_record_key": str(args.trace_record_key or ""),
        "trace_url": str(args.trace_url or ""),
    }
    resume_snapshot = _build_resume_compatibility_snapshot(
        args=args,
        runtime_profile_settings=runtime_profile_settings,
    )
    reliability_metadata["resume_snapshot"] = resume_snapshot
    reliability_metadata["resume_signature"] = _stable_json_dumps(resume_snapshot)
    existing_manifest = None
    existing_run_id = None
    if args.resume and not args.force_reprocess:
        existing_manifest = _load_existing_run_manifest(RUN_MANIFEST_CSV)
        if (
            existing_manifest
            and str(existing_manifest.get("status", "")).strip().lower() != "completed"
            and _manifest_matches_inputs(existing_manifest, reliability_metadata)
        ):
            checkpoint_events_csv = str(
                existing_manifest.get("checkpoints_csv", "")
                or existing_manifest.get("url_result_events_csv", "")
                or ""
            )
            if checkpoint_events_csv and os.path.exists(checkpoint_events_csv):
                existing_run_id = str(existing_manifest.get("run_id", "") or "").strip() or None

    resolved_run_id = args.run_id or existing_run_id
    resuming_existing_run = bool(existing_run_id and resolved_run_id == existing_run_id and args.resume and not args.force_reprocess)
    run_context = build_run_context(
        output_dir=OUTPUT_DIR,
        run_id=resolved_run_id,
        telemetry_mode=args.telemetry_mode,
        trace_record_key=args.trace_record_key,
        trace_url=args.trace_url,
        stall_threshold_seconds=args.stall_threshold_seconds,
        watchdog_warning_seconds=int(reliability_config.get("watchdog_warning_seconds", 60)),
        append_flush_interval_seconds=int(reliability_config.get("append_flush_interval_seconds", 5)),
        append_flush_row_interval=int(reliability_config.get("append_flush_row_interval", 2000)),
        snapshot_flush_interval_seconds=int(reliability_config.get("snapshot_flush_interval_seconds", 30)),
        snapshot_flush_row_interval=int(reliability_config.get("snapshot_flush_row_interval", 5000)),
        stage0_progress_log_interval_seconds=int(reliability_config.get("stage0_progress_log_interval_seconds", 10)),
        stage1_failure_policy=args.stage1_failure_policy,
        max_worker_restarts=int(reliability_config.get("max_worker_restarts", 2)),
        metadata=reliability_metadata,
    )
    checkpoint_store = CheckpointStore(run_context)
    checkpoint_store.update_manifest(status="running", metadata_json=reliability_metadata)
    execution_backend = "ray" if args.pipeline_mode == "hash_only" else "legacy"
    from phishing_pipeline.progress_display import resolve_progress_mode

    requested_progress_mode = os.getenv("PHISHING_PROGRESS_MODE", "auto")
    effective_progress_mode = resolve_progress_mode(
        requested_progress_mode,
        execution_backend=execution_backend,
    )
    logger.info(
        "Reliability run context | run_id=%s | resume=%s | force_reprocess=%s | manifest=%s | checkpoints=%s | stage1_failure_policy=%s | stall_threshold_seconds=%d",
        run_context.run_id,
        resuming_existing_run,
        args.force_reprocess,
        run_context.run_manifest_csv,
        run_context.checkpoints_csv,
        run_context.stage1_failure_policy,
        run_context.stall_threshold_seconds,
    )
    logger.info(
        "Progress mode requested=%s resolved=%s | backend=%s | stderr_tty=%s",
        requested_progress_mode,
        effective_progress_mode,
        execution_backend,
        sys.stderr.isatty(),
    )

    def _load_checkpoint_store_for_finalize():
        store = checkpoint_store
        if store is not None:
            return store, False
        store = CheckpointStore(run_context)
        return store, True

    _apply_runtime_profile_env(runtime_profile_settings)

    components = _load_runtime_components()
    final_output = components["FINAL_OUTPUT"]
    close_browser = components["close_browser"]
    run_pipeline = components["run_pipeline"]
    package_results = components["package_results"]
    shortlisting = components["shortlisting"]
    run_hashing_shortlist_async = components["run_hashing_shortlist_async"]
    stage1_http_config = resolve_stage1_http_config(runtime_profile_settings=runtime_profile_settings)
    ray_runtime = None
    ray_runtime_config = {}
    if execution_backend == "ray":
        from phishing_pipeline import ray_runtime as ray_runtime
        from phishing_pipeline.config import resolve_ray_runtime_config
        ray_runtime_config = resolve_ray_runtime_config()
    effective_runtime_snapshot = {
        "requested_progress_mode": requested_progress_mode,
        "effective_progress_mode": effective_progress_mode,
        "execution_backend": execution_backend,
        "runtime_profile": runtime_profile_settings,
        "stage1_http_config": dict(stage1_http_config or {}),
        "telemetry_mode": args.telemetry_mode,
        "trace_record_key": str(args.trace_record_key or ""),
        "trace_url": str(args.trace_url or ""),
    }
    effective_runtime_snapshot["ray_runtime_config"] = dict(ray_runtime_config or {})
    write_run_artifact_json(
        run_context,
        "effective_args_json",
        {
            "args": vars(args),
            "run_id": run_context.run_id,
            "run_output_dir": run_context.run_output_dir,
            "latest_output_dir": run_context.latest_output_dir,
        },
        best_effort=True,
    )
    write_run_artifact_json(
        run_context,
        "effective_runtime_json",
        effective_runtime_snapshot,
        best_effort=True,
    )
    if checkpoint_store is not None:
        checkpoint_store.update_manifest(
            metadata_json={**reliability_metadata, "effective_runtime_snapshot": effective_runtime_snapshot}
        )
    effective_shortlist_debug_csv = get_run_artifact_path(
        run_context,
        "stage0_lexical_decisions_csv",
        args.shortlist_debug_csv,
    )
    canonical_holdout_csv = get_run_artifact_path(
        run_context,
        "holdout_csv",
        os.path.join("output", "holdout.csv"),
    )
    logger.info(
        "Run artifact roots | run_id=%s | run_output_dir=%s | latest_output_dir=%s",
        run_context.run_id,
        run_context.run_output_dir,
        run_context.latest_output_dir,
    )
    if execution_backend == "ray" and checkpoint_store is not None:
        checkpoint_store.close()
        checkpoint_store = None

    # --- Ray debug startup diagnostic ---
    if getattr(args, "ray_debug", False) and execution_backend == "ray":
        resource_info = _probe_runtime_resources()
        ray_cfg = dict(ray_runtime_config or {})
        actor_cpu_total = (
            ray_cfg["stage1_fetch_actors"] * 0.25
            + ray_cfg["stage1_enrich_actors"] * 0.25
            + ray_cfg["hash_browser_actors"] * 0.5
            + ray_cfg["classify_actors"] * 1.0
            + ray_cfg.get("ocr_actors", 1) * 1.0
        )
        logger.info("\n" + "-" * 70)
        logger.info("[RAY-DEBUG] STARTUP DIAGNOSTIC")
        logger.info("  Physical CPUs:     %d", resource_info["cpu_cores"])
        logger.info("  System RAM:        %.1f GB", resource_info["ram_gb"])
        logger.info("  GPU VRAM:          %.1f GB", resource_info["vram_gb"])
        logger.info("  Actor CPU demand:  %.1f  (fetch=%d*0.25 + enrich=%d*0.25 + browser=%d*0.5 + classify=%d*1.0 + ocr=%d*1.0)",
            actor_cpu_total,
            ray_cfg["stage1_fetch_actors"],
            ray_cfg["stage1_enrich_actors"],
            ray_cfg["hash_browser_actors"],
            ray_cfg["classify_actors"],
            ray_cfg.get("ocr_actors", 1),
        )
        logger.info("  Task CPU per call: 0.5  (stage0_batch, stage1_parse, hash_enrich, hash_finalize)")
        logger.info("  Headroom:          %.1f CPUs  (%s)",
            resource_info["cpu_cores"] - actor_cpu_total,
            "✅ OK" if resource_info["cpu_cores"] > actor_cpu_total else "🛑 RISK OF DEADLOCK",
        )
        logger.info("  Memory mode:       %s",
            "very_low" if ray_cfg.get("very_low_memory_mode") else
            "low" if ray_cfg.get("low_memory_mode") else
            "critical" if ray_cfg.get("critical_memory_mode") else "normal",
        )
        logger.info("-" * 70 + "\n")

    if args.high_confidence_threshold < args.medium_confidence_threshold:
        raise ValueError("high-confidence-threshold must be >= medium-confidence-threshold")
    if (
        args.failed_fetch_suspected_min is not None
        and args.failed_fetch_review_min is not None
        and args.failed_fetch_suspected_min < args.failed_fetch_review_min
    ):
        raise ValueError("failed-fetch-suspected-min must be >= failed-fetch-review-min")
    logger.info(
        "Runtime profile requested=%s resolved=%s | host={cpu=%s,ram_gb=%.1f,vram_gb=%.1f,platform=%s} | ray={fetch_actors=%s,enrich_actors=%s,browser_actors=%s,classify_actors=%s,stage0_inflight=%s,prewarm=%s,dynamic_control=%s}",
        runtime_profile_settings["requested_profile"],
        runtime_profile_settings["resolved_profile"],
        runtime_profile_settings["resource_info"].get("cpu_cores", "NA"),
        float(runtime_profile_settings["resource_info"].get("ram_gb", 0.0) or 0.0),
        float(runtime_profile_settings["resource_info"].get("vram_gb", 0.0) or 0.0),
        runtime_profile_settings["resource_info"].get("platform", "unknown"),
        (ray_runtime_config or {}).get("stage1_fetch_actors", "NA"),
        (ray_runtime_config or {}).get("stage1_enrich_actors", "NA"),
        (ray_runtime_config or {}).get("hash_browser_actors", "NA"),
        (ray_runtime_config or {}).get("classify_actors", "NA"),
        (ray_runtime_config or {}).get("stage0_inflight", "NA"),
        (ray_runtime_config or {}).get("prewarm_mode", "NA"),
        (ray_runtime_config or {}).get("enable_dynamic_control", "NA"),
    )
    logger.info(
        "Effective runtime concurrency | hash={pages=%s,page_concurrency=%s,http_limit=%s,aux_net_limit=%s,active_fetch_floor=%s} | stage1_http={url=%s,http=%s,dns=%s,rdap=%s,tls=%s}",
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_PAGES", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_PAGE_CONCURRENCY", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_HTTP_LIMIT", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_AUX_NET_LIMIT", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_ACTIVE_PAGES_FLOOR", "NA"),
        stage1_http_config.get("concurrency", "NA"),
        stage1_http_config.get("http_concurrency", "NA"),
        stage1_http_config.get("dns_concurrency", "NA"),
        stage1_http_config.get("rdap_concurrency", "NA"),
        stage1_http_config.get("tls_concurrency", "NA"),
    )
    logger.info(
        "Hash stage topology | pages=%s | shard_workers=%s | shards=auto | http_limit=%s | aux_net_limit=%s | active_pages_floor=%s",
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_PAGES", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_PAGE_CONCURRENCY", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_HTTP_LIMIT", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_AUX_NET_LIMIT", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_ACTIVE_PAGES_FLOOR", "NA"),
    )
    logger.info(
        "Stage1 lane topology | tiered_fast_path=%s | dns_reuse=%s | final_domain_dns_fallback=%s | fetch={start=%s,max=%s,floor=%s,conn=%s,keepalive=%s,per_host=%s} | cpu_workers=%s | enrich={dns=%s,rdap=%s,tls=%s} | queues={fetch=%s,cpu=%s,enrich=%s,result=%s}",
        stage1_http_config.get("stage1_enable_tiered_fast_path", False),
        True,
        True,
        stage1_http_config.get("stage1_fetch_concurrency_start", "NA"),
        stage1_http_config.get("stage1_fetch_concurrency_max", "NA"),
        stage1_http_config.get("stage1_fetch_concurrency_floor", "NA"),
        stage1_http_config.get("stage1_http_connection_limit", "NA"),
        stage1_http_config.get("stage1_http_keepalive_limit", "NA"),
        stage1_http_config.get("stage1_per_host_limit", "NA"),
        stage1_http_config.get("stage1_cpu_workers", stage1_http_config.get("stage1_parse_workers", "NA")),
        stage1_http_config.get("stage1_enrich_dns_concurrency", "NA"),
        stage1_http_config.get("stage1_enrich_rdap_concurrency", "NA"),
        stage1_http_config.get("stage1_enrich_tls_concurrency", "NA"),
        stage1_http_config.get("stage1_fetch_queue_max", "NA"),
        stage1_http_config.get("stage1_cpu_queue_max", "NA"),
        stage1_http_config.get("stage1_enrich_queue_max", "NA"),
        stage1_http_config.get("stage1_result_queue_max", "NA"),
    )
    logger.info(
        "Strict attempt policy | checkpoint_mode=csv | retries={stage1=0,rdap=0,tls=0,hash=0,classify=0} | timeouts={stage1_dns=%s,stage1_connect=%s,stage1_head=%s,stage1_get=%s,stage1_rdap=%s,stage1_tls=%s}",
        stage1_http_config.get("dns_timeout", "NA"),
        stage1_http_config.get("connect_timeout", "NA"),
        stage1_http_config.get("head_timeout", "NA"),
        stage1_http_config.get("get_timeout", "NA"),
        stage1_http_config.get("rdap_timeout", "NA"),
        stage1_http_config.get("tls_timeout", "NA"),
    )

    # ✅ Ensure whitelist file exists
    if not os.path.exists(args.whitelist):
        logger.error("Whitelist file '%s' not found", args.whitelist)
        raise FileNotFoundError(f"Whitelist file '{args.whitelist}' not found")

    # ✅ Ensure shortlisting folder exists
    if not os.path.exists(args.shortlisting):
        logger.error("Shortlisting folder '%s' not found", args.shortlisting)
        raise FileNotFoundError(f"Shortlisting folder '{args.shortlisting}' not found")

    try:
        # 🧹 Clear GPU memory at the start of every run
        if execution_backend == "ray" and ray_runtime is not None:
            ray_runtime.ensure_ray_initialized()
        clear_gpu_memory()

        if resuming_existing_run:
            logger.info("Resuming existing compatible run. Output cleanup is skipped for run_id=%s", run_context.run_id)
        else:
            # Preserve resumable artifacts unless this is a fresh run.
            import shutil
            import glob

            evidence_dir = os.path.join("phishing_pipeline", "PS-02_ISS_NLP_Evidences")
            packaged_submission_dir = os.path.join("output", "PS-02_ISS_NLP_Submission")
            if os.path.isdir(evidence_dir):
                shutil.rmtree(evidence_dir, ignore_errors=True)
                logger.info("🧹 Cleared previous evidence directory: %s", evidence_dir)
            if os.path.isdir(packaged_submission_dir):
                shutil.rmtree(packaged_submission_dir, ignore_errors=True)
                logger.info("🧹 Cleared stale packaged submission directory: %s", packaged_submission_dir)
            for xlsx in glob.glob(os.path.join("phishing_pipeline", "PS-02_*_Submission_Set.xlsx")):
                os.remove(xlsx)
                logger.info("🧹 Removed old submission xlsx: %s", xlsx)

            cleanup_patterns = [
                os.path.join("output", "*.zip"),
                os.path.join("output", "output_file.csv"),
                os.path.join("output", "output_file_filtered.csv"),
                os.path.join("output", "hash_review_queue.csv"),
                os.path.join("output", "dns_gate_audit.csv"),
                os.path.join("output", "dns_rejected_lexical_hits.csv"),
                os.path.join("output", "parked_page_exclusions.csv"),
                os.path.join("output", "stage1_lexical_debug.csv"),
                os.path.join("output", "stage1_methods_debug.csv"),
                os.path.join("output", "stage1_deep_analysis_candidates.csv"),
                os.path.join("output", "stage2_model_debug.csv"),
                os.path.join("output", "stage3_classification_debug.csv"),
            ]
            if args.stage_smoke_test != "classify":
                cleanup_patterns.append(os.path.join("output", "holdout.csv"))
            for pattern in cleanup_patterns:
                for f in glob.glob(pattern):
                    os.remove(f)
                    logger.info("🧹 Removed old output: %s", f)
            legacy_checkpoint_dir = os.path.join("output", "checkpoints")
            if os.path.isdir(legacy_checkpoint_dir):
                shutil.rmtree(legacy_checkpoint_dir, ignore_errors=True)
                logger.info("Removed obsolete checkpoint folder: %s", legacy_checkpoint_dir)

        logger.info("Using whitelist file: %s", args.whitelist)
        logger.info("Using shortlisting folder: %s", args.shortlisting)
        if args.limit:
            logger.info("Processing first %d whitelisted domains...", args.limit)
        else:
            logger.info("Processing ALL whitelisted domains...")
        if args.target_limit is not None:
            logger.info("Limiting shortlist input to first %d target URLs...", args.target_limit)
        effective_stage1_thresholds = {
            "escalate_total_threshold": (
                args.stage1_escalate_total_threshold
                if args.stage1_escalate_total_threshold is not None
                else stage1_http_config.get("escalate_total_threshold", "NA")
            ),
            "brand_min": (
                args.stage1_brand_min
                if args.stage1_brand_min is not None
                else stage1_http_config.get("brand_min", "NA")
            ),
            "credential_min": (
                args.stage1_credential_min
                if args.stage1_credential_min is not None
                else stage1_http_config.get("credential_min", "NA")
            ),
            "low_band_min": (
                args.stage1_low_band_min
                if args.stage1_low_band_min is not None
                else stage1_http_config.get("low_band_min", "NA")
            ),
            "hard_trigger_brand_min": (
                args.stage1_hard_trigger_brand_min
                if args.stage1_hard_trigger_brand_min is not None
                else stage1_http_config.get("hard_trigger_brand_min", "NA")
            ),
        }
        logger.info(
            "Runtime mode=%s | shortlist threshold=%.3f domain_sim_threshold=%.3f "
            "confidence_bands={high>=%.3f, medium>=%.3f} "
            "typo={top_k=%d,min_score=%.3f,lexical_pass_min_score=%.3f} "
            "stage1_http={url_concurrency=%s,http=%s,dns=%s,rdap=%s,tls=%s,max_html_bytes=%s,max_redirects=%s,escalate_total=%s,brand_min=%s,credential_min=%s,low_band_min=%s,hard_trigger_brand_min=%s} "
            "review_policies={stage1_suspected_passthrough=%s,fetch_failed_strict_lexical_passthrough=%s} "
            "failed_fetch_rescue={suspected_min=%s,review_min=%s} "
            "weights={domain=%.3f,favicon=%.3f,ssl_hash=%.3f,html_hash=%.3f,domain_hash=%.3f,keywords=%.3f} "
            "stage_smoke_test=%s shortlist_debug_csv=%s",
            args.pipeline_mode,
            args.hashing_threshold,
            args.domain_sim_threshold,
            args.high_confidence_threshold,
            args.medium_confidence_threshold,
            args.typo_top_k,
            args.typo_min_score,
            args.lexical_pass_min_score,
            stage1_http_config.get("concurrency", "NA"),
            stage1_http_config.get("http_concurrency", "NA"),
            stage1_http_config.get("dns_concurrency", "NA"),
            stage1_http_config.get("rdap_concurrency", "NA"),
            stage1_http_config.get("tls_concurrency", "NA"),
            stage1_http_config.get("max_html_bytes", "NA"),
            stage1_http_config.get("max_redirects", "NA"),
            effective_stage1_thresholds["escalate_total_threshold"],
            effective_stage1_thresholds["brand_min"],
            effective_stage1_thresholds["credential_min"],
            effective_stage1_thresholds["low_band_min"],
            effective_stage1_thresholds["hard_trigger_brand_min"],
            args.keep_stage1_suspected,
            args.keep_fetch_failed_strict_lexical,
            args.failed_fetch_suspected_min if args.failed_fetch_suspected_min is not None else "off",
            args.failed_fetch_review_min if args.failed_fetch_review_min is not None else "off",
            args.weight_domain,
            args.weight_favicon,
            args.weight_ssl_hash,
            args.weight_html_hash,
            args.weight_domain_hash,
            args.weight_keywords,
            args.stage_smoke_test,
            effective_shortlist_debug_csv,
        )

        df_out = None

        # Try the new-style orchestration (controller -> comparison -> pipeline)
        if run_hashing_shortlist_async and shortlisting:
            if args.stage_smoke_test == "classify":
                fatal_stage = "classify"
                existing_holdout = canonical_holdout_csv
                if not os.path.exists(existing_holdout):
                    raise FileNotFoundError(f"stage-smoke-test=classify requires an existing holdout CSV at {existing_holdout}")
                logger.info("--- Stage Smoke Test classify: Reusing existing holdout.csv ---")
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting,
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None,
                    limit_target_urls=args.target_limit,
                    use_existing_holdout=True,
                    pipeline_mode=args.pipeline_mode,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    hashing_threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    shortlist_debug_csv=effective_shortlist_debug_csv,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    failed_fetch_suspected_min=args.failed_fetch_suspected_min,
                    failed_fetch_review_min=args.failed_fetch_review_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
                    execution_backend=execution_backend,
                    progress_mode=effective_progress_mode,
                )
                logger.info("--- Finished Stage Smoke Test classify ---")
            else:
            # 1. Run Shortlisting using phishing_pipeline.comparison
                fatal_stage = "shortlist"
                logger.info("--- Starting Step 1: Running Hashing-based Shortlisting ---")
                url_records = shortlisting.load_url_records_from_excel_folder(
                    args.shortlisting,
                    limit=args.target_limit,
                )
                input_manifest_rows = [
                    {
                        "url": str(record.get("url", "") or ""),
                        "source_workbooks_json": _stable_json_dumps(record.get("source_workbooks", []) or []),
                    }
                    for record in url_records
                ]
                write_run_artifact_csv(
                    run_context,
                    "input_manifest_csv",
                    ("url", "source_workbooks_json"),
                    input_manifest_rows,
                    best_effort=True,
                )
                urls = [record["url"] for record in url_records]
                url_sources = {
                    record["url"]: record.get("source_workbooks", [])
                    for record in url_records
                }
                shortlist_weights = {
                    "domain": args.weight_domain,
                    "favicon": args.weight_favicon,
                    "ssl_hash": args.weight_ssl_hash,
                    "html_hash": args.weight_html_hash,
                    "domain_hash": args.weight_domain_hash,
                    "keywords": args.weight_keywords,
                }
                
                holdout_df = await run_hashing_shortlist_async(
                    list(urls),
                    threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    weights=shortlist_weights,
                    shortlist_debug_csv=effective_shortlist_debug_csv,
                    url_sources=url_sources,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
                    execution_backend=execution_backend,
                    progress_mode=effective_progress_mode,
                )
                
                # Save output to holdout.csv
                os.makedirs(os.path.dirname(canonical_holdout_csv), exist_ok=True)
                holdout_df.to_csv(canonical_holdout_csv, index=False)
                sync_run_artifact(run_context, "holdout_csv", src_path=canonical_holdout_csv, best_effort=True)
                logger.info(f"--- Finished Step 1: Shortlisting Complete ({len(holdout_df)} matched) ---")

                if args.stage_smoke_test in {"fetch", "lexical", "score"}:
                    logger.info("Stage smoke test '%s' requested. Stopping after Step 1.", args.stage_smoke_test)
                    df_out = holdout_df
                    finalize_store, should_close_finalize_store = _load_checkpoint_store_for_finalize()
                    finalize_store.mark_completed()
                    finalize_store.export_all()
                    if should_close_finalize_store:
                        finalize_store.close()
                    return
                
                # 2. Run Pipeline
                fatal_stage = "classify"
                logger.info("--- Starting Step 2: Running Main Pipeline ---")
                
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting, 
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None,
                    limit_target_urls=args.target_limit,
                    use_existing_holdout=True,
                    pipeline_mode=args.pipeline_mode,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    hashing_threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    shortlist_debug_csv=effective_shortlist_debug_csv,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    failed_fetch_suspected_min=args.failed_fetch_suspected_min,
                    failed_fetch_review_min=args.failed_fetch_review_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
                    execution_backend=execution_backend,
                    progress_mode=effective_progress_mode,
                )
                
                logger.info("--- Finished Step 2: Main Pipeline Complete ---")

        # Fallback to old style (pipeline does everything)
        elif run_pipeline is not None:
            fatal_stage = "pipeline"
            logger.warning("Could not find shortlisting.run_shortlisting_process. Falling back to old pipeline-only mode.")
            try:
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting, 
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None,
                    limit_target_urls=args.target_limit,
                    pipeline_mode=args.pipeline_mode,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    hashing_threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    shortlist_debug_csv=effective_shortlist_debug_csv,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    failed_fetch_suspected_min=args.failed_fetch_suspected_min,
                    failed_fetch_review_min=args.failed_fetch_review_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
                    execution_backend=execution_backend,
                    progress_mode=effective_progress_mode,
                )
            except TypeError:
                df_out = await run_pipeline(args.shortlisting, args.whitelist, args.limit)
        else:
            raise RuntimeError("No suitable pipeline entrypoint found (shortlisting.run_shortlisting_process or run_pipeline).")

        # Package results if available
        zip_path = None
        if package_results is not None:
            try:
                fatal_stage = "package"
                input_name = os.path.basename(os.path.normpath(args.shortlisting))
                zip_path = package_results(zip_path=f"Submission-{input_name}.zip")
                logger.info("Packaged results into: %s", zip_path)
            except Exception as exc:
                logger.warning("package_results() failed: %s", exc)

        if final_output:
            logger.info("Final output expected at: %s", final_output)

        # Show small preview if df_out is a DataFrame-like object
        if df_out is not None:
            try:
                print(df_out.head(10))
            except Exception:
                logger.info("Output is not a pandas DataFrame or cannot be printed.")
        finalize_store, should_close_finalize_store = _load_checkpoint_store_for_finalize()
        finalize_store.mark_completed()
        finalize_store.export_all()
        if should_close_finalize_store:
            finalize_store.close()

    except Exception as exc:
        finalize_store, should_close_finalize_store = _load_checkpoint_store_for_finalize()
        finalize_store.mark_failed(stage=fatal_stage, exc=exc)
        finalize_store.export_all()
        if should_close_finalize_store:
            finalize_store.close()
        raise

    finally:
        # Always attempt to close the visual browser (if available)
        if close_browser:
            try:
                close_browser()
                logger.info("Closed visual browser.")
            except Exception as exc:
                logger.warning("close_browser() raised: %s", exc)

        # Kill any orphaned chrome-headless processes
        try:
            import subprocess
            subprocess.run(["pkill", "-f", "chrome-headless"], capture_output=True, timeout=5)
            logger.info("Cleaned up orphaned Chrome processes.")
        except Exception:
            pass  # Expected to fail on Windows
        try:
            if checkpoint_store is not None:
                checkpoint_store.close()
        except Exception as exc:
            logger.warning("Checkpoint store close failed: %s", exc)
        if execution_backend == "ray" and ray_runtime is not None:
            try:
                ray_runtime.shutdown_ray_runtime()
            except Exception as exc:
                logger.warning("Ray shutdown failed: %s", exc)


if __name__ == "__main__":
    asyncio.run(main())
