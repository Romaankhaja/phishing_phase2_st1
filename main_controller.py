# main_controller.py
"""
CLI controller for the phishing pipeline.
"""

import sys
import os
import argparse
import asyncio
import logging
import json
from typing import Any

# Event loop policy on Windows
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

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
    allowed = {"off", "dns", "fetch", "lexical", "score", "classify", "all"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"stage smoke test must be one of {sorted(allowed)}")
    return normalized


def _runtime_profile(value: str) -> str:
    normalized = str(value).strip().lower()
    allowed = {"auto", "default", "cpu-safe", "cpu-recall", "cpu-fast"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"runtime profile must be one of {sorted(allowed)}")
    return normalized


def _stage1_failure_policy(value: str) -> str:
    normalized = str(value or "").strip().lower()
    allowed = {"route_to_dns", "stop"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"stage1 failure policy must be one of {sorted(allowed)}")
    return normalized


def _probe_runtime_resources() -> dict[str, Any]:
    cpu_cores = os.cpu_count() or 4
    ram_gb = 0.0
    vram_gb = 0.0

    try:
        import psutil  # type: ignore

        ram_gb = float(psutil.virtual_memory().total / (1024 ** 3))
    except Exception:
        ram_gb = 0.0

    try:
        import torch  # type: ignore

        if torch.cuda.is_available():
            vram_gb = float(torch.cuda.get_device_properties(0).total_memory / (1024 ** 3))
    except Exception:
        vram_gb = 0.0

    return {
        "cpu_cores": int(cpu_cores),
        "ram_gb": float(ram_gb),
        "vram_gb": float(vram_gb),
        "platform": sys.platform,
    }


def _resolve_auto_runtime_profile(resource_info: dict[str, Any] | None = None) -> str:
    resource_info = dict(resource_info or _probe_runtime_resources())
    cpu_cores = int(resource_info.get("cpu_cores", 0) or 0)
    ram_gb = float(resource_info.get("ram_gb", 0.0) or 0.0)
    vram_gb = float(resource_info.get("vram_gb", 0.0) or 0.0)

    if cpu_cores >= 32 and ram_gb >= 96.0:
        return "cpu-recall"
    if cpu_cores <= 16 or ram_gb < 16.0 or (0.0 < vram_gb <= 6.0):
        return "cpu-safe"
    return "cpu-fast"


def _resolve_runtime_profile_settings(
    profile: str,
    *,
    resource_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    requested_profile = _runtime_profile(profile)
    resource_info = dict(resource_info or _probe_runtime_resources())
    resolved_profile = (
        _resolve_auto_runtime_profile(resource_info)
        if requested_profile in {"auto", "default"}
        else requested_profile
    )

    profiles: dict[str, dict[str, Any]] = {
        "cpu-safe": {
            "env": {
                "PHISHING_HASH_PAGES": 16,
                "PHISHING_HASH_PAGE_CONCURRENCY": 4,
                "PHISHING_HASH_HTTP_LIMIT": 64,
                "PHISHING_HASH_AUX_NET_LIMIT": 24,
                "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 6,
                "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
                "PHISHING_DNS_GATE_MIN_WORKERS": 96,
                "PHISHING_DNS_GATE_MAX_WORKERS": 192,
            },
            "stage1_http": {
                "concurrency": 96,
                "http_concurrency": 96,
                "dns_concurrency": 96,
                "rdap_concurrency": 4,
                "tls_concurrency": 16,
            },
            "dns_max_workers": 192,
        },
        "cpu-recall": {
            "env": {
                "PHISHING_HASH_PAGES": 20,
                "PHISHING_HASH_PAGE_CONCURRENCY": 4,
                "PHISHING_HASH_HTTP_LIMIT": 80,
                "PHISHING_HASH_AUX_NET_LIMIT": 32,
                "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 8,
                "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
                "PHISHING_DNS_GATE_MIN_WORKERS": 128,
                "PHISHING_DNS_GATE_MAX_WORKERS": 256,
            },
            "stage1_http": {
                "concurrency": 128,
                "http_concurrency": 128,
                "dns_concurrency": 128,
                "rdap_concurrency": 4,
                "tls_concurrency": 24,
            },
            "dns_max_workers": 256,
        },
        "cpu-fast": {
            "env": {
                "PHISHING_HASH_PAGES": 24,
                "PHISHING_HASH_PAGE_CONCURRENCY": 4,
                "PHISHING_HASH_HTTP_LIMIT": 96,
                "PHISHING_HASH_AUX_NET_LIMIT": 40,
                "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 8,
                "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
                "PHISHING_DNS_GATE_MIN_WORKERS": 128,
                "PHISHING_DNS_GATE_MAX_WORKERS": 256,
            },
            "stage1_http": {
                "concurrency": 144,
                "http_concurrency": 144,
                "dns_concurrency": 144,
                "rdap_concurrency": 8,
                "tls_concurrency": 24,
            },
            "dns_max_workers": 256,
        },
    }
    selected = profiles[resolved_profile]
    return {
        "name": resolved_profile,
        "requested_profile": requested_profile,
        "resolved_profile": resolved_profile,
        "resource_info": resource_info,
        "env": dict(selected["env"]),
        "stage1_http": dict(selected["stage1_http"]),
        "dns_max_workers": selected["dns_max_workers"],
    }


def _apply_runtime_profile_env(settings: dict[str, Any]) -> None:
    for key, value in (settings.get("env") or {}).items():
        os.environ[str(key)] = str(value)


def _apply_stage1_http_runtime_profile(stage1_http_config: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    stage1_http_config.update(settings.get("stage1_http") or {})
    return stage1_http_config


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
        "STAGE1_HTTP_CONFIG": {},
    }

    try:
        from phishing_pipeline.config import FINAL_OUTPUT, STAGE1_HTTP_CONFIG
        components["FINAL_OUTPUT"] = FINAL_OUTPUT
        components["STAGE1_HTTP_CONFIG"] = STAGE1_HTTP_CONFIG
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
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _manifest_matches_inputs(manifest: dict[str, Any] | None, metadata: dict[str, Any]) -> bool:
    if not manifest:
        return False
    manifest_meta = manifest.get("metadata_json")
    if not isinstance(manifest_meta, dict):
        return False
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
    parser.add_argument("--clip-margin-min", type=_non_negative_float, default=0.20,
                        help="Deprecated compatibility no-op. CLIP routing is disabled.")
    parser.add_argument("--dns-timeout", type=_non_negative_float, default=5.0,
                        help="DNS gate timeout in seconds (default=5.0)")
    parser.add_argument("--dns-retries", type=_non_negative_int, default=2,
                        help="DNS gate retry count for timeout/resolver errors (default=2)")
    parser.add_argument("--dns-max-workers", type=_positive_int, default=None,
                        help="Optional fixed DNS gate worker count (default=adaptive)")
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
    parser.add_argument("--keep-dns-rejected-strict-lexical", action="store_true",
                        help="Keep strict-lexical DNS rejected rows as weak holdout candidates")
    parser.add_argument("--keep-fetch-failed-strict-lexical", action="store_true",
                        help="Keep strict-lexical fetch failed/timeout rows as weak holdout candidates")
    parser.add_argument("--failed-fetch-suspected-min", type=_probability_float, default=None,
                        help="Lexical score rescue threshold for Suspected on non-fetched strict-lexical rows")
    parser.add_argument("--failed-fetch-review-min", type=_probability_float, default=None,
                        help="Lexical score rescue threshold for REVIEW_ONLY on non-fetched strict-lexical rows")
    parser.add_argument("--weight-domain", type=_non_negative_float, default=30.0,
                        help="Weight for domain similarity score contribution (default=30)")
    parser.add_argument("--weight-screenshot", type=_non_negative_float, default=20.0,
                        help="Deprecated compatibility no-op. Screenshot/CLIP routing weight is ignored.")
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
                        help="Optional partial-run mode: off, dns, fetch, lexical, score, classify, all (default=off)")
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
    args = parser.parse_args()

    from phishing_pipeline.config import OUTPUT_DIR, RELIABILITY_CONFIG
    from phishing_pipeline.reliability import CheckpointStore, build_run_context

    reliability_metadata = {
        "shortlisting": os.path.abspath(args.shortlisting),
        "whitelist": os.path.abspath(args.whitelist),
        "pipeline_mode": args.pipeline_mode,
        "target_limit": args.target_limit,
        "limit_whitelisted": args.limit,
        "runtime_profile": args.runtime_profile,
    }
    existing_manifest = None
    existing_run_id = None
    if args.resume and not args.force_reprocess:
        existing_manifest = _load_existing_run_manifest(os.path.join(OUTPUT_DIR, "run_manifest.json"))
        if (
            existing_manifest
            and str(existing_manifest.get("status", "")).strip().lower() != "completed"
            and _manifest_matches_inputs(existing_manifest, reliability_metadata)
        ):
            checkpoint_db_path = str(existing_manifest.get("checkpoint_db_path", "") or "")
            if checkpoint_db_path and os.path.exists(checkpoint_db_path):
                existing_run_id = str(existing_manifest.get("run_id", "") or "").strip() or None

    resolved_run_id = args.run_id or existing_run_id
    resuming_existing_run = bool(existing_run_id and resolved_run_id == existing_run_id and args.resume and not args.force_reprocess)
    run_context = build_run_context(
        output_dir=OUTPUT_DIR,
        run_id=resolved_run_id,
        stall_threshold_seconds=args.stall_threshold_seconds,
        watchdog_warning_seconds=int(RELIABILITY_CONFIG.get("watchdog_warning_seconds", 60)),
        export_flush_interval_seconds=int(RELIABILITY_CONFIG.get("export_flush_interval_seconds", 5)),
        export_flush_row_interval=int(RELIABILITY_CONFIG.get("export_flush_row_interval", 50)),
        stage1_failure_policy=args.stage1_failure_policy,
        max_worker_restarts=int(RELIABILITY_CONFIG.get("max_worker_restarts", 2)),
        metadata=reliability_metadata,
    )
    checkpoint_store = CheckpointStore(run_context)
    checkpoint_store.update_manifest(status="running", metadata_json=reliability_metadata)
    logger.info(
        "Reliability run context | run_id=%s | resume=%s | force_reprocess=%s | checkpoint=%s | stage1_failure_policy=%s | stall_threshold_seconds=%d",
        run_context.run_id,
        resuming_existing_run,
        args.force_reprocess,
        run_context.checkpoint_db_path,
        run_context.stage1_failure_policy,
        run_context.stall_threshold_seconds,
    )

    runtime_profile_settings = _resolve_runtime_profile_settings(args.runtime_profile)
    _apply_runtime_profile_env(runtime_profile_settings)

    components = _load_runtime_components()
    final_output = components["FINAL_OUTPUT"]
    close_browser = components["close_browser"]
    run_pipeline = components["run_pipeline"]
    package_results = components["package_results"]
    shortlisting = components["shortlisting"]
    run_hashing_shortlist_async = components["run_hashing_shortlist_async"]
    stage1_http_config = components["STAGE1_HTTP_CONFIG"] or {}
    _apply_stage1_http_runtime_profile(stage1_http_config, runtime_profile_settings)
    effective_dns_max_workers = (
        args.dns_max_workers
        if args.dns_max_workers is not None
        else runtime_profile_settings.get("dns_max_workers")
    )

    if args.high_confidence_threshold < args.medium_confidence_threshold:
        raise ValueError("high-confidence-threshold must be >= medium-confidence-threshold")
    if args.dns_timeout <= 0:
        raise ValueError("dns-timeout must be > 0")
    if (
        args.failed_fetch_suspected_min is not None
        and args.failed_fetch_review_min is not None
        and args.failed_fetch_suspected_min < args.failed_fetch_review_min
    ):
        raise ValueError("failed-fetch-suspected-min must be >= failed-fetch-review-min")
    logger.info(
        "Deprecated CLI compatibility | clip_margin_min=%.3f ignored | weight_screenshot=%.3f ignored",
        args.clip_margin_min,
        args.weight_screenshot,
    )
    logger.info(
        "Runtime profile requested=%s resolved=%s | host={cpu=%s,ram_gb=%.1f,vram_gb=%.1f,platform=%s} | hash_env=%s | stage1_http_overrides=%s | dns_max_workers=%s",
        runtime_profile_settings["requested_profile"],
        runtime_profile_settings["resolved_profile"],
        runtime_profile_settings["resource_info"].get("cpu_cores", "NA"),
        float(runtime_profile_settings["resource_info"].get("ram_gb", 0.0) or 0.0),
        float(runtime_profile_settings["resource_info"].get("vram_gb", 0.0) or 0.0),
        runtime_profile_settings["resource_info"].get("platform", "unknown"),
        runtime_profile_settings.get("env", {}),
        runtime_profile_settings.get("stage1_http", {}),
        effective_dns_max_workers if effective_dns_max_workers is not None else "adaptive",
    )
    logger.info(
        "Effective runtime concurrency | hash={pages=%s,page_concurrency=%s,http_limit=%s,aux_net_limit=%s,active_fetch_floor=%s,dns_gate_min=%s,dns_gate_max=%s} | stage1_http={url=%s,http=%s,dns=%s,rdap=%s,tls=%s}",
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_PAGES", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_PAGE_CONCURRENCY", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_HTTP_LIMIT", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_AUX_NET_LIMIT", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_HASH_ACTIVE_PAGES_FLOOR", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_DNS_GATE_MIN_WORKERS", "NA"),
        runtime_profile_settings.get("env", {}).get("PHISHING_DNS_GATE_MAX_WORKERS", "NA"),
        stage1_http_config.get("concurrency", "NA"),
        stage1_http_config.get("http_concurrency", "NA"),
        stage1_http_config.get("dns_concurrency", "NA"),
        stage1_http_config.get("rdap_concurrency", "NA"),
        stage1_http_config.get("tls_concurrency", "NA"),
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
                os.path.join("output", "checkpoint_records.csv"),
                os.path.join("output", "stage1_lexical_debug.csv"),
                os.path.join("output", "stage1_methods_debug.csv"),
                os.path.join("output", "stage1_deep_analysis_candidates.csv"),
                os.path.join("output", "stage2_model_debug.csv"),
                os.path.join("output", "stage3_classification_debug.csv"),
                os.path.join("output", "parked_page_exclusions.csv"),
            ]
            if args.stage_smoke_test != "classify":
                cleanup_patterns.append(os.path.join("output", "holdout.csv"))
            for pattern in cleanup_patterns:
                for f in glob.glob(pattern):
                    os.remove(f)
                    logger.info("🧹 Removed old output: %s", f)
        
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
            "dns={timeout=%.2f,retries=%d,max_workers=%s} "
            "stage1_http={url_concurrency=%s,http=%s,dns=%s,rdap=%s,tls=%s,max_html_bytes=%s,max_redirects=%s,escalate_total=%s,brand_min=%s,credential_min=%s,low_band_min=%s,hard_trigger_brand_min=%s} "
            "recall_passthroughs={stage1_suspected=%s,dns_rejected_strict_lexical=%s,fetch_failed_strict_lexical=%s} "
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
            args.dns_timeout,
            args.dns_retries,
            effective_dns_max_workers if effective_dns_max_workers is not None else "adaptive",
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
            args.keep_dns_rejected_strict_lexical,
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
            args.shortlist_debug_csv,
        )

        df_out = None

        # Try the new-style orchestration (controller -> comparison -> pipeline)
        if run_hashing_shortlist_async and shortlisting:
            if args.stage_smoke_test == "classify":
                fatal_stage = "classify"
                existing_holdout = os.path.join("output", "holdout.csv")
                if not os.path.exists(existing_holdout):
                    raise FileNotFoundError("stage-smoke-test=classify requires an existing output/holdout.csv")
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
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=effective_dns_max_workers,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_dns_rejected_strict_lexical=args.keep_dns_rejected_strict_lexical,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    failed_fetch_suspected_min=args.failed_fetch_suspected_min,
                    failed_fetch_review_min=args.failed_fetch_review_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
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
                urls = [record["url"] for record in url_records]
                url_sources = {
                    record["url"]: record.get("source_workbooks", [])
                    for record in url_records
                }
                shortlist_weights = {
                    "domain": args.weight_domain,
                    "screenshot": args.weight_screenshot,
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
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=effective_dns_max_workers,
                    weights=shortlist_weights,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                    url_sources=url_sources,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_dns_rejected_strict_lexical=args.keep_dns_rejected_strict_lexical,
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
                )
                
                # Save output to holdout.csv
                out_csv = os.path.join("output", "holdout.csv")
                os.makedirs("output", exist_ok=True)
                holdout_df.to_csv(out_csv, index=False)
                logger.info(f"--- Finished Step 1: Shortlisting Complete ({len(holdout_df)} matched) ---")

                if args.stage_smoke_test in {"dns", "fetch", "lexical", "score"}:
                    logger.info("Stage smoke test '%s' requested. Stopping after Step 1.", args.stage_smoke_test)
                    df_out = holdout_df
                    checkpoint_store.mark_completed()
                    checkpoint_store.export_all()
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
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=effective_dns_max_workers,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_dns_rejected_strict_lexical=args.keep_dns_rejected_strict_lexical,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    failed_fetch_suspected_min=args.failed_fetch_suspected_min,
                    failed_fetch_review_min=args.failed_fetch_review_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
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
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=effective_dns_max_workers,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                    stage1_escalate_total_threshold=args.stage1_escalate_total_threshold,
                    stage1_brand_min=args.stage1_brand_min,
                    stage1_credential_min=args.stage1_credential_min,
                    stage1_low_band_min=args.stage1_low_band_min,
                    stage1_hard_trigger_brand_min=args.stage1_hard_trigger_brand_min,
                    keep_stage1_suspected=args.keep_stage1_suspected,
                    keep_dns_rejected_strict_lexical=args.keep_dns_rejected_strict_lexical,
                    keep_fetch_failed_strict_lexical=args.keep_fetch_failed_strict_lexical,
                    failed_fetch_suspected_min=args.failed_fetch_suspected_min,
                    failed_fetch_review_min=args.failed_fetch_review_min,
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                    resume=args.resume,
                    force_reprocess=args.force_reprocess,
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
        checkpoint_store.mark_completed()
        checkpoint_store.export_all()

    except Exception as exc:
        checkpoint_store.mark_failed(stage=fatal_stage, exc=exc)
        checkpoint_store.export_all()
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
            checkpoint_store.close()
        except Exception as exc:
            logger.warning("Checkpoint store close failed: %s", exc)


if __name__ == "__main__":
    asyncio.run(main())
