import os
import sys

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")

# Columns
DOMAIN_COL   = "Legitimate Domains"
ORG_COL      = "Cooresponding CSE"
 
# Root (go one level up)
ROOT_DIR = os.path.dirname(BASE_DIR)

# Core CSVs
FEATURES_CSV     = os.path.join(BASE_DIR, "blacklist_features.csv")
FEATURES_ENRICH  = os.path.join(BASE_DIR, "features_enriched.csv")
FINAL_OUTPUT     = os.path.join(ROOT_DIR, "output", "output_file.csv")
CHECKPOINT_CSV   = os.path.join(ROOT_DIR, "output", "checkpoints.csv")

# ML Models + Preprocessors
MODELS_DIR           = os.path.join(ROOT_DIR, "models")
MODEL_LABEL_PATH     = os.path.join(MODELS_DIR, "xgb_label_model.joblib")
MODEL_SOURCE_PATH    = os.path.join(MODELS_DIR, "xgb_source_model.joblib")
ENCODER_LABEL_PATH   = os.path.join(MODELS_DIR, "label_encoder_label.joblib")
SOURCE_CLASSES_PATH  = os.path.join(MODELS_DIR, "source_classes.joblib")
FEATURE_COLUMNS_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")
SCALER_PATH          = os.path.join(MODELS_DIR, "scaler.joblib")
IMPUTER_PATH         = os.path.join(MODELS_DIR, "imputer.joblib")

# GeoIP DBs
GEOLITE_DIR  = os.path.join(ROOT_DIR, "data", "geolite")
ASN_DB_PATH  = os.path.join(GEOLITE_DIR, "GeoLite2-ASN.mmdb")
CITY_DB_PATH = os.path.join(GEOLITE_DIR, "GeoLite2-City.mmdb")

# Data directories
WHITELISTS_DIR  = os.path.join(ROOT_DIR, "data", "whitelists")
HOLDOUT_SETS_DIR = os.path.join(ROOT_DIR, "data", "holdout_sets")
OUTPUT_DIR      = os.path.join(ROOT_DIR, "output")
CHECKPOINTS_CSV = os.path.join(OUTPUT_DIR, "checkpoints.csv")
PIPELINE_RUN_RESULTS_CSV = os.path.join(OUTPUT_DIR, "pipeline_run_results.csv")
PIPELINE_STAGE_EVENTS_CSV = os.path.join(OUTPUT_DIR, "pipeline_stage_events.csv")
RUN_MANIFEST_CSV = os.path.join(OUTPUT_DIR, "run_manifest.csv")
HASH_EXPORT_DIR = os.path.join(OUTPUT_DIR, "hash_folder")

# Screenshots & Evidence
SCREENS_DIR  = os.path.join(BASE_DIR, "screens")
APPLICATION_ID = "ISS_NLP"

# Evidence folder format as per PS-02
EVIDENCE_DIR  = os.path.join(BASE_DIR, f"PS-02_{APPLICATION_ID}_Evidences")

# Limits
MAX_VARIANTS = 40
MAX_WORKERS  = 20

# Stage 1 cheap HTTP routing
STAGE1_HTTP_CONFIG = {
    "concurrency": 200,
    "http_concurrency": 200,
    "dns_concurrency": 200,
    "rdap_concurrency": 10,
    "tls_concurrency": 32,
    "stage1_enable_tiered_fast_path": True,
    "stage1_fetch_concurrency_start": 200,
    "stage1_fetch_concurrency_max": 400,
    "stage1_fetch_concurrency_floor": 64,
    "stage1_http_connection_limit": 400,
    "stage1_http_keepalive_limit": 200,
    "stage1_per_host_limit": 4,
    "stage1_cpu_workers": 4,
    "stage1_parse_workers": 4,
    "stage1_enrich_dns_concurrency": 200,
    "stage1_enrich_rdap_concurrency": 10,
    "stage1_enrich_tls_concurrency": 32,
    "stage1_fetch_queue_max": 8000,
    "stage1_cpu_queue_max": 4000,
    "stage1_parse_queue_max": 4000,
    "stage1_score_queue_max": 4000,
    "stage1_enrich_queue_max": 4000,
    "stage1_result_queue_max": 4000,
    "stage1_control_interval_seconds": 2.0,
    "stage1_progress_log_interval_seconds": 10,
    "stage1_target_urls_per_sec": 500,
    "connect_timeout": 3.0,
    "head_timeout": 3.0,
    "get_timeout": 5.0,
    "dns_timeout": 3.0,
    "rdap_timeout": 4.0,
    "tls_timeout": 3.0,
    "max_html_bytes": 32768,
    "max_redirects": 4,
    "escalate_total_threshold": 60,
    "brand_min": 18,
    "credential_min": 18,
    "low_band_min": 20,
    "hard_trigger_brand_min": 10,
}

HASH_STAGE_CONFIG = {
    "hash_pages": 24,
    "hash_page_concurrency": 4,
    "hash_http_limit": 96,
    "hash_aux_net_limit": 48,
    "hash_active_pages_floor": 8,
    "hash_progress_log_interval_seconds": 10,
    "hash_target_urls_per_sec": 24,
}

RAY_RUNTIME_CONFIG = {
    "address": os.getenv("PHISHING_RAY_ADDRESS", "").strip(),
    "local_mode": os.getenv("PHISHING_RAY_LOCAL_MODE", "").strip().lower() in {"1", "true", "yes", "on"},
    "stage0_batch_size": max(64, int(os.getenv("PHISHING_RAY_STAGE0_BATCH_SIZE", os.getenv("PHISHING_LEXICAL_BATCH_SIZE", "512")))),
    "stage0_inflight": max(1, int(os.getenv("PHISHING_RAY_STAGE0_INFLIGHT", "8"))),
    "stage1_fetch_actors": max(1, int(os.getenv("PHISHING_RAY_STAGE1_FETCH_ACTORS", "24"))),
    "stage1_enrich_actors": max(1, int(os.getenv("PHISHING_RAY_STAGE1_ENRICH_ACTORS", "12"))),
    "hash_browser_actors": max(1, int(os.getenv("PHISHING_RAY_HASH_BROWSER_ACTORS", "6"))),
    "hash_tabs_per_actor": max(1, int(os.getenv("PHISHING_RAY_HASH_TABS_PER_ACTOR", os.getenv("PHISHING_HASH_PAGE_CONCURRENCY", "4")))),
    "hash_finalize_batch": max(1, int(os.getenv("PHISHING_RAY_HASH_FINALIZE_BATCH", "16"))),
    "classify_actors": max(1, int(os.getenv("PHISHING_RAY_CLASSIFY_ACTORS", "12"))),
    "classify_inflight": max(1, int(os.getenv("PHISHING_RAY_CLASSIFY_INFLIGHT", "24"))),
    "ocr_actors": max(1, int(os.getenv("PHISHING_RAY_OCR_ACTORS", "1"))),
    "ocr_batch_size": max(1, int(os.getenv("PHISHING_RAY_OCR_BATCH_SIZE", "32"))),
    "ocr_batch_delay_ms": max(1, int(os.getenv("PHISHING_RAY_OCR_BATCH_DELAY_MS", "25"))),
    "stage1_fetch_actor_max_concurrency": max(1, int(os.getenv("PHISHING_RAY_STAGE1_FETCH_ACTOR_MAX_CONCURRENCY", "4"))),
    "stage1_enrich_actor_max_concurrency": max(1, int(os.getenv("PHISHING_RAY_STAGE1_ENRICH_ACTOR_MAX_CONCURRENCY", "4"))),
    "stage1_pending_cap": max(1, int(os.getenv("PHISHING_RAY_STAGE1_PENDING_CAP", "48"))),
    "hash_pending_cap": max(1, int(os.getenv("PHISHING_RAY_HASH_PENDING_CAP", "16"))),
    "stage1_http_connection_cap": max(4, int(os.getenv("PHISHING_RAY_STAGE1_HTTP_CONNECTION_CAP", "64"))),
    "stage1_http_keepalive_cap": max(2, int(os.getenv("PHISHING_RAY_STAGE1_HTTP_KEEPALIVE_CAP", "32"))),
    "prewarm_actors": os.getenv("PHISHING_RAY_PREWARM_ACTORS", "").strip().lower() in {"1", "true", "yes", "on"},
    "prewarm_mode": str(os.getenv("PHISHING_RAY_PREWARM_MODE", "full") or "full").strip().lower(),
    "browser_hardened_flags": os.getenv("PHISHING_RAY_BROWSER_HARDENED_FLAGS", "").strip().lower() in {"1", "true", "yes", "on"},
    "metrics_interval_seconds": max(1.0, float(os.getenv("PHISHING_RAY_METRICS_INTERVAL_SECONDS", "5"))),
    "enable_dynamic_control": str(os.getenv("PHISHING_RAY_ENABLE_DYNAMIC_CONTROL", "true") or "true").strip().lower() in {"1", "true", "yes", "on"},
    "target_cpu_utilization": max(0.1, min(float(os.getenv("PHISHING_RAY_TARGET_CPU_UTILIZATION", "0.82") or "0.82"), 0.98)),
    "cpu_headroom_cores": max(1, int(os.getenv("PHISHING_RAY_CPU_HEADROOM_CORES", "6"))),
}

RAY_ENV_TO_CONFIG_KEY = {
    "PHISHING_RAY_ADDRESS": "address",
    "PHISHING_RAY_LOCAL_MODE": "local_mode",
    "PHISHING_RAY_STAGE0_BATCH_SIZE": "stage0_batch_size",
    "PHISHING_RAY_STAGE0_INFLIGHT": "stage0_inflight",
    "PHISHING_RAY_STAGE1_FETCH_ACTORS": "stage1_fetch_actors",
    "PHISHING_RAY_STAGE1_ENRICH_ACTORS": "stage1_enrich_actors",
    "PHISHING_RAY_HASH_BROWSER_ACTORS": "hash_browser_actors",
    "PHISHING_RAY_HASH_TABS_PER_ACTOR": "hash_tabs_per_actor",
    "PHISHING_RAY_HASH_FINALIZE_BATCH": "hash_finalize_batch",
    "PHISHING_RAY_CLASSIFY_ACTORS": "classify_actors",
    "PHISHING_RAY_CLASSIFY_INFLIGHT": "classify_inflight",
    "PHISHING_RAY_OCR_ACTORS": "ocr_actors",
    "PHISHING_RAY_OCR_BATCH_SIZE": "ocr_batch_size",
    "PHISHING_RAY_OCR_BATCH_DELAY_MS": "ocr_batch_delay_ms",
    "PHISHING_RAY_STAGE1_FETCH_ACTOR_MAX_CONCURRENCY": "stage1_fetch_actor_max_concurrency",
    "PHISHING_RAY_STAGE1_ENRICH_ACTOR_MAX_CONCURRENCY": "stage1_enrich_actor_max_concurrency",
    "PHISHING_RAY_STAGE1_PENDING_CAP": "stage1_pending_cap",
    "PHISHING_RAY_HASH_PENDING_CAP": "hash_pending_cap",
    "PHISHING_RAY_STAGE1_HTTP_CONNECTION_CAP": "stage1_http_connection_cap",
    "PHISHING_RAY_STAGE1_HTTP_KEEPALIVE_CAP": "stage1_http_keepalive_cap",
    "PHISHING_RAY_PREWARM_ACTORS": "prewarm_actors",
    "PHISHING_RAY_PREWARM_MODE": "prewarm_mode",
    "PHISHING_RAY_BROWSER_HARDENED_FLAGS": "browser_hardened_flags",
    "PHISHING_RAY_METRICS_INTERVAL_SECONDS": "metrics_interval_seconds",
    "PHISHING_RAY_ENABLE_DYNAMIC_CONTROL": "enable_dynamic_control",
    "PHISHING_RAY_TARGET_CPU_UTILIZATION": "target_cpu_utilization",
    "PHISHING_RAY_CPU_HEADROOM_CORES": "cpu_headroom_cores",
}

# Debug mode for Ray pipeline stall diagnostics
RAY_DEBUG_MODE = os.getenv("PHISHING_RAY_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


STAGE3_RECALL_RESCUE_CONFIG = {
    "failed_fetch_suspected_min": None,
    "failed_fetch_review_min": None,
}

RELIABILITY_CONFIG = {
    "stall_threshold_seconds": 180,
    "watchdog_warning_seconds": 60,
    "append_flush_interval_seconds": 5,
    "append_flush_row_interval": 2000,
    "snapshot_flush_interval_seconds": 30,
    "snapshot_flush_row_interval": 5000,
    "stage0_progress_log_interval_seconds": 10,
    "stage1_failure_policy": "route_to_dns",
    "max_worker_restarts": 2,
}


def resolve_stage1_http_config(overrides: dict | None = None) -> dict:
    config = dict(STAGE1_HTTP_CONFIG)
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        config[key] = value
    if config.get("stage1_cpu_workers") is None:
        config["stage1_cpu_workers"] = int(config.get("stage1_parse_workers", 4) or 4)
    if config.get("stage1_parse_workers") is None:
        config["stage1_parse_workers"] = int(config.get("stage1_cpu_workers", 4) or 4)
    if config.get("stage1_cpu_queue_max") is None:
        parse_queue_max = int(config.get("stage1_parse_queue_max", 0) or 0)
        score_queue_max = int(config.get("stage1_score_queue_max", 0) or 0)
        config["stage1_cpu_queue_max"] = max(1, parse_queue_max, score_queue_max)
    if config.get("stage1_fetch_concurrency_floor") is None:
        fetch_start = int(config.get("stage1_fetch_concurrency_start", config.get("concurrency", 1)) or 1)
        config["stage1_fetch_concurrency_floor"] = max(1, min(fetch_start, 64))
    return config


def resolve_hash_stage_config(overrides: dict | None = None) -> dict:
    config = dict(HASH_STAGE_CONFIG)
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        config[key] = value
    return config


def _estimate_ray_cpu_budget(config: dict[str, object]) -> tuple[float, float, float]:
    stage1_fetch_actors = max(1, int(config.get("stage1_fetch_actors", 1) or 1))
    stage1_enrich_actors = max(1, int(config.get("stage1_enrich_actors", 1) or 1))
    hash_browser_actors = max(1, int(config.get("hash_browser_actors", 1) or 1))
    classify_actors = max(1, int(config.get("classify_actors", 1) or 1))
    ocr_actors = max(1, int(config.get("ocr_actors", 1) or 1))
    stage1_pending_cap = max(1, int(config.get("stage1_pending_cap", 1) or 1))
    hash_pending_cap = max(1, int(config.get("hash_pending_cap", 1) or 1))
    stage0_inflight = max(1, int(config.get("stage0_inflight", 1) or 1))
    hash_finalize_batch = max(1, int(config.get("hash_finalize_batch", 1) or 1))
    actor_cpu_demand = (
        stage1_fetch_actors * 0.25
        + stage1_enrich_actors * 0.25
        + hash_browser_actors * (1.0 if bool(config.get("server_mode")) else 0.5)
        + classify_actors * 1.0
        + ocr_actors * 1.0
    )
    stage0_task_cpu = 1.0
    light_task_cpu = 0.5
    finalize_task_cpu = 1.0
    estimated_stage1_task_parallelism = min(stage1_pending_cap, stage1_fetch_actors)
    estimated_hash_task_parallelism = min(hash_pending_cap, hash_browser_actors)
    estimated_finalize_parallelism = min(
        2 if bool(config.get("server_mode")) else 1,
        hash_browser_actors,
        hash_finalize_batch,
    )
    worst_case_task_cpus = (
        stage0_inflight * stage0_task_cpu
        + estimated_stage1_task_parallelism * light_task_cpu
        + estimated_hash_task_parallelism * light_task_cpu
        + estimated_finalize_parallelism * finalize_task_cpu
    )
    return actor_cpu_demand, worst_case_task_cpus, actor_cpu_demand + worst_case_task_cpus


def _clamp_ray_budget(config: dict[str, object], *, cpu_cores: int) -> dict[str, object]:
    actor_cpu_target = max(1.0, float(cpu_cores) * 0.60)
    total_cpu_target = max(actor_cpu_target, float(cpu_cores) * 0.85)
    adjustments: list[str] = []
    server_mode = bool(config.get("server_mode"))
    low_memory_mode = bool(config.get("low_memory_mode"))
    very_low_memory_mode = bool(config.get("very_low_memory_mode"))

    min_stage0_inflight = 1
    min_stage1_fetch_actors = 1 if very_low_memory_mode else 2 if low_memory_mode else 4
    min_stage1_enrich_actors = 1
    min_hash_browser_actors = 1
    min_classify_actors = 1 if low_memory_mode else 2
    min_stage1_pending_cap = 24 if server_mode and cpu_cores >= 32 else min_stage1_fetch_actors
    min_hash_pending_cap = 4 if server_mode and cpu_cores >= 32 else min_hash_browser_actors
    min_classify_inflight = max(
        1,
        min(
            int(config.get("classify_inflight", 1) or 1),
            8 if server_mode and cpu_cores >= 32 and not low_memory_mode else 1,
        ),
    )

    def _reduce_value(key: str, *, minimum: int, step: int = 1, reason: str) -> bool:
        current = int(config.get(key, minimum) or minimum)
        updated = max(minimum, current - step)
        if updated == current:
            return False
        config[key] = updated
        adjustments.append(f"{key}:{current}->{updated} ({reason})")
        return True

    for _ in range(256):
        actor_cpu_demand, worst_case_task_cpus, total_demand = _estimate_ray_cpu_budget(config)
        if actor_cpu_demand <= actor_cpu_target and total_demand <= total_cpu_target:
            break

        changed = False
        if total_demand > total_cpu_target:
            changed = _reduce_value(
                "classify_inflight",
                minimum=min_classify_inflight,
                step=4,
                reason="total_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "stage1_pending_cap",
                minimum=min_stage1_pending_cap,
                step=8,
                reason="total_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "hash_pending_cap",
                minimum=min_hash_pending_cap,
                step=4,
                reason="total_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "stage0_inflight",
                minimum=min_stage0_inflight,
                step=1,
                reason="total_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "stage1_fetch_actor_max_concurrency",
                minimum=1,
                step=1,
                reason="total_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "stage1_enrich_actor_max_concurrency",
                minimum=1,
                step=1,
                reason="total_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "hash_tabs_per_actor",
                minimum=1,
                step=1,
                reason="total_cpu_budget",
            ) or changed

        actor_cpu_demand, worst_case_task_cpus, total_demand = _estimate_ray_cpu_budget(config)
        if actor_cpu_demand > actor_cpu_target or total_demand > total_cpu_target:
            changed = _reduce_value(
                "stage1_fetch_actors",
                minimum=min_stage1_fetch_actors,
                step=1,
                reason="actor_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "stage1_enrich_actors",
                minimum=min_stage1_enrich_actors,
                step=1,
                reason="actor_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "hash_browser_actors",
                minimum=min_hash_browser_actors,
                step=1,
                reason="actor_cpu_budget",
            ) or changed
            changed = _reduce_value(
                "classify_actors",
                minimum=min_classify_actors,
                step=1,
                reason="actor_cpu_budget",
            ) or changed

        if not changed:
            break

    config["classify_inflight"] = max(
        min_classify_inflight,
        min(
            int(config.get("classify_inflight", min_classify_inflight) or min_classify_inflight),
            max(1, int(config.get("classify_actors", 1) or 1) * 2),
        ),
    )
    config["stage1_pending_cap"] = max(
        max(int(config.get("stage1_fetch_actors", 1) or 1), min_stage1_pending_cap),
        int(config.get("stage1_pending_cap", min_stage1_pending_cap) or min_stage1_pending_cap),
    )
    config["hash_pending_cap"] = max(
        max(int(config.get("hash_browser_actors", 1) or 1), min_hash_pending_cap),
        int(config.get("hash_pending_cap", min_hash_pending_cap) or min_hash_pending_cap),
    )
    actor_cpu_demand, worst_case_task_cpus, total_demand = _estimate_ray_cpu_budget(config)
    return {
        "actor_cpu_target": round(actor_cpu_target, 2),
        "total_cpu_target": round(total_cpu_target, 2),
        "actor_cpu_demand": round(actor_cpu_demand, 2),
        "worst_case_task_cpus": round(worst_case_task_cpus, 2),
        "total_demand": round(total_demand, 2),
        "clamped": bool(adjustments),
        "adjustments": adjustments,
    }


def resolve_ray_runtime_config(overrides: dict | None = None) -> dict:
    cpu_cores = os.cpu_count() or 4
    hash_pages = max(1, int(os.getenv("PHISHING_HASH_PAGES", HASH_STAGE_CONFIG["hash_pages"])))
    local_mode_env = os.getenv("PHISHING_RAY_LOCAL_MODE", "").strip().lower()
    explicit_local_mode = (
        local_mode_env in {"1", "true", "yes", "on"}
        if local_mode_env
        else None
    )
    total_ram_gb = 0.0
    available_ram_gb = 0.0
    if psutil is not None:
        try:
            vm = psutil.virtual_memory()
            total_ram_gb = float(vm.total / (1024 ** 3))
            available_ram_gb = float(vm.available / (1024 ** 3))
        except Exception:
            total_ram_gb = 0.0
            available_ram_gb = 0.0
    config = dict(RAY_RUNTIME_CONFIG)
    overrides = dict(overrides or {})
    explicit_keys = {key for key, value in overrides.items() if value is not None}
    explicit_env_keys = {
        config_key
        for env_name, config_key in RAY_ENV_TO_CONFIG_KEY.items()
        if os.getenv(env_name) is not None
    }
    for key, value in overrides.items():
        if value is None:
            continue
        config[key] = value

    low_memory_mode = bool((total_ram_gb and total_ram_gb <= 16.5) or (available_ram_gb and available_ram_gb < 4.0))
    very_low_memory_mode = bool((total_ram_gb and total_ram_gb <= 8.5) or (available_ram_gb and available_ram_gb < 2.5))
    critical_memory_mode = bool(available_ram_gb and available_ram_gb < 1.25)
    server_mode = bool(cpu_cores >= 32 and total_ram_gb >= 128.0 and not critical_memory_mode)

    server_defaults = {
        "stage0_batch_size": 1024,
        "stage0_inflight": 4,
        "stage1_fetch_actors": 12,
        "stage1_enrich_actors": 6,
        "hash_browser_actors": 8,
        "hash_tabs_per_actor": 2,
        "hash_finalize_batch": 32,
        "classify_actors": 8,
        "classify_inflight": 8,
        "ocr_actors": 1,
        "ocr_batch_size": 32,
        "ocr_batch_delay_ms": 25,
        "stage1_fetch_actor_max_concurrency": 4,
        "stage1_enrich_actor_max_concurrency": 2,
        "stage1_pending_cap": 48,
        "hash_pending_cap": 16,
        "stage1_http_connection_cap": 192,
        "stage1_http_keepalive_cap": 96,
        "prewarm_actors": True,
        "prewarm_mode": "staged",
        "enable_dynamic_control": True,
        "target_cpu_utilization": 0.82,
        "cpu_headroom_cores": 6,
    }
    if server_mode:
        for key, value in server_defaults.items():
            if key not in explicit_keys and key not in explicit_env_keys:
                config[key] = value

    if very_low_memory_mode:
        fetch_actor_cap = 1
        enrich_actor_cap = 1
        browser_actor_cap = 1
        classify_actor_cap = 1
        stage0_inflight_cap = 1
        finalize_batch_cap = 2
        stage0_batch_size_cap = 64
        tabs_per_actor_cap = 1
        fetch_actor_concurrency_cap = 1
        enrich_actor_concurrency_cap = 1
        classify_inflight_cap = 2
        stage1_pending_cap = 8   # was 4 — too low, starves stage1 pipeline
        hash_pending_cap = 4     # was 2 — too low, single browser actor needs work queued ahead
        stage1_connection_cap = 8
        stage1_keepalive_cap = 4
    elif server_mode:
        fetch_actor_cap = max(24, cpu_cores)
        enrich_actor_cap = max(12, max(1, cpu_cores // 2))
        browser_actor_cap = max(12, max(1, cpu_cores // 4))
        classify_actor_cap = max(16, max(1, cpu_cores // 2))
        stage0_inflight_cap = max(16, max(1, cpu_cores // 2))
        finalize_batch_cap = 128
        stage0_batch_size_cap = 4096
        tabs_per_actor_cap = 4
        fetch_actor_concurrency_cap = 8
        enrich_actor_concurrency_cap = 6
        classify_inflight_cap = max(64, cpu_cores * 4)
        stage1_pending_cap = max(384, fetch_actor_cap * fetch_actor_concurrency_cap * 2)
        hash_pending_cap = max(96, browser_actor_cap * tabs_per_actor_cap * 2)
        stage1_connection_cap = max(1536, fetch_actor_cap * 64)
        stage1_keepalive_cap = max(768, fetch_actor_cap * 32)
    elif low_memory_mode:
        fetch_actor_cap = 4
        enrich_actor_cap = 2
        browser_actor_cap = 2
        classify_actor_cap = 2
        stage0_inflight_cap = 2
        finalize_batch_cap = 8
        stage0_batch_size_cap = 128
        tabs_per_actor_cap = 2
        fetch_actor_concurrency_cap = 2
        enrich_actor_concurrency_cap = 2
        classify_inflight_cap = 4
        stage1_pending_cap = 12
        hash_pending_cap = 6
        stage1_connection_cap = 24
        stage1_keepalive_cap = 12
    else:
        fetch_actor_cap = max(4, cpu_cores * 2)
        enrich_actor_cap = max(2, cpu_cores)
        browser_actor_cap = max(1, cpu_cores // 3)
        classify_actor_cap = max(2, cpu_cores)
        stage0_inflight_cap = 8
        finalize_batch_cap = 16
        stage0_batch_size_cap = 512
        tabs_per_actor_cap = max(1, min(4, cpu_cores // 2))
        fetch_actor_concurrency_cap = 4
        enrich_actor_concurrency_cap = 4
        classify_inflight_cap = max(8, min(64, cpu_cores * 4))
        stage1_pending_cap = max(16, cpu_cores * 6)
        hash_pending_cap = max(8, cpu_cores * 2)
        stage1_connection_cap = 64
        stage1_keepalive_cap = 32

    if critical_memory_mode:
        fetch_actor_cap = min(fetch_actor_cap, 1)
        enrich_actor_cap = min(enrich_actor_cap, 1)
        browser_actor_cap = min(browser_actor_cap, 1)
        classify_actor_cap = min(classify_actor_cap, 1)
        stage0_inflight_cap = min(stage0_inflight_cap, 1)
        finalize_batch_cap = min(finalize_batch_cap, 2)
        stage0_batch_size_cap = min(stage0_batch_size_cap, 64)
        tabs_per_actor_cap = min(tabs_per_actor_cap, 1)
        fetch_actor_concurrency_cap = min(fetch_actor_concurrency_cap, 1)
        enrich_actor_concurrency_cap = min(enrich_actor_concurrency_cap, 1)
        classify_inflight_cap = min(classify_inflight_cap, 1)
        # Pending caps are lightweight queue depth limits (dict refs only), not
        # heavy memory allocations.  Keep enough headroom so the single actor
        # always has work queued and the pipeline doesn't stall.
        stage1_pending_cap = min(stage1_pending_cap, 6)
        hash_pending_cap = min(hash_pending_cap, 3)
        stage1_connection_cap = min(stage1_connection_cap, 6)
        stage1_keepalive_cap = min(stage1_keepalive_cap, 3)

    min_stage1_fetch_actors = 1 if very_low_memory_mode else 2 if low_memory_mode else 4
    min_stage1_enrich_actors = 1
    min_classify_actors = 1 if low_memory_mode else 2
    min_stage0_inflight = 1
    tabs_per_actor = max(
        1,
        min(
            int(config.get("hash_tabs_per_actor", RAY_RUNTIME_CONFIG["hash_tabs_per_actor"]) or 1),
            tabs_per_actor_cap,
        ),
    )
    address = str(config.get("address", "") or "").strip()
    del address
    local_mode = explicit_local_mode if explicit_local_mode is not None else False

    stage1_fetch_actors = max(
        min_stage1_fetch_actors,
        min(int(config.get("stage1_fetch_actors", 24) or 24), fetch_actor_cap),
    )
    stage1_enrich_actors = max(
        min_stage1_enrich_actors,
        min(int(config.get("stage1_enrich_actors", 12) or 12), enrich_actor_cap),
    )
    hash_browser_actors = max(
        1,
        min(
            int(config.get("hash_browser_actors", max(1, (hash_pages + tabs_per_actor - 1) // tabs_per_actor)) or 1),
            browser_actor_cap,
        ),
    )
    classify_actors = max(
        min_classify_actors,
        min(int(config.get("classify_actors", 12) or 12), classify_actor_cap),
    )
    fetch_actor_max_concurrency = max(
        1,
        min(
            int(config.get("stage1_fetch_actor_max_concurrency", RAY_RUNTIME_CONFIG["stage1_fetch_actor_max_concurrency"]) or 1),
            fetch_actor_concurrency_cap,
        ),
    )
    enrich_actor_max_concurrency = max(
        1,
        min(
            int(config.get("stage1_enrich_actor_max_concurrency", RAY_RUNTIME_CONFIG["stage1_enrich_actor_max_concurrency"]) or 1),
            enrich_actor_concurrency_cap,
        ),
    )
    default_classify_inflight = max(1, classify_actors * (4 if server_mode else 2))
    default_stage1_pending_cap = max(1, stage1_fetch_actors * fetch_actor_max_concurrency * (2 if server_mode else 1))
    default_hash_pending_cap = max(1, hash_browser_actors * tabs_per_actor * 2)
    default_stage1_connection_cap = 1536 if server_mode else int(config.get("stage1_http_connection_cap", stage1_connection_cap) or stage1_connection_cap)
    default_stage1_keepalive_cap = 768 if server_mode else int(config.get("stage1_http_keepalive_cap", stage1_keepalive_cap) or stage1_keepalive_cap)

    config.update(
        {
            "stage0_batch_size": max(64, min(int(config.get("stage0_batch_size", 512) or 512), stage0_batch_size_cap)),
            "stage0_inflight": max(min_stage0_inflight, min(int(config.get("stage0_inflight", 8) or 8), stage0_inflight_cap)),
            "stage1_fetch_actors": stage1_fetch_actors,
            "stage1_enrich_actors": stage1_enrich_actors,
            "hash_tabs_per_actor": tabs_per_actor,
            "hash_browser_actors": hash_browser_actors,
            "hash_finalize_batch": max(1, min(int(config.get("hash_finalize_batch", 16) or 16), finalize_batch_cap)),
            "classify_actors": classify_actors,
            "classify_inflight": max(1, min(int(config.get("classify_inflight", default_classify_inflight) or 1), classify_inflight_cap)),
            "ocr_actors": max(1, int(config.get("ocr_actors", 1) or 1)),
            "ocr_batch_size": max(1, int(config.get("ocr_batch_size", RAY_RUNTIME_CONFIG["ocr_batch_size"]) or 1)),
            "ocr_batch_delay_ms": max(1, int(config.get("ocr_batch_delay_ms", RAY_RUNTIME_CONFIG["ocr_batch_delay_ms"]) or 1)),
            "metrics_interval_seconds": max(1.0, float(config.get("metrics_interval_seconds", 5.0) or 5.0)),
            "stage1_fetch_actor_max_concurrency": fetch_actor_max_concurrency,
            "stage1_enrich_actor_max_concurrency": enrich_actor_max_concurrency,
            "stage1_pending_cap": max(1, min(int(config.get("stage1_pending_cap", default_stage1_pending_cap) or 1), stage1_pending_cap)),
            "hash_pending_cap": max(1, min(int(config.get("hash_pending_cap", default_hash_pending_cap) or 1), hash_pending_cap)),
            "stage1_http_connection_cap": max(4, min(int(config.get("stage1_http_connection_cap", default_stage1_connection_cap) or 4), stage1_connection_cap)),
            "stage1_http_keepalive_cap": max(2, min(int(config.get("stage1_http_keepalive_cap", default_stage1_keepalive_cap) or 2), stage1_keepalive_cap)),
            "prewarm_mode": str(config.get("prewarm_mode", "staged" if server_mode and not low_memory_mode else "full") or "full").strip().lower(),
            "prewarm_actors": bool(config.get("prewarm_actors", server_mode and not low_memory_mode)),
            "local_mode": bool(local_mode),
            "low_memory_mode": bool(low_memory_mode),
            "very_low_memory_mode": bool(very_low_memory_mode),
            "critical_memory_mode": bool(critical_memory_mode),
            "server_mode": bool(server_mode),
            "detected_total_ram_gb": round(total_ram_gb, 2),
            "detected_available_ram_gb": round(available_ram_gb, 2),
            "debug_mode": bool(RAY_DEBUG_MODE),
            "enable_dynamic_control": bool(config.get("enable_dynamic_control", True)),
            "target_cpu_utilization": max(0.1, min(float(config.get("target_cpu_utilization", 0.82) or 0.82), 0.98)),
            "cpu_headroom_cores": max(1, int(config.get("cpu_headroom_cores", 6) or 6)),
        }
    )
    if str(config.get("prewarm_mode", "full") or "full").strip().lower() not in {"off", "staged", "full"}:
        config["prewarm_mode"] = "full"
    if str(config.get("prewarm_mode", "full") or "full").strip().lower() == "off":
        config["prewarm_actors"] = False
    elif not bool(config.get("prewarm_actors", False)):
        config["prewarm_mode"] = "off"

    budget_info = _clamp_ray_budget(config, cpu_cores=cpu_cores)
    config["actor_cpu_budget"] = float(budget_info["actor_cpu_target"])
    config["planned_total_cpu_budget"] = float(budget_info["total_cpu_target"])
    config["actor_cpu_demand"] = float(budget_info["actor_cpu_demand"])
    config["worst_case_task_cpus"] = float(budget_info["worst_case_task_cpus"])
    config["total_cpu_demand"] = float(budget_info["total_demand"])
    config["budget_clamped"] = bool(budget_info["clamped"])
    config["budget_adjustments"] = list(budget_info["adjustments"])

    # --- Resource budget validation ---
    import logging as _cfg_logging
    _cfg_logger = _cfg_logging.getLogger(__name__)
    actor_cpu_demand = float(config.get("actor_cpu_demand", 0.0) or 0.0)
    worst_case_task_cpus = float(config.get("worst_case_task_cpus", 0.0) or 0.0)
    total_demand = float(config.get("total_cpu_demand", 0.0) or 0.0)
    _cfg_logger.info(
        "Ray resource budget | cpu_cores=%d | actor_cpu_demand=%.1f/%.1f | worst_case_task_cpus=%.1f | total_demand=%.1f/%.1f | headroom=%.1f | clamped=%s",
        cpu_cores,
        actor_cpu_demand,
        float(config.get("actor_cpu_budget", 0.0) or 0.0),
        worst_case_task_cpus,
        total_demand,
        float(config.get("planned_total_cpu_budget", 0.0) or 0.0),
        cpu_cores - total_demand,
        bool(config.get("budget_clamped", False)),
    )
    if bool(config.get("budget_clamped", False)):
        _cfg_logger.warning(
            "Ray runtime clamp applied | adjustments=%s",
            ", ".join(str(item) for item in list(config.get("budget_adjustments") or [])),
        )

    return config

STAGE1_SCORE_WEIGHTS = {
    "brand": {
        "title": 24,
        "meta": 8,
        "body": 4,
        "submit": 12,
        "favicon": 4,
        "final_domain": 4,
        "redirect_alias": 4,
    },
    "credential": {
        "password": 18,
        "login_form": 8,
        "auth_terms": 4,
        "submit_auth": 4,
        "action_mismatch": 16,
        "multi_input": 2,
    },
    "infra": {
        "age_le_30d": 10,
        "age_le_90d": 5,
        "suspicious_provider": 6,
        "cert_suspect": 3,
        "redirect_count_ge_2": 3,
    },
    "evasion": {
        "meta_refresh": 6,
        "js_redirect": 6,
        "iframe": 4,
        "image_heavy_low_text": 6,
        "final_domain_changed": 4,
    },
}

STAGE1_AUTH_TERMS = (
    "login",
    "log in",
    "signin",
    "sign in",
    "auth",
    "authenticate",
    "verification",
    "verify",
    "account",
    "reset",
    "portal",
    "secure",
    "password",
    "otp",
)

STAGE1_SUSPICIOUS_PROVIDER_TOKENS = {
    "namecheap",
    "contabo",
    "digitalocean",
    "ovh",
    "vultr",
    "hetzner",
    "hostinger",
    "reg.ru",
    "shinjiru",
    "pq hosting",
}

STAGE1_SUSPICIOUS_CERT_ISSUER_TOKENS = {
    "self signed",
    "local",
    "temporary",
    "default",
    "localhost",
}
