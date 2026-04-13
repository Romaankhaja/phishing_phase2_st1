import copy
import os
import sys
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

_LAST_RAY_CLAMP_LOG_SIGNATURE: str = ""

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

PATHS_CONFIG = {
    "base_dir": BASE_DIR,
    "uploads_dir": UPLOADS_DIR,
    "root_dir": ROOT_DIR,
    "features_csv": FEATURES_CSV,
    "features_enrich_csv": FEATURES_ENRICH,
    "final_output_csv": FINAL_OUTPUT,
    "checkpoint_csv": CHECKPOINT_CSV,
    "models_dir": MODELS_DIR,
    "model_label_path": MODEL_LABEL_PATH,
    "model_source_path": MODEL_SOURCE_PATH,
    "encoder_label_path": ENCODER_LABEL_PATH,
    "source_classes_path": SOURCE_CLASSES_PATH,
    "feature_columns_path": FEATURE_COLUMNS_PATH,
    "scaler_path": SCALER_PATH,
    "imputer_path": IMPUTER_PATH,
    "geolite_dir": GEOLITE_DIR,
    "asn_db_path": ASN_DB_PATH,
    "city_db_path": CITY_DB_PATH,
    "whitelists_dir": WHITELISTS_DIR,
    "holdout_sets_dir": HOLDOUT_SETS_DIR,
    "output_dir": OUTPUT_DIR,
    "checkpoints_csv": CHECKPOINTS_CSV,
    "pipeline_run_results_csv": PIPELINE_RUN_RESULTS_CSV,
    "pipeline_stage_events_csv": PIPELINE_STAGE_EVENTS_CSV,
    "run_manifest_csv": RUN_MANIFEST_CSV,
    "hash_export_dir": HASH_EXPORT_DIR,
    "screens_dir": SCREENS_DIR,
    "application_id": APPLICATION_ID,
    "evidence_dir": EVIDENCE_DIR,
}

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

def _read_live_ray_runtime_env_config() -> dict[str, object]:
    return {
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


RAY_RUNTIME_CONFIG = _read_live_ray_runtime_env_config()

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
    # Stall prevention parameters
    "stall_timeout_seconds": 120,           # warn if no progress for this many seconds
    "stall_emergency_seconds": 300,         # emergency drain if no progress for this many seconds
    "actor_health_check_interval": 30,      # seconds between actor liveness pings
    "checkpoint_batch_size": 100,           # batch this many checkpoint writes before flush
    "checkpoint_batch_interval_ms": 2000,   # flush checkpoint batch after this many ms
}

PIPELINE_STAGE_CONFIG = {
    "stage0": {
        "lexical_workers": 12,
        "batch_size": 512,
        "inflight_batches": 8,
        "execution_mode": "streaming-concurrent",
        "progress_log_interval_seconds": 10,
        "adaptive_downshift": True,
    },
    "stage1_http": copy.deepcopy(STAGE1_HTTP_CONFIG),
    "hash": copy.deepcopy(HASH_STAGE_CONFIG),
    "classify": {
        "failed_fetch_suspected_min": None,
        "failed_fetch_review_min": None,
        "ocr_batch_size": 32,
        "ocr_batch_delay_ms": 25,
    },
    "ray": copy.deepcopy(RAY_RUNTIME_CONFIG),
    "reliability": copy.deepcopy(RELIABILITY_CONFIG),
}

RUNTIME_PROFILE_NAMES = (
    "auto",
    "default",
    "cpu-safe",
    "cpu-recall",
    "cpu-fast",
    "server-balanced",
    "server-throughput",
)

RUNTIME_PROFILE_CONFIG: dict[str, dict[str, Any]] = {
    "cpu-safe": {
        "env": {
            "PHISHING_HASH_PAGES": 16,
            "PHISHING_HASH_PAGE_CONCURRENCY": 4,
            "PHISHING_HASH_HTTP_LIMIT": 64,
            "PHISHING_HASH_AUX_NET_LIMIT": 24,
            "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 6,
            "PHISHING_LEXICAL_WORKERS": 8,
            "PHISHING_LEXICAL_BATCH_SIZE": 256,
            "PHISHING_LEXICAL_INFLIGHT_BATCHES": 8,
            "PHISHING_SHORTLIST_EXECUTION_MODE": "legacy-batch",
            "PHISHING_HASH_PROGRESS_LOG_INTERVAL_SECONDS": 10,
            "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
        },
        "stage1_http": {
            "concurrency": 96,
            "http_concurrency": 96,
            "dns_concurrency": 96,
            "rdap_concurrency": 4,
            "tls_concurrency": 16,
            "stage1_fetch_concurrency_start": 96,
            "stage1_fetch_concurrency_max": 192,
            "stage1_fetch_concurrency_floor": 32,
            "stage1_http_connection_limit": 192,
            "stage1_http_keepalive_limit": 96,
            "stage1_per_host_limit": 4,
            "stage1_cpu_workers": 4,
            "stage1_parse_workers": 4,
            "stage1_enrich_dns_concurrency": 96,
            "stage1_enrich_rdap_concurrency": 4,
            "stage1_enrich_tls_concurrency": 16,
            "stage1_fetch_queue_max": 4000,
            "stage1_cpu_queue_max": 2000,
            "stage1_parse_queue_max": 2000,
            "stage1_score_queue_max": 2000,
            "stage1_enrich_queue_max": 2000,
            "stage1_result_queue_max": 2000,
            "stage1_control_interval_seconds": 2.0,
        },
        "reliability": {},
    },
    "server-balanced": {
        "env": {
            "PHISHING_HASH_PAGES": 48,
            "PHISHING_HASH_PAGE_CONCURRENCY": 3,
            "PHISHING_HASH_HTTP_LIMIT": 384,
            "PHISHING_HASH_AUX_NET_LIMIT": 192,
            "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 12,
            "PHISHING_LEXICAL_WORKERS": 16,
            "PHISHING_LEXICAL_BATCH_SIZE": 1024,
            "PHISHING_LEXICAL_INFLIGHT_BATCHES": 8,
            "PHISHING_SHORTLIST_EXECUTION_MODE": "streaming-concurrent",
            "PHISHING_HASH_PROGRESS_LOG_INTERVAL_SECONDS": 10,
            "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
            "PHISHING_RAY_STAGE0_BATCH_SIZE": 1024,
            "PHISHING_RAY_STAGE0_INFLIGHT": 8,
            "PHISHING_RAY_STAGE1_FETCH_ACTORS": 24,
            "PHISHING_RAY_STAGE1_ENRICH_ACTORS": 12,
            "PHISHING_RAY_HASH_BROWSER_ACTORS": 16,
            "PHISHING_RAY_HASH_TABS_PER_ACTOR": 3,
            "PHISHING_RAY_HASH_FINALIZE_BATCH": 64,
            "PHISHING_RAY_CLASSIFY_ACTORS": 16,
            "PHISHING_RAY_CLASSIFY_INFLIGHT": 48,
            "PHISHING_RAY_OCR_ACTORS": 2,
            "PHISHING_RAY_STAGE1_FETCH_ACTOR_MAX_CONCURRENCY": 8,
            "PHISHING_RAY_STAGE1_ENRICH_ACTOR_MAX_CONCURRENCY": 4,
            "PHISHING_RAY_STAGE1_PENDING_CAP": 192,
            "PHISHING_RAY_HASH_PENDING_CAP": 96,
            "PHISHING_RAY_STAGE1_HTTP_CONNECTION_CAP": 768,
            "PHISHING_RAY_STAGE1_HTTP_KEEPALIVE_CAP": 384,
            "PHISHING_RAY_OCR_BATCH_SIZE": 32,
            "PHISHING_RAY_OCR_BATCH_DELAY_MS": 25,
            "PHISHING_RAY_PREWARM_MODE": "staged",
            "PHISHING_RAY_PREWARM_ACTORS": "true",
            "PHISHING_RAY_ENABLE_DYNAMIC_CONTROL": "true",
            "PHISHING_RAY_TARGET_CPU_UTILIZATION": "0.92",
            "PHISHING_RAY_CPU_HEADROOM_CORES": "4",
        },
        "stage1_http": {
            "concurrency": 192,
            "http_concurrency": 768,
            "dns_concurrency": 384,
            "rdap_concurrency": 24,
            "tls_concurrency": 96,
            "stage1_target_urls_per_sec": 2000,
            "stage1_fetch_concurrency_start": 192,
            "stage1_fetch_concurrency_max": 768,
            "stage1_fetch_concurrency_floor": 48,
            "stage1_http_connection_limit": 768,
            "stage1_http_keepalive_limit": 384,
            "stage1_per_host_limit": 4,
            "stage1_cpu_workers": 16,
            "stage1_parse_workers": 16,
            "stage1_enrich_dns_concurrency": 384,
            "stage1_enrich_rdap_concurrency": 24,
            "stage1_enrich_tls_concurrency": 96,
            "stage1_fetch_queue_max": 8000,
            "stage1_cpu_queue_max": 4000,
            "stage1_parse_queue_max": 4000,
            "stage1_score_queue_max": 4000,
            "stage1_enrich_queue_max": 4000,
            "stage1_result_queue_max": 8000,
            "stage1_control_interval_seconds": 2.0,
        },
        "reliability": {
            "append_flush_interval_seconds": 10,
            "append_flush_row_interval": 10000,
            "snapshot_flush_interval_seconds": 60,
            "snapshot_flush_row_interval": 50000,
        },
    },
    "server-throughput": {
        "env": {
            "PHISHING_HASH_PAGES": 64,
            "PHISHING_HASH_PAGE_CONCURRENCY": 4,
            "PHISHING_HASH_HTTP_LIMIT": 512,
            "PHISHING_HASH_AUX_NET_LIMIT": 256,
            "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 20,
            "PHISHING_LEXICAL_WORKERS": 32,
            "PHISHING_LEXICAL_BATCH_SIZE": 2048,
            "PHISHING_LEXICAL_INFLIGHT_BATCHES": 16,
            "PHISHING_SHORTLIST_EXECUTION_MODE": "streaming-concurrent",
            "PHISHING_HASH_PROGRESS_LOG_INTERVAL_SECONDS": 10,
            "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
            "PHISHING_RAY_STAGE0_BATCH_SIZE": 2048,
            "PHISHING_RAY_STAGE0_INFLIGHT": 16,
            "PHISHING_RAY_STAGE1_FETCH_ACTORS": 32,
            "PHISHING_RAY_STAGE1_ENRICH_ACTORS": 16,
            "PHISHING_RAY_HASH_BROWSER_ACTORS": 20,
            "PHISHING_RAY_HASH_TABS_PER_ACTOR": 4,
            "PHISHING_RAY_HASH_FINALIZE_BATCH": 64,
            "PHISHING_RAY_CLASSIFY_ACTORS": 20,
            "PHISHING_RAY_CLASSIFY_INFLIGHT": 80,
            "PHISHING_RAY_OCR_ACTORS": 2,
            "PHISHING_RAY_STAGE1_FETCH_ACTOR_MAX_CONCURRENCY": 8,
            "PHISHING_RAY_STAGE1_ENRICH_ACTOR_MAX_CONCURRENCY": 6,
            "PHISHING_RAY_STAGE1_PENDING_CAP": 512,
            "PHISHING_RAY_HASH_PENDING_CAP": 160,
            "PHISHING_RAY_STAGE1_HTTP_CONNECTION_CAP": 2048,
            "PHISHING_RAY_STAGE1_HTTP_KEEPALIVE_CAP": 1024,
            "PHISHING_RAY_OCR_BATCH_SIZE": 32,
            "PHISHING_RAY_OCR_BATCH_DELAY_MS": 25,
            "PHISHING_RAY_PREWARM_ACTORS": "true",
            "PHISHING_RAY_TARGET_CPU_UTILIZATION": "0.95",
            "PHISHING_RAY_CPU_HEADROOM_CORES": "3",
        },
        "stage1_http": {
            "concurrency": 512,
            "http_concurrency": 2048,
            "dns_concurrency": 768,
            "rdap_concurrency": 48,
            "tls_concurrency": 192,
            "stage1_target_urls_per_sec": 4000,
            "stage1_fetch_concurrency_start": 512,
            "stage1_fetch_concurrency_max": 2048,
            "stage1_fetch_concurrency_floor": 128,
            "stage1_http_connection_limit": 2048,
            "stage1_http_keepalive_limit": 1024,
            "stage1_per_host_limit": 4,
            "stage1_cpu_workers": 32,
            "stage1_parse_workers": 32,
            "stage1_enrich_dns_concurrency": 768,
            "stage1_enrich_rdap_concurrency": 48,
            "stage1_enrich_tls_concurrency": 192,
            "stage1_fetch_queue_max": 16000,
            "stage1_cpu_queue_max": 10000,
            "stage1_parse_queue_max": 10000,
            "stage1_score_queue_max": 8000,
            "stage1_enrich_queue_max": 10000,
            "stage1_result_queue_max": 16000,
            "stage1_control_interval_seconds": 2.0,
        },
        "reliability": {
            "append_flush_interval_seconds": 10,
            "append_flush_row_interval": 10000,
            "snapshot_flush_interval_seconds": 60,
            "snapshot_flush_row_interval": 50000,
        },
    },
    "cpu-fast": {
        "env": {
            "PHISHING_HASH_PAGES": 24,
            "PHISHING_HASH_PAGE_CONCURRENCY": 4,
            "PHISHING_HASH_HTTP_LIMIT": 96,
            "PHISHING_HASH_AUX_NET_LIMIT": 40,
            "PHISHING_HASH_ACTIVE_PAGES_FLOOR": 8,
            "PHISHING_LEXICAL_WORKERS": 12,
            "PHISHING_LEXICAL_BATCH_SIZE": 512,
            "PHISHING_LEXICAL_INFLIGHT_BATCHES": 12,
            "PHISHING_SHORTLIST_EXECUTION_MODE": "streaming-concurrent",
            "PHISHING_HASH_PROGRESS_LOG_INTERVAL_SECONDS": 10,
            "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": "true",
        },
        "stage1_http": {
            "concurrency": 144,
            "http_concurrency": 144,
            "dns_concurrency": 144,
            "rdap_concurrency": 8,
            "tls_concurrency": 24,
            "stage1_fetch_concurrency_start": 192,
            "stage1_fetch_concurrency_max": 384,
            "stage1_fetch_concurrency_floor": 48,
            "stage1_http_connection_limit": 384,
            "stage1_http_keepalive_limit": 128,
            "stage1_per_host_limit": 4,
            "stage1_cpu_workers": 6,
            "stage1_parse_workers": 6,
            "stage1_enrich_dns_concurrency": 144,
            "stage1_enrich_rdap_concurrency": 8,
            "stage1_enrich_tls_concurrency": 24,
            "stage1_fetch_queue_max": 6000,
            "stage1_cpu_queue_max": 3000,
            "stage1_parse_queue_max": 3000,
            "stage1_score_queue_max": 3000,
            "stage1_enrich_queue_max": 3000,
            "stage1_result_queue_max": 3000,
            "stage1_control_interval_seconds": 2.0,
        },
        "reliability": {},
    },
}

ENV_BINDINGS = {
    "PHISHING_HASH_PAGES": {"section": "hash", "key": "hash_pages", "type": "int"},
    "PHISHING_HASH_PAGE_CONCURRENCY": {"section": "hash", "key": "hash_page_concurrency", "type": "int"},
    "PHISHING_HASH_HTTP_LIMIT": {"section": "hash", "key": "hash_http_limit", "type": "int"},
    "PHISHING_HASH_AUX_NET_LIMIT": {"section": "hash", "key": "hash_aux_net_limit", "type": "int"},
    "PHISHING_HASH_ACTIVE_PAGES_FLOOR": {"section": "hash", "key": "hash_active_pages_floor", "type": "int"},
    "PHISHING_HASH_PROGRESS_LOG_INTERVAL_SECONDS": {"section": "hash", "key": "hash_progress_log_interval_seconds", "type": "int"},
    "PHISHING_LEXICAL_WORKERS": {"section": "stage0", "key": "lexical_workers", "type": "int"},
    "PHISHING_LEXICAL_BATCH_SIZE": {"section": "stage0", "key": "batch_size", "type": "int"},
    "PHISHING_LEXICAL_INFLIGHT_BATCHES": {"section": "stage0", "key": "inflight_batches", "type": "int"},
    "PHISHING_SHORTLIST_EXECUTION_MODE": {"section": "stage0", "key": "execution_mode", "type": "str"},
    "PHISHING_HASH_ADAPTIVE_DOWNSHIFT": {"section": "stage0", "key": "adaptive_downshift", "type": "bool"},
    **{
        env_name: {"section": "ray", "key": config_key, "type": "auto"}
        for env_name, config_key in RAY_ENV_TO_CONFIG_KEY.items()
    },
}

CLI_OVERRIDE_KEYS = (
    "runtime_profile",
    "telemetry_mode",
    "trace_record_key",
    "trace_url",
    "stage1_failure_policy",
    "stall_threshold_seconds",
)


def probe_runtime_resources() -> dict[str, Any]:
    cpu_cores = os.cpu_count() or 4
    ram_gb = 0.0
    vram_gb = 0.0

    if psutil is not None:
        try:
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
    resource_info = dict(resource_info or probe_runtime_resources())
    cpu_cores = int(resource_info.get("cpu_cores", 0) or 0)
    ram_gb = float(resource_info.get("ram_gb", 0.0) or 0.0)
    vram_gb = float(resource_info.get("vram_gb", 0.0) or 0.0)

    if cpu_cores >= 32 and ram_gb >= 128.0:
        return "server-balanced"
    if cpu_cores <= 16 or ram_gb < 16.0 or (0.0 < vram_gb <= 6.0):
        return "cpu-safe"
    return "cpu-fast"


def resolve_runtime_profile(
    profile_name: str,
    *,
    resource_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    requested_profile = str(profile_name or "auto").strip().lower()
    if requested_profile not in RUNTIME_PROFILE_NAMES:
        raise ValueError(f"runtime profile must be one of {sorted(RUNTIME_PROFILE_NAMES)}")
    resource_info = dict(resource_info or probe_runtime_resources())
    resolved_profile = (
        _resolve_auto_runtime_profile(resource_info)
        if requested_profile in {"auto", "default"}
        else requested_profile
    )
    if resolved_profile == "cpu-recall":
        resolved_profile = "server-throughput"
    selected = RUNTIME_PROFILE_CONFIG[resolved_profile]
    return {
        "name": resolved_profile,
        "requested_profile": requested_profile,
        "resolved_profile": resolved_profile,
        "resource_info": resource_info,
        "env": copy.deepcopy(selected.get("env") or {}),
        "stage1_http": copy.deepcopy(selected.get("stage1_http") or {}),
        "reliability": copy.deepcopy(selected.get("reliability") or {}),
    }


def apply_runtime_profile_env(settings: dict[str, Any]) -> None:
    for key, value in (settings.get("env") or {}).items():
        os.environ[str(key)] = str(value)


def _coerce_env_binding_value(value: Any, value_type: str) -> Any:
    if value_type == "int":
        return int(value)
    if value_type == "float":
        return float(value)
    if value_type == "bool":
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
    if value_type == "str":
        return str(value)
    return value


def _resolve_stage_env_overrides(
    *,
    section_name: str,
    runtime_profile_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    env_overrides = dict((runtime_profile_settings or {}).get("env") or {})
    resolved: dict[str, Any] = {}
    for env_name, metadata in ENV_BINDINGS.items():
        if str(metadata.get("section", "") or "") != section_name:
            continue
        if env_name not in env_overrides:
            continue
        resolved[str(metadata["key"])] = _coerce_env_binding_value(
            env_overrides[env_name],
            str(metadata.get("type", "auto") or "auto"),
        )
    return resolved


def resolve_reliability_config(
    overrides: dict[str, Any] | None = None,
    *,
    profile_name: str | None = None,
    resource_info: dict[str, Any] | None = None,
    runtime_profile_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = copy.deepcopy(PIPELINE_STAGE_CONFIG["reliability"])
    settings = runtime_profile_settings
    if settings is None and profile_name:
        settings = resolve_runtime_profile(profile_name, resource_info=resource_info)
    config.update(copy.deepcopy((settings or {}).get("reliability") or {}))
    for key, value in dict(overrides or {}).items():
        if value is None:
            continue
        config[key] = value
    return config


def resolve_stage_config(
    overrides: dict[str, Any] | None = None,
    *,
    profile_name: str | None = None,
    resource_info: dict[str, Any] | None = None,
    runtime_profile_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    settings = runtime_profile_settings
    if settings is None and profile_name:
        settings = resolve_runtime_profile(profile_name, resource_info=resource_info)
    overrides = dict(overrides or {})
    stage0_config = copy.deepcopy(PIPELINE_STAGE_CONFIG["stage0"])
    stage0_config.update(_resolve_stage_env_overrides(section_name="stage0", runtime_profile_settings=settings))
    stage0_config.update(copy.deepcopy(overrides.get("stage0") or {}))
    classify_config = copy.deepcopy(PIPELINE_STAGE_CONFIG["classify"])
    classify_config.update(copy.deepcopy(overrides.get("classify") or {}))
    return {
        "paths": copy.deepcopy(PATHS_CONFIG),
        "runtime_profile": copy.deepcopy(settings or {}),
        "stage0": stage0_config,
        "stage1_http": resolve_stage1_http_config(
            copy.deepcopy(overrides.get("stage1_http") or {}),
            profile_name=profile_name,
            resource_info=resource_info,
            runtime_profile_settings=settings,
        ),
        "hash": resolve_hash_stage_config(
            copy.deepcopy(overrides.get("hash") or {}),
            profile_name=profile_name,
            resource_info=resource_info,
            runtime_profile_settings=settings,
        ),
        "classify": classify_config,
        "ray": resolve_ray_runtime_config(
            copy.deepcopy(overrides.get("ray") or {}),
            runtime_profile_settings=settings,
            resource_info=resource_info,
        ),
        "reliability": resolve_reliability_config(
            copy.deepcopy(overrides.get("reliability") or {}),
            profile_name=profile_name,
            resource_info=resource_info,
            runtime_profile_settings=settings,
        ),
    }


def resolve_stage1_http_config(
    overrides: dict | None = None,
    *,
    profile_name: str | None = None,
    resource_info: dict[str, Any] | None = None,
    runtime_profile_settings: dict[str, Any] | None = None,
) -> dict:
    config = copy.deepcopy(PIPELINE_STAGE_CONFIG["stage1_http"])
    settings = runtime_profile_settings
    if settings is None and profile_name:
        settings = resolve_runtime_profile(profile_name, resource_info=resource_info)
    config.update(copy.deepcopy((settings or {}).get("stage1_http") or {}))
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


def resolve_hash_stage_config(
    overrides: dict | None = None,
    *,
    profile_name: str | None = None,
    resource_info: dict[str, Any] | None = None,
    runtime_profile_settings: dict[str, Any] | None = None,
) -> dict:
    config = copy.deepcopy(PIPELINE_STAGE_CONFIG["hash"])
    settings = runtime_profile_settings
    if settings is None and profile_name:
        settings = resolve_runtime_profile(profile_name, resource_info=resource_info)
    config.update(_resolve_stage_env_overrides(section_name="hash", runtime_profile_settings=settings))
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
    server_mode = bool(config.get("server_mode"))
    # IO-bound actors need minimal CPU reservation on servers
    fetch_actor_cpu = 0.10 if server_mode else 0.25
    enrich_actor_cpu = 0.10 if server_mode else 0.25
    browser_actor_cpu = 0.20 if server_mode else 0.50
    classify_actor_cpu = 0.35 if server_mode else 1.0
    ocr_actor_cpu = 0.50 if server_mode else 1.0
    actor_cpu_demand = (
        stage1_fetch_actors * fetch_actor_cpu
        + stage1_enrich_actors * enrich_actor_cpu
        + hash_browser_actors * browser_actor_cpu
        + classify_actors * classify_actor_cpu
        + ocr_actors * ocr_actor_cpu
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


def _as_bool_config_value(value: object, *, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _clamp_ray_budget(
    config: dict[str, object],
    *,
    cpu_cores: int,
    explicit_env_keys: set[str] | None = None,
) -> dict[str, object]:
    explicit_env_keys = set(explicit_env_keys or set())
    server_mode = bool(config.get("server_mode"))
    if server_mode and cpu_cores >= 32:
        actor_cpu_target = max(1.0, float(cpu_cores) * 0.90)
        total_cpu_target = actor_cpu_target
    else:
        actor_cpu_target = max(1.0, float(cpu_cores) * 0.60)
        total_cpu_target = max(actor_cpu_target, float(cpu_cores) * 0.85)
    adjustments: list[str] = []
    low_memory_mode = bool(config.get("low_memory_mode"))
    very_low_memory_mode = bool(config.get("very_low_memory_mode"))

    min_stage0_inflight = 1
    min_stage1_fetch_actors = 1 if very_low_memory_mode else 2 if low_memory_mode else 4
    min_stage1_enrich_actors = 1
    min_hash_browser_actors = 1
    min_classify_actors = 1 if low_memory_mode else 2
    min_ocr_actors = 1
    min_stage1_pending_cap = 24 if server_mode and cpu_cores >= 32 else min_stage1_fetch_actors
    min_hash_pending_cap = 4 if server_mode and cpu_cores >= 32 else min_hash_browser_actors
    min_classify_inflight = max(
        1,
        min(
            int(config.get("classify_inflight", 1) or 1),
            8 if server_mode and cpu_cores >= 32 and not low_memory_mode else 1,
        ),
    )
    explicit_minima: dict[str, int] = {}
    if server_mode:
        for key in (
            "stage0_inflight",
            "stage1_fetch_actors",
            "stage1_enrich_actors",
            "hash_browser_actors",
            "hash_tabs_per_actor",
            "classify_actors",
            "classify_inflight",
            "ocr_actors",
            "stage1_fetch_actor_max_concurrency",
            "stage1_enrich_actor_max_concurrency",
            "stage1_pending_cap",
            "hash_pending_cap",
        ):
            if key in explicit_env_keys:
                explicit_minima[key] = max(1, int(config.get(key, 1) or 1))
    relax_explicit_minima = False

    def _minimum_for(key: str, default: int) -> int:
        if not relax_explicit_minima and key in explicit_minima:
            return max(default, explicit_minima[key])
        return default

    def _reduce_value(key: str, *, minimum: int, step: int = 1, reason: str) -> bool:
        minimum = _minimum_for(key, minimum)
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
            changed = _reduce_value(
                "ocr_actors",
                minimum=min_ocr_actors,
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
            changed = _reduce_value(
                "ocr_actors",
                minimum=min_ocr_actors,
                step=1,
                reason="actor_cpu_budget",
            ) or changed

        if not changed:
            if explicit_minima and not relax_explicit_minima and total_demand > total_cpu_target:
                relax_explicit_minima = True
                adjustments.append("relax_explicit_env_minima(total_cpu_budget_exceeded)")
                continue
            break

    effective_classify_inflight_cap = max(
        1,
        int(config.get("classify_actors", 1) or 1) * (4 if server_mode else 2),
    )
    if not relax_explicit_minima and "classify_inflight" in explicit_minima:
        effective_classify_inflight_cap = max(
            effective_classify_inflight_cap,
            explicit_minima["classify_inflight"],
        )
    config["classify_inflight"] = max(
        _minimum_for("classify_inflight", min_classify_inflight),
        min(
            int(config.get("classify_inflight", min_classify_inflight) or min_classify_inflight),
            effective_classify_inflight_cap,
        ),
    )
    config["stage1_pending_cap"] = max(
        max(int(config.get("stage1_fetch_actors", 1) or 1), _minimum_for("stage1_pending_cap", min_stage1_pending_cap)),
        int(config.get("stage1_pending_cap", min_stage1_pending_cap) or min_stage1_pending_cap),
    )
    config["hash_pending_cap"] = max(
        max(int(config.get("hash_browser_actors", 1) or 1), _minimum_for("hash_pending_cap", min_hash_pending_cap)),
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


def resolve_ray_runtime_config(
    overrides: dict | None = None,
    *,
    runtime_profile_settings: dict[str, Any] | None = None,
    resource_info: dict[str, Any] | None = None,
) -> dict:
    resource_info = dict(resource_info or {})
    cpu_cores = int(resource_info.get("cpu_cores", 0) or (os.cpu_count() or 4))
    profile_env = dict((runtime_profile_settings or {}).get("env") or {})
    hash_pages_default = profile_env.get("PHISHING_HASH_PAGES", HASH_STAGE_CONFIG["hash_pages"])
    hash_pages = max(1, int(os.getenv("PHISHING_HASH_PAGES", hash_pages_default)))
    local_mode_env = os.getenv("PHISHING_RAY_LOCAL_MODE", "").strip().lower()
    explicit_local_mode = (
        local_mode_env in {"1", "true", "yes", "on"}
        if local_mode_env
        else None
    )
    total_ram_gb = float(resource_info.get("ram_gb", 0.0) or 0.0)
    available_ram_gb = float(resource_info.get("available_ram_gb", 0.0) or 0.0)
    if psutil is not None and (not total_ram_gb or not available_ram_gb):
        try:
            vm = psutil.virtual_memory()
            if not total_ram_gb:
                total_ram_gb = float(vm.total / (1024 ** 3))
            if not available_ram_gb:
                available_ram_gb = float(vm.available / (1024 ** 3))
        except Exception:
            total_ram_gb = total_ram_gb or 0.0
            available_ram_gb = available_ram_gb or 0.0
    config = _read_live_ray_runtime_env_config()
    for env_name, config_key in RAY_ENV_TO_CONFIG_KEY.items():
        if env_name in profile_env and os.getenv(env_name) is None:
            config[config_key] = profile_env[env_name]
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
        "stage0_inflight": 8,
        "stage1_fetch_actors": 24,
        "stage1_enrich_actors": 12,
        "hash_browser_actors": 16,
        "hash_tabs_per_actor": 3,
        "hash_finalize_batch": 64,
        "classify_actors": 16,
        "classify_inflight": 48,
        "ocr_actors": 4,
        "ocr_batch_size": 32,
        "ocr_batch_delay_ms": 25,
        "stage1_fetch_actor_max_concurrency": 8,
        "stage1_enrich_actor_max_concurrency": 4,
        "stage1_pending_cap": 192,
        "hash_pending_cap": 96,
        "stage1_http_connection_cap": 768,
        "stage1_http_keepalive_cap": 384,
        "prewarm_actors": True,
        "prewarm_mode": "staged",
        "enable_dynamic_control": True,
        "target_cpu_utilization": 0.92,
        "cpu_headroom_cores": 4,
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
    prewarm_requested = _as_bool_config_value(
        config.get("prewarm_actors", server_mode and not low_memory_mode),
        default=server_mode and not low_memory_mode,
    )
    dynamic_control_requested = _as_bool_config_value(
        config.get("enable_dynamic_control", True),
        default=True,
    )

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
            "prewarm_actors": prewarm_requested,
            "local_mode": bool(local_mode),
            "low_memory_mode": bool(low_memory_mode),
            "very_low_memory_mode": bool(very_low_memory_mode),
            "critical_memory_mode": bool(critical_memory_mode),
            "server_mode": bool(server_mode),
            "detected_total_ram_gb": round(total_ram_gb, 2),
            "detected_available_ram_gb": round(available_ram_gb, 2),
            "debug_mode": bool(RAY_DEBUG_MODE),
            "enable_dynamic_control": dynamic_control_requested,
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

    budget_info = _clamp_ray_budget(
        config,
        cpu_cores=cpu_cores,
        explicit_env_keys=explicit_env_keys,
    )
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
        raw_adjustments = [str(item) for item in list(config.get("budget_adjustments") or []) if str(item)]
        reduced: dict[str, dict[str, str]] = {}
        ordered_keys: list[str] = []
        for item in raw_adjustments:
            left, _, reason_part = item.partition(" (")
            key, _, transition = left.partition(":")
            key = key.strip()
            transition = transition.strip()
            reason = reason_part.rstrip(")").strip()
            if not key:
                key = left.strip() or "unknown"
            if key not in reduced:
                reduced[key] = {"first": transition, "last": transition, "reason": reason}
                ordered_keys.append(key)
            else:
                reduced[key]["last"] = transition or reduced[key]["last"]
                if reason:
                    reduced[key]["reason"] = reason

        compact_adjustments: list[str] = []
        for key in ordered_keys:
            info = reduced.get(key, {})
            first = str(info.get("first", "") or "")
            last = str(info.get("last", "") or "")
            reason = str(info.get("reason", "") or "")
            if "->" in first:
                start_value = first.split("->", 1)[0].strip()
            else:
                start_value = first
            if "->" in last:
                end_value = last.rsplit("->", 1)[-1].strip()
            else:
                end_value = last
            transition = start_value if not end_value or start_value == end_value else f"{start_value}->{end_value}"
            compact_adjustments.append(f"{key}:{transition}" + (f" ({reason})" if reason else ""))

        signature = "|".join(compact_adjustments)
        global _LAST_RAY_CLAMP_LOG_SIGNATURE
        if signature != _LAST_RAY_CLAMP_LOG_SIGNATURE:
            _LAST_RAY_CLAMP_LOG_SIGNATURE = signature
            preview = ", ".join(compact_adjustments[:10])
            hidden = max(0, len(compact_adjustments) - 10)
            if hidden > 0:
                preview = f"{preview}, ... (+{hidden} more)"
            _cfg_logger.warning(
                "Ray runtime clamp applied | fields_changed=%d | actor=%.1f/%.1f | total=%.1f/%.1f | %s",
                len(compact_adjustments),
                actor_cpu_demand,
                float(config.get("actor_cpu_budget", 0.0) or 0.0),
                total_demand,
                float(config.get("planned_total_cpu_budget", 0.0) or 0.0),
                preview,
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
