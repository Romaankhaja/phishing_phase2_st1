import os

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
