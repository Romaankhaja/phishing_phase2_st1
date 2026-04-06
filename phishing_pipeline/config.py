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
CHECKPOINT_CSV   = os.path.join(ROOT_DIR, "output", "checkpoint_records.csv")

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
CHECKPOINTS_DIR = os.path.join(OUTPUT_DIR, "checkpoints")
PIPELINE_RUN_RESULTS_CSV = os.path.join(OUTPUT_DIR, "pipeline_run_results.csv")
PIPELINE_STAGE_EVENTS_CSV = os.path.join(OUTPUT_DIR, "pipeline_stage_events.csv")
RUN_MANIFEST_JSON = os.path.join(OUTPUT_DIR, "run_manifest.json")

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
    "connect_timeout": 4.0,
    "head_timeout": 4.0,
    "get_timeout": 6.0,
    "dns_timeout": 3.0,
    "rdap_timeout": 5.0,
    "tls_timeout": 3.0,
    "max_html_bytes": 32768,
    "max_redirects": 4,
    "escalate_total_threshold": 60,
    "brand_min": 18,
    "credential_min": 18,
    "low_band_min": 20,
    "hard_trigger_brand_min": 10,
}

STAGE3_RECALL_RESCUE_CONFIG = {
    "failed_fetch_suspected_min": None,
    "failed_fetch_review_min": None,
}

RELIABILITY_CONFIG = {
    "stall_threshold_seconds": 180,
    "watchdog_warning_seconds": 60,
    "export_flush_interval_seconds": 5,
    "export_flush_row_interval": 50,
    "stage1_failure_policy": "route_to_dns",
    "max_worker_restarts": 2,
}


def resolve_stage1_http_config(overrides: dict | None = None) -> dict:
    config = dict(STAGE1_HTTP_CONFIG)
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
