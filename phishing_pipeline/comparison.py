import json
import hashlib
import numbers
import re
import ssl
import tldextract
from collections import Counter
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import asyncio
from playwright.async_api import async_playwright
try:
    import jellyfish
except Exception:
    jellyfish = None
from rapidfuzz import fuzz
from rapidfuzz.fuzz import ratio
import numpy as np
import csv
import math
import os
import time
import torch
import logging as _logging
import warnings as _warnings
import unicodedata
import psutil

try:
    import aiohttp
    _has_aiohttp = True
except ImportError:
    import requests
    _has_aiohttp = False

_clip_logger = _logging.getLogger(__name__)

_GENERIC_DOMAIN_PARTS = {
    "com", "in", "gov", "org", "co", "net", "www", "io", "xyz", "app", "site",
    "online", "shop", "store", "info", "live", "club", "dev", "ai", "bank",
}
# Parallelism tuning (auto-tuned from system resources)
import multiprocessing as _mp


def _read_env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        _clip_logger.warning("Invalid integer override for %s=%r; using %d", name, raw, default)
        return default


def _probe_runtime_resources() -> tuple[int, float, float]:
    cpu_count = _mp.cpu_count() or 4
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    vram_gb = 0.0
    if torch.cuda.is_available():
        try:
            vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        except Exception:
            vram_gb = 0.0
    return cpu_count, ram_gb, vram_gb


_CPU_COUNT, _RAM_GB, _VRAM_GB = _probe_runtime_resources()
_SERVER_CLASS = _CPU_COUNT >= 32 and _RAM_GB >= 96

if _SERVER_CLASS and _VRAM_GB >= 40:
    _default_max_pages = min(192, max(160, _CPU_COUNT * 4))
    _default_page_concurrency = 24
elif _CPU_COUNT >= 48:
    _default_max_pages = 120
    _default_page_concurrency = 16
elif _CPU_COUNT >= 16:
    _default_max_pages = 48
    _default_page_concurrency = 8
else:
    _default_max_pages = 16
    _default_page_concurrency = 4

MAX_CONCURRENT_PAGES = _read_env_int("PHISHING_HASH_PAGES", _default_max_pages)
SCRAPER_PAGE_CONCURRENCY = min(
    MAX_CONCURRENT_PAGES,
    _read_env_int("PHISHING_HASH_PAGE_CONCURRENCY", _default_page_concurrency),
)
BROWSER_SHARDS = max(1, math.ceil(MAX_CONCURRENT_PAGES / SCRAPER_PAGE_CONCURRENCY))
SCRAPER_NAV_TIMEOUT_MS = 8000
SCRAPER_SCREENSHOT_TIMEOUT_MS = 3000
SCRAPER_FETCH_TIMEOUT_S = 10.0
GPU_QUEUE_MAXSIZE = _read_env_int(
    "PHISHING_GPU_QUEUE_MAXSIZE",
    BROWSER_SHARDS * SCRAPER_PAGE_CONCURRENCY * (4 if _SERVER_CLASS else 2),
)
GPU_MAX_WAIT_MS = _read_env_int("PHISHING_GPU_MAX_WAIT_MS", 40 if _SERVER_CLASS else 50)
_AIOHTTP_CONNECTOR_LIMIT = min(1024 if _SERVER_CLASS else 256, max(64, MAX_CONCURRENT_PAGES * 3))


def _probe_gpu_batch_size() -> int:
    if not torch.cuda.is_available():
        return 16
    try:
        free_bytes, _ = torch.cuda.mem_get_info()
        vram_gb = free_bytes / 1024**3
        if vram_gb >= 80:
            return 512
        if vram_gb >= 40:
            return 256
        if vram_gb >= 16:
            return 96
        return 16
    except Exception:
        return 16


GPU_MAX_BATCH_SIZE = _read_env_int("PHISHING_GPU_BATCH_SIZE", _probe_gpu_batch_size())

_clip_logger.info(
    "Hash shortlist parallelism: pages=%d, shard_workers=%d, shards=%d, gpu_batch=%d, gpu_queue=%d, http_limit=%d",
    MAX_CONCURRENT_PAGES,
    SCRAPER_PAGE_CONCURRENCY,
    BROWSER_SHARDS,
    GPU_MAX_BATCH_SIZE,
    GPU_QUEUE_MAXSIZE,
    _AIOHTTP_CONNECTOR_LIMIT,
)

# transformers and CLIP are optional; use fallback for environments without these deps.
try:
    from transformers import CLIPProcessor, CLIPModel
    _has_clip = True
except Exception as e:
    _has_clip = False
    CLIPProcessor = None
    CLIPModel = None
    _clip_logger.debug("transformers/CLIP import failed, using fallback embeddings: %s", e)

BASE_DIR = os.path.dirname(__file__)

_MODEL_NAME = "openai/clip-vit-base-patch32"
_CLIP_DIM = 512  # output dimension for clip-vit-base-patch32
device = "cuda" if torch.cuda.is_available() else "cpu"

# â”€â”€ Lazy-loaded singletons (initialized on first use) â”€â”€
_model = None
_processor = None


def _get_model():
    """Lazy-load CLIP model & processor on first call. Uses FP16 on CUDA."""
    global _model, _processor, _has_clip
    if _model is not None and _processor is not None:
        return _model, _processor

    if not _has_clip:
        return None, None

    try:
        _clip_logger.info("ðŸš€ Loading CLIP model (%s) on %s...", _MODEL_NAME, device)
        m = CLIPModel.from_pretrained(_MODEL_NAME, use_safetensors=True)
        # FP16 on CUDA for massive throughput
        if device == "cuda":
            m = m.half()
        m = m.to(device).eval()
        p = CLIPProcessor.from_pretrained(_MODEL_NAME, use_fast=True)
        _model, _processor = m, p
        _clip_logger.info("âœ… CLIP model ready (dtype=%s)", next(m.parameters()).dtype)
        return _model, _processor
    except Exception as e:
        _has_clip = False
        _model = None
        _processor = None
        _clip_logger.debug("Failed to init CLIP model, using fallback embeddings: %s", e)
        return None, None

# Backward-compat aliases used by external code that references the globals
model = None      # legacy â€” use _get_model() instead
processor = None  # legacy â€” use _get_model() instead

def clean_domain(url):
    """Extract domain name from URL. Handles None/NaN values."""
    import pandas as pd
    if pd.isna(url) if isinstance(url, float) else url is None:
        return None
    
    url = str(url).strip()
    if not url.startswith("http"):
        url = "https://" + url
    
    return urlparse(url).netloc.lower()


def is_block_page(html):
    """Check if HTML is a block/error page (403, 404, etc)."""
    if not html or len(html) < 100:
        return True
    
    html_lower = html.lower()
    block_indicators = [
        "403 forbidden",
        "404 not found",
        "access denied",
        "page not found",
        "500 internal server error",
        "503 service unavailable",
        "blocked",
        "error page",
        "nginx",  # common error page
    ]
    
    return any(indicator in html_lower for indicator in block_indicators)


def sha256_text(text):
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_clip_embeddings_batch(images: list, batch_size: int = GPU_MAX_BATCH_SIZE) -> list:
    """
    Process multiple PIL images through CLIP in batched forward passes.
    Returns a list of normalized numpy arrays (float32, shape 512).
    """
    m, p = _get_model()
    if m is None or p is None:
        return [np.zeros(_CLIP_DIM, dtype="float32") for _ in images]

    all_embeddings = []
    for i in range(0, len(images), batch_size):
        batch = images[i : i + batch_size]
        try:
            inputs = p(images=batch, return_tensors="pt", padding=True)
            # Match model dtype (fp16 on CUDA, fp32 on CPU)
            model_dtype = next(m.parameters()).dtype
            inputs = {k: v.to(device=device, dtype=model_dtype) if v.dtype.is_floating_point else v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                # Robust HuggingFace extraction (bypassing unpredictable get_image_features APIs)
                pixel_values = inputs["pixel_values"]
                vision_out = m.vision_model(pixel_values=pixel_values)
                pooler = vision_out.pooler_output if hasattr(vision_out, "pooler_output") else vision_out[1]
                features = m.visual_projection(pooler)

            # L2 normalize
            features = features / features.norm(dim=-1, keepdim=True).clamp(min=1e-8)
            batch_np = features.cpu().float().numpy().astype("float32")
            all_embeddings.extend(batch_np)
        except Exception as e:
            _clip_logger.debug("CLIP batch embedding failed: %s", e)
            all_embeddings.extend([np.zeros(_CLIP_DIM, dtype="float32") for _ in batch])

    return all_embeddings


def get_clip_embedding(image):
    """Single-image convenience wrapper. Prefer get_clip_embeddings_batch() for multiple images."""
    results = get_clip_embeddings_batch([image], batch_size=1)
    return results[0]


def cosine_similarity(v1, v2):
    if v1 is None or v2 is None:
        return 0.0

    v1 = np.array(v1)
    v2 = np.array(v2)

    denom = np.linalg.norm(v1) * np.linalg.norm(v2)
    if denom == 0:
        return 0.0

    return float(np.dot(v1, v2) / denom)


def phash_distance(hash1, hash2):
    """
    Calculate Hamming distance between two perceptual hashes.
    Hashes should be hex strings. Lower distance = more similar.
    """
    if not hash1 or not hash2:
        return float('inf')
    
    try:
        # Convert hex strings to integers
        h1 = int(str(hash1), 16) if isinstance(hash1, str) else hash1
        h2 = int(str(hash2), 16) if isinstance(hash2, str) else hash2
        
        # XOR and count bits
        xor_result = h1 ^ h2
        distance = bin(xor_result).count('1')  # Hamming distance
        return distance
    except (ValueError, TypeError):
        return float('inf')


###############################################
# LOAD DATA
###############################################

with open(os.path.join(os.path.dirname(BASE_DIR), "data", "entity_hash_db.json")) as f:
    entity_db = json.load(f)


# âœ… CSV LOADER (NEW)
def load_domains(csv_file):
    domains = []

    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        if 'domain' not in reader.fieldnames:
            raise ValueError("CSV must contain a 'domain' column")

        for row in reader:
            domain = row['domain'].strip()
            if domain:
                domains.append(domain)

    return domains



BASE_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(BASE_DIR)
URLS_PATH = os.path.join(ROOT_DIR, "data", "urls.csv")
HASHING_LOG_PATH = os.path.join(ROOT_DIR, "output", "hashing_shortlist.log")
HASHING_EXCLUDED_URLS_PATH = os.path.join(
    ROOT_DIR, "output", "hashing_shortlist_excluded_urls.csv"
)

# Only load test URLs if running standalone; do not crash module import.
# url_list = load_domains(URLS_PATH)

DEFAULT_HASHING_THRESHOLD = 65.0
DEFAULT_DOMAIN_SIMILARITY_THRESHOLD = 0.85
DEFAULT_HIGH_CONFIDENCE_THRESHOLD = 78.0
DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD = 68.0
DEFAULT_TYPO_TOP_K = 10
DEFAULT_TYPO_MIN_SCORE = 0.45
DEFAULT_CLIP_MARGIN_MIN = 0.12
DEFAULT_CLIP_STRONG_SIMILARITY = 0.92
DEFAULT_SCORING_WEIGHTS = {
    "domain": 30.0,
    "screenshot": 20.0,
    "favicon": 14.0,
    "ssl_hash": 12.0,
    "html_hash": 6.0,
    "domain_hash": 8.0,
    "keywords": 10.0,
}
_SCORING_WEIGHT_KEYS = tuple(DEFAULT_SCORING_WEIGHTS.keys())


def _format_weights_for_logging(weights: dict) -> str:
    return ", ".join(f"{key}={weights[key]:g}" for key in _SCORING_WEIGHT_KEYS)


def _resolve_scoring_config(
    weights: dict | None = None,
    domain_similarity_threshold: float = DEFAULT_DOMAIN_SIMILARITY_THRESHOLD,
    high_confidence_threshold: float = DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
    medium_confidence_threshold: float = DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD,
    typo_top_k: int = DEFAULT_TYPO_TOP_K,
    typo_min_score: float = DEFAULT_TYPO_MIN_SCORE,
    clip_margin_min: float = DEFAULT_CLIP_MARGIN_MIN,
) -> dict:
    if not isinstance(domain_similarity_threshold, numbers.Real):
        raise ValueError("domain_similarity_threshold must be a numeric value in [0, 1]")
    domain_similarity_threshold = float(domain_similarity_threshold)
    if not (0.0 <= domain_similarity_threshold <= 1.0):
        raise ValueError("domain_similarity_threshold must be in [0, 1]")
    if not isinstance(high_confidence_threshold, numbers.Real):
        raise ValueError("high_confidence_threshold must be numeric")
    if not isinstance(medium_confidence_threshold, numbers.Real):
        raise ValueError("medium_confidence_threshold must be numeric")
    high_confidence_threshold = float(high_confidence_threshold)
    medium_confidence_threshold = float(medium_confidence_threshold)
    if high_confidence_threshold < 0 or high_confidence_threshold > 100:
        raise ValueError("high_confidence_threshold must be in [0, 100]")
    if medium_confidence_threshold < 0 or medium_confidence_threshold > 100:
        raise ValueError("medium_confidence_threshold must be in [0, 100]")
    if high_confidence_threshold < medium_confidence_threshold:
        raise ValueError("high_confidence_threshold must be >= medium_confidence_threshold")
    if not isinstance(typo_top_k, numbers.Real):
        raise ValueError("typo_top_k must be numeric")
    typo_top_k = int(typo_top_k)
    if typo_top_k <= 0:
        raise ValueError("typo_top_k must be >= 1")
    if not isinstance(typo_min_score, numbers.Real):
        raise ValueError("typo_min_score must be numeric")
    typo_min_score = float(typo_min_score)
    if typo_min_score < 0 or typo_min_score > 1:
        raise ValueError("typo_min_score must be in [0, 1]")
    if not isinstance(clip_margin_min, numbers.Real):
        raise ValueError("clip_margin_min must be numeric")
    clip_margin_min = float(clip_margin_min)
    if clip_margin_min < 0:
        raise ValueError("clip_margin_min must be non-negative")

    resolved_weights = dict(DEFAULT_SCORING_WEIGHTS)
    if weights is not None:
        if not isinstance(weights, dict):
            raise ValueError("weights must be a dict with known scoring keys")
        unknown_keys = sorted(set(weights.keys()) - set(_SCORING_WEIGHT_KEYS))
        if unknown_keys:
            raise ValueError(
                f"Unknown weight keys: {unknown_keys}. Allowed keys: {list(_SCORING_WEIGHT_KEYS)}"
            )
        for key, value in weights.items():
            if not isinstance(value, numbers.Real):
                raise ValueError(f"Weight '{key}' must be numeric")
            value = float(value)
            if value < 0:
                raise ValueError(f"Weight '{key}' must be non-negative")
            resolved_weights[key] = value

    for key in _SCORING_WEIGHT_KEYS:
        value = resolved_weights[key]
        if not isinstance(value, numbers.Real):
            raise ValueError(f"Weight '{key}' must be numeric")
        value = float(value)
        if value < 0:
            raise ValueError(f"Weight '{key}' must be non-negative")
        resolved_weights[key] = value

    total_weight = float(sum(resolved_weights.values()))
    if total_weight <= 0:
        raise ValueError("Total scoring weight must be greater than zero")

    return {
        "weights": resolved_weights,
        "total_weight": total_weight,
        "domain_similarity_threshold": domain_similarity_threshold,
        "high_confidence_threshold": high_confidence_threshold,
        "medium_confidence_threshold": medium_confidence_threshold,
        "typo_top_k": typo_top_k,
        "typo_min_score": typo_min_score,
        "clip_margin_min": clip_margin_min,
        "clip_similarity_floor": DEFAULT_CLIP_STRONG_SIMILARITY,
    }


_DEFAULT_SCORING_CONFIG = _resolve_scoring_config()

# Backward-compat aliases retained for external imports.
WEIGHTS = dict(_DEFAULT_SCORING_CONFIG["weights"])
_TOTAL_WEIGHT = _DEFAULT_SCORING_CONFIG["total_weight"]

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _configure_hashing_log(log_path: str = HASHING_LOG_PATH) -> str:
    return _ensure_hashing_log(log_path=log_path, reset=True)


def _ensure_hashing_log(log_path: str = HASHING_LOG_PATH, reset: bool = False) -> str:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    target_loggers = (
        _clip_logger,
        _logging.getLogger("py.warnings"),
        _logging.getLogger("phishing_pipeline.dns_gate"),
    )
    for logger in target_loggers:
        for handler in list(logger.handlers):
            if getattr(handler, "_hashing_run_log", False):
                logger.removeHandler(handler)
                handler.close()

    if reset:
        open(log_path, "w", encoding="utf-8").close()

    for logger in target_loggers:
        file_handler = _logging.FileHandler(log_path, mode="a", encoding="utf-8")
        file_handler.setLevel(_logging.DEBUG)
        file_handler.setFormatter(
            _logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        )
        file_handler._hashing_run_log = True
        logger.addHandler(file_handler)

    _clip_logger.setLevel(_logging.DEBUG)
    _clip_logger.propagate = False
    warning_logger = _logging.getLogger("py.warnings")
    warning_logger.setLevel(_logging.WARNING)
    warning_logger.propagate = False
    dns_gate_logger = _logging.getLogger("phishing_pipeline.dns_gate")
    dns_gate_logger.setLevel(_logging.INFO)
    dns_gate_logger.propagate = False
    _logging.captureWarnings(True)
    _warnings.simplefilter("default")
    _warnings.filterwarnings(
        "ignore",
        category=ResourceWarning,
        message=r".*unclosed file.*?/dev/null.*",
    )
    return log_path


def _close_hashing_log() -> None:
    for logger in (
        _clip_logger,
        _logging.getLogger("py.warnings"),
        _logging.getLogger("phishing_pipeline.dns_gate"),
    ):
        for handler in list(logger.handlers):
            if getattr(handler, "_hashing_run_log", False):
                handler.flush()
                logger.removeHandler(handler)
                handler.close()
    _logging.captureWarnings(False)


def _write_hashing_log_messages(log_messages: list[dict]) -> None:
    for log_message in log_messages:
        level = str(log_message.get("level", "info")).lower()
        message = str(log_message.get("message", "")).strip()
        if not message:
            continue

        log_method = getattr(_clip_logger, level, _clip_logger.info)
        log_method(message)


def _format_asyncio_exception_context(context: dict) -> str:
    message = str(context.get("message", "Asyncio loop exception")).strip()
    future = context.get("future") or context.get("task")
    exception = context.get("exception")

    details = [message]
    if future is not None:
        details.append(f"future={future!r}")
    if exception is not None:
        details.append(f"{exception.__class__.__name__}: {exception}")

    return " | ".join(details)


def _compact_exception_message(exc: Exception) -> str:
    text = str(exc or "").strip()
    if not text:
        return exc.__class__.__name__

    browser_logs_index = text.find("\nBrowser logs:")
    if browser_logs_index != -1:
        text = text[:browser_logs_index].rstrip()

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return exc.__class__.__name__

    compact_lines = [lines[0]]
    if "Call log:" in lines:
        call_log_index = lines.index("Call log:")
        call_steps = lines[call_log_index + 1:call_log_index + 4]
        if call_steps:
            compact_lines.append("Call log: " + " | ".join(call_steps))

    return " | ".join(compact_lines)


def _is_playwright_background_exception(context: dict) -> bool:
    message = str(context.get("message", ""))
    exception = context.get("exception")
    if message != "Future exception was never retrieved" or exception is None:
        return False

    exception_name = exception.__class__.__name__
    exception_text = str(exception)
    return (
        exception_name in {"TargetClosedError", "TimeoutError", "Error"}
        and (
            "taking page screenshot" in exception_text
            or "Target page, context or browser has been closed" in exception_text
            or "Unable to retrieve content because the page is navigating" in exception_text
            or "net::ERR_ABORTED" in exception_text
            or "frame was detached" in exception_text
            or "Navigation failed because page was closed" in exception_text
        )
    )


def _install_asyncio_exception_logging(loop) -> None:
    if getattr(loop, "_hashing_log_exception_handler", False):
        return

    def _exception_handler(loop, context):
        formatted = _format_asyncio_exception_context(context)
        exception = context.get("exception")

        if _is_playwright_background_exception(context):
            _clip_logger.warning(
                "Suppressed Playwright background exception: %s",
                formatted,
            )
            return

        if exception is not None:
            _clip_logger.error(
                "Asyncio exception: %s",
                formatted,
                exc_info=(type(exception), exception, exception.__traceback__),
            )
        else:
            _clip_logger.error("Asyncio exception: %s", formatted)

    loop.set_exception_handler(_exception_handler)
    loop._hashing_log_exception_handler = True


def _empty_shortlist_df():
    import pandas as pd

    return pd.DataFrame(
        columns=[
            "Cooresponding CSE",
            "Legitimate Domains",
            "Identified Phishing/Suspected Domain Name",
            "hash_score",
            "confidence_band",
            "score_margin",
            "evidence_tier",
            "lexical_score",
            "jw_primary",
            "token_set_primary",
            "skeleton_similarity",
            "lexical_rule_hit",
            "brand_token_hit",
            "candidate_generation_reason",
            "dominant_signal_family",
            "typo_similarity",
            "typo_min_score_used",
            "typo_decision_reason",
            "clip_similarity",
            "typo_anchor",
            "hash_anchor",
            "clip_anchor",
            "signal_hit_screenshot",
            "signal_hit_domain",
            "signal_hit_favicon",
            "signal_hit_ssl_hash",
            "signal_hit_html_hash",
            "signal_hit_domain_hash",
            "signal_hit_keywords",
            "signal_hit_typo",
            "screenshot_path",
        ]
    )


def _build_excluded_url_rows(input_urls, audit_rows, matched_urls):
    """Build rows for URLs excluded by DNS gate or hash shortlist scoring."""
    matched_counts = Counter()
    for matched_url in matched_urls:
        matched_text = str(matched_url or "").strip()
        if not matched_text:
            continue
        matched_counts[normalize_url(matched_text)] += 1

    excluded_rows = []
    for idx, raw_url in enumerate(input_urls):
        input_text = str(raw_url or "").strip()
        normalized_url = normalize_url(input_text) if input_text else ""
        audit_row = audit_rows[idx] if idx < len(audit_rows) else {}
        dns_status = str(audit_row.get("dns_status", "")).strip()
        dns_decision = str(audit_row.get("decision", "")).strip()

        if dns_decision and dns_decision != "accepted":
            excluded_rows.append(
                {
                    "input_position": idx + 1,
                    "input_url": input_text,
                    "normalized_url": normalized_url,
                    "exclusion_stage": "dns_gate",
                    "reason": dns_status or "dns_rejected",
                    "dns_status": dns_status,
                    "dns_decision": dns_decision,
                }
            )
            continue

        if normalized_url and matched_counts.get(normalized_url, 0) > 0:
            matched_counts[normalized_url] -= 1
            continue

        excluded_rows.append(
            {
                "input_position": idx + 1,
                "input_url": input_text,
                "normalized_url": normalized_url,
                "exclusion_stage": "hashing_shortlist",
                "reason": "below_threshold_or_fetch_failed",
                "dns_status": dns_status,
                "dns_decision": dns_decision or "accepted",
            }
        )

    return excluded_rows


def _write_excluded_urls_audit(
    excluded_rows,
    output_path: str = HASHING_EXCLUDED_URLS_PATH,
) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "input_position",
                "input_url",
                "normalized_url",
                "exclusion_stage",
                "reason",
                "dns_status",
                "dns_decision",
            ],
        )
        writer.writeheader()
        writer.writerows(excluded_rows)
    return output_path


# Block all resource types not needed for HTML text + screenshot extraction.
# Dropping images/fonts/media/stylesheets cuts per-page network time significantly.
_BLOCKED_RESOURCE_TYPES = {"font", "media", "image", "stylesheet", "other", "eventsource", "websocket"}

async def _route_nonessential_requests(route):
    request = route.request
    if request.resource_type in _BLOCKED_RESOURCE_TYPES:
        await route.abort()
        return
    await route.continue_()


# â”€â”€ Async favicon fetching (non-blocking) â”€â”€
async def favicon_hash_async(domain, session=None):
    """Fetch favicon hash using aiohttp (non-blocking) or requests fallback."""
    if _has_aiohttp and session is not None:
        try:
            async with session.get(
                f"https://{domain}/favicon.ico",
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    return hashlib.sha256(data).hexdigest()
        except Exception:
            pass
        return None
    else:
        # Sync fallback â€” run in thread so we don't block the loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _favicon_hash_sync, domain)


def _favicon_hash_sync(domain):
    """Sync favicon fetch (used as thread-pool fallback)."""
    import requests
    try:
        r = requests.get(f"https://{domain}/favicon.ico", timeout=5)
        if r.status_code == 200:
            return hashlib.sha256(r.content).hexdigest()
    except Exception:
        pass
    return None


# Keep old sync version for backward compat if anyone imports it
def favicon_hash(domain):
    return _favicon_hash_sync(domain)


async def get_ssl_hash_async(domain):
    """Non-blocking SSL certificate hash fetch."""
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx),
            timeout=5,
        )
        # reader is intentionally unused; the connection side effect gives ssl_object.
        _ = reader
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert_der = ssl_obj.getpeercert(binary_form=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if cert_der:
                return hashlib.sha256(cert_der).hexdigest()
        writer.close()
    except Exception:
        pass
    return None


def get_ssl_hash(domain):
    """Sync SSL certificate hash fetch (backward-compatible helper)."""
    import socket

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    return hashlib.sha256(cert_der).hexdigest()
    except Exception:
        pass
    return None


def domain_similarity(d1, d2):
    if isinstance(d1, list): d1 = d1[0] if d1 else ""
    if isinstance(d2, list): d2 = d2[0] if d2 else ""
    e1 = tldextract.extract(str(d1))
    e2 = tldextract.extract(str(d2))

    if e1.domain == e2.domain:
        return 1.0

    return ratio(e1.domain, e2.domain) / 100


_TYPO_CONFUSABLE_MAP = str.maketrans(
    {
        "\u0430": "a",
        "\u03bf": "o",
        "\u0435": "e",
        "\u0456": "i",
        "\u0455": "s",
        "\u0440": "p",
        "\u0441": "c",
        "\u03c5": "u",
        "\u03bd": "v",
        "\uff10": "0",
        "\uff11": "1",
        "\uff15": "5",
        "\uff16": "6",
        "\uff17": "7",
        "\uff18": "8",
        "\uff19": "9",
        "@": "a",
        "$": "s",
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "8": "b",
    }
)


def _domain_label_skeleton(label: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(label or "").lower())
    return normalized.translate(_TYPO_CONFUSABLE_MAP)


def _normalized_host_for_similarity(value: str) -> str:
    ext = tldextract.extract(str(value or ""))
    parts = [part for part in [ext.subdomain, ext.domain] if part]
    if not parts:
        return ""
    return _domain_label_skeleton(".".join(parts))


def _normalized_primary_for_similarity(value: str) -> str:
    ext = tldextract.extract(str(value or ""))
    return _domain_label_skeleton(ext.domain)


def _extract_brand_tokens(value: str) -> set[str]:
    host = _normalized_host_for_similarity(value)
    if not host:
        return set()
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", host)
        if token and token not in _GENERIC_DOMAIN_PARTS and len(token) > 2
    }
    ext = tldextract.extract(str(value or ""))
    primary = _domain_label_skeleton(ext.domain)
    if primary and primary not in _GENERIC_DOMAIN_PARTS and len(primary) > 2:
        tokens.add(primary)
    return tokens


def _jaro_winkler_similarity(text_a: str, text_b: str) -> float:
    if not text_a or not text_b:
        return 0.0
    if jellyfish is None:
        return ratio(text_a, text_b) / 100.0
    try:
        return float(jellyfish.jaro_winkler_similarity(text_a, text_b))
    except Exception:
        return ratio(text_a, text_b) / 100.0


def typosquat_similarity(d1: str, d2: str) -> float:
    """Typo/confusable similarity in [0,1] between two domains/hosts."""
    e1 = tldextract.extract(str(d1 or ""))
    e2 = tldextract.extract(str(d2 or ""))
    p1 = _domain_label_skeleton(e1.domain)
    p2 = _domain_label_skeleton(e2.domain)
    if not p1 or not p2:
        return 0.0
    if p1 == p2:
        return 1.0

    host1 = _domain_label_skeleton(".".join(part for part in [e1.subdomain, e1.domain] if part))
    host2 = _domain_label_skeleton(".".join(part for part in [e2.subdomain, e2.domain] if part))
    sim_primary = ratio(p1, p2) / 100.0
    sim_host = ratio(host1, host2) / 100.0 if host1 and host2 else 0.0
    sim = max(sim_primary, sim_host)
    if e1.suffix and e1.suffix == e2.suffix:
        sim = min(1.0, sim + 0.03)
    return float(sim)


def _compute_hybrid_lexical_metrics(target_domain: str, top_k: int | None = None) -> dict:
    n_entities = len(_entity_index["names"])
    if n_entities == 0:
        empty_scores = np.zeros(0, dtype="float64")
        empty_mask = np.zeros(0, dtype=bool)
        return {
            "lexical_scores": empty_scores,
            "jw_scores": empty_scores,
            "token_scores": empty_scores,
            "skeleton_scores": empty_scores,
            "host_scores": empty_scores,
            "lexical_rule_hit": empty_mask,
            "brand_token_hit": empty_mask,
            "candidate_mask": empty_mask,
            "candidate_reasons": [],
        }

    target_primary = _normalized_primary_for_similarity(target_domain)
    target_host = _normalized_host_for_similarity(target_domain)
    target_tokens = _extract_brand_tokens(target_domain)

    lexical_scores = np.zeros(n_entities, dtype="float64")
    jw_scores = np.zeros(n_entities, dtype="float64")
    token_scores = np.zeros(n_entities, dtype="float64")
    skeleton_scores = np.zeros(n_entities, dtype="float64")
    host_scores = np.zeros(n_entities, dtype="float64")
    lexical_rule_hit = np.zeros(n_entities, dtype=bool)
    brand_token_hit = np.zeros(n_entities, dtype=bool)
    candidate_mask = np.zeros(n_entities, dtype=bool)
    candidate_reasons = [""] * n_entities

    for i in range(n_entities):
        best_reason_parts = []
        entity_domains = _entity_index["domains"][i]
        entity_brand_tokens = _entity_index["brand_tokens"][i]
        if entity_brand_tokens and target_tokens and (entity_brand_tokens & target_tokens):
            brand_token_hit[i] = True
            lexical_rule_hit[i] = True
            best_reason_parts.append("brand_token_match")

        best_jw = 0.0
        best_token = 0.0
        best_skeleton = 0.0
        best_host = 0.0
        best_lexical = 0.0
        best_domain_reasons = []

        for entity_domain in entity_domains:
            entity_primary = _normalized_primary_for_similarity(entity_domain)
            entity_host = _normalized_host_for_similarity(entity_domain)

            jw_score = _jaro_winkler_similarity(target_primary, entity_primary)
            token_score = fuzz.token_set_ratio(target_primary, entity_primary) / 100.0 if target_primary and entity_primary else 0.0
            skeleton_score = typosquat_similarity(target_domain, entity_domain)
            host_score = ratio(target_host, entity_host) / 100.0 if target_host and entity_host else 0.0
            lexical_score = max(jw_score, token_score, skeleton_score, host_score)

            if lexical_score > best_lexical:
                best_lexical = lexical_score
                best_jw = jw_score
                best_token = token_score
                best_skeleton = skeleton_score
                best_host = host_score
                best_domain_reasons = []
                if jw_score >= 0.85:
                    best_domain_reasons.append("jw_primary")
                if token_score >= 0.90:
                    best_domain_reasons.append("token_set_primary")
                if skeleton_score >= 0.88:
                    best_domain_reasons.append("skeleton_similarity")
                if host_score >= 0.90:
                    best_domain_reasons.append("host_similarity")

        lexical_scores[i] = best_lexical
        jw_scores[i] = best_jw
        token_scores[i] = best_token
        skeleton_scores[i] = best_skeleton
        host_scores[i] = best_host

        if best_domain_reasons:
            lexical_rule_hit[i] = True
            best_reason_parts.extend(best_domain_reasons)

        if lexical_rule_hit[i]:
            candidate_mask[i] = True
            candidate_reasons[i] = "|".join(dict.fromkeys(best_reason_parts))

    if not candidate_mask.any():
        fallback_count = _DEFAULT_SCORING_CONFIG["typo_top_k"] if top_k is None else top_k
        fallback_mask = _select_topk_candidate_mask(lexical_scores, fallback_count)
        candidate_mask |= fallback_mask
        fallback_indices = np.where(fallback_mask)[0]
        for idx in fallback_indices:
            reason = candidate_reasons[idx]
            candidate_reasons[idx] = f"{reason}|fallback_top_k".strip("|")

    return {
        "lexical_scores": lexical_scores,
        "jw_scores": jw_scores,
        "token_scores": token_scores,
        "skeleton_scores": skeleton_scores,
        "host_scores": host_scores,
        "lexical_rule_hit": lexical_rule_hit,
        "brand_token_hit": brand_token_hit,
        "candidate_mask": candidate_mask,
        "candidate_reasons": candidate_reasons,
    }


def _compute_typosquat_scores(target_domain: str) -> np.ndarray:
    return _compute_hybrid_lexical_metrics(target_domain)["skeleton_scores"]


def _select_topk_candidate_mask(typo_scores: np.ndarray, top_k: int) -> np.ndarray:
    n_entities = int(typo_scores.shape[0])
    mask = np.zeros(n_entities, dtype=bool)
    if n_entities == 0:
        return mask
    k = max(1, min(int(top_k), n_entities))
    top_idx = np.argsort(-typo_scores)[:k]
    mask[top_idx] = True
    return mask


###############################################
# PRE-COMPUTED ENTITY INDEX (vectorised scoring)
###############################################

def _build_entity_index(entity_db):
    """
    Pre-compute numpy arrays from entity_db for vectorised scoring.
    Called once at module load â€” avoids repeated dict traversal.
    """
    entity_names = list(entity_db.keys())

    # Build a matrix of ALL screenshot CLIP vectors across ALL entities
    # plus a mapping so we know which rows belong to which entity.
    clip_vecs = []
    clip_entity_idx = []  # index into entity_names for each row

    entity_domains = []            # list of domain-lists, aligned with entity_names
    entity_fav_sets = []           # list of favicon-hash-sets
    entity_ssl_hash_sets = []      # list of SSL cert hash sets
    entity_html_hash_sets = []     # list of HTML hash sets
    entity_domain_hash_sets = []   # list of domain hash sets
    entity_kw_sets = []            # list of keyword-sets
    entity_brand_tokens = []       # list of lexical brand-token sets

    for idx, name in enumerate(entity_names):
        data = entity_db[name]

        domains = data.get("domains", [])
        entity_domains.append(domains)
        entity_fav_sets.append(set(data.get("favicon_hashes", [])) - {None})
        entity_ssl_hash_sets.append(set(data.get("ssl_hashes", [])) - {None})
        entity_html_hash_sets.append(set(data.get("html_hashes", [])) - {None})
        entity_domain_hash_sets.append(set(data.get("domain_hashes", [])) - {None})
        keyword_set = set(data.get("keywords", []))
        entity_kw_sets.append(keyword_set)
        brand_tokens = set()
        for domain in domains:
            brand_tokens |= _extract_brand_tokens(domain)
        for keyword in keyword_set:
            brand_tokens |= _extract_brand_tokens(keyword)
        entity_brand_tokens.append(brand_tokens)

        for vec in data.get("screenshot_clip", []):
            if vec is not None:
                clip_vecs.append(vec)
                clip_entity_idx.append(idx)

    clip_matrix = np.array(clip_vecs, dtype="float32") if clip_vecs else np.empty((0, _CLIP_DIM), dtype="float32")
    # L2-normalise rows (just in case they aren't already)
    norms = np.linalg.norm(clip_matrix, axis=1, keepdims=True).clip(min=1e-8)
    clip_matrix = clip_matrix / norms

    return {
        "names": entity_names,
        "clip_matrix": clip_matrix,
        "clip_entity_idx": np.array(clip_entity_idx, dtype="int32"),
        "domains": entity_domains,
        "fav_sets": entity_fav_sets,
        "ssl_hash_sets": entity_ssl_hash_sets,
        "html_hash_sets": entity_html_hash_sets,
        "domain_hash_sets": entity_domain_hash_sets,
        "kw_sets": entity_kw_sets,
        "brand_tokens": entity_brand_tokens,
    }


_entity_index = _build_entity_index(entity_db)

_gpu_clip_matrix = None
if _entity_index["clip_matrix"].shape[0] > 0 and device == "cuda":
    # Push precomputed numpy matrices permanently into H100 VRAM for instant access
    _gpu_clip_matrix = torch.tensor(_entity_index["clip_matrix"], dtype=torch.float32, device=device)

# â”€â”€ Top-level helper for ProcessPoolExecutor (must be picklable) â”€â”€

def _domain_sim_for_entity(args):
    """Compute max domain similarity for one entity. Runs in child process."""
    target_domain, entity_domains = args
    if not entity_domains:
        return 0.0
    return max(domain_similarity(target_domain, d) for d in entity_domains)


###############################################
# VECTORISED SCORING
###############################################

def _normalize_scores_with_active_weights(raw_scores, active_denominators):
    raw = np.array(raw_scores, dtype="float64")
    den = np.array(active_denominators, dtype="float64")
    normalized = np.zeros_like(raw, dtype="float64")
    valid = den > 1e-8
    normalized[valid] = (raw[valid] / den[valid]) * 100.0
    return normalized


def _confidence_band_from_score(score: float, scoring_config: dict) -> str:
    if score >= scoring_config["high_confidence_threshold"]:
        return "High"
    if score >= scoring_config["medium_confidence_threshold"]:
        return "Medium"
    return "Low"


def score_all_entities(
    screenshot_vec,
    target_domain,
    fav_hash,
    words,
    pool,
    ssl_hash=None,
    html_hash=None,
    domain_hash=None,
    scoring_config=None,
):
    """
    Score target against ALL entities using vectorised numpy ops + process pool.
    Returns dict { entity_name: score (0-100) }.
    """
    idx = _entity_index
    if scoring_config is None:
        scoring_config = _DEFAULT_SCORING_CONFIG
    resolved_weights = scoring_config["weights"]
    domain_similarity_floor = scoring_config["domain_similarity_threshold"]

    n_entities = len(idx["names"])
    scores = np.zeros(n_entities, dtype="float64")
    active_denominators = np.zeros(n_entities, dtype="float64")

    # â”€â”€â”€ SCREENSHOT (vectorised GPU/CPU cosine similarity) â”€â”€â”€
    if idx["clip_matrix"].shape[0] > 0 and screenshot_vec is not None:
        if _gpu_clip_matrix is not None:
            # Native H100 matrix multiplication
            sv = torch.tensor(screenshot_vec, dtype=torch.float32, device=device).unsqueeze(1)
            sv = sv / sv.norm(dim=0, keepdim=True).clamp(min=1e-8)
            all_sims = torch.mm(_gpu_clip_matrix, sv).squeeze().cpu().numpy()
        else:
            # Fallback CPU NumPy computation
            sv = np.array(screenshot_vec, dtype="float32").reshape(1, -1)
            sv_norm = np.linalg.norm(sv).clip(min=1e-8)
            sv = sv / sv_norm
            all_sims = idx["clip_matrix"] @ sv.T
            all_sims = all_sims.ravel()

        # reduce per-entity: max similarity for each entity
        for i in range(n_entities):
            mask = idx["clip_entity_idx"] == i
            if mask.any():
                scores[i] += float(all_sims[mask].max()) * resolved_weights["screenshot"]
                active_denominators[i] += resolved_weights["screenshot"]

    # â”€â”€â”€ DOMAIN (process pool for CPU-bound tldextract + rapidfuzz) â”€â”€â”€
    args_list = [(target_domain, idx["domains"][i]) for i in range(n_entities)]
    domain_sims = list(pool.map(_domain_sim_for_entity, args_list))
    for i, sim in enumerate(domain_sims):
        if sim >= domain_similarity_floor:
            scores[i] += sim * resolved_weights["domain"]
            active_denominators[i] += resolved_weights["domain"]

    # â”€â”€â”€ FAVICON (set lookup â€“ O(1) per entity) â”€â”€â”€
    if fav_hash:
        for i in range(n_entities):
            if idx["fav_sets"][i]:
                active_denominators[i] += resolved_weights["favicon"]
            if fav_hash in idx["fav_sets"][i]:
                scores[i] += resolved_weights["favicon"]

    if ssl_hash:
        for i in range(n_entities):
            if idx["ssl_hash_sets"][i]:
                active_denominators[i] += resolved_weights["ssl_hash"]
            if ssl_hash in idx["ssl_hash_sets"][i]:
                scores[i] += resolved_weights["ssl_hash"]

    if html_hash:
        for i in range(n_entities):
            if idx["html_hash_sets"][i]:
                active_denominators[i] += resolved_weights["html_hash"]
            if html_hash in idx["html_hash_sets"][i]:
                scores[i] += resolved_weights["html_hash"]

    if domain_hash:
        for i in range(n_entities):
            if idx["domain_hash_sets"][i]:
                active_denominators[i] += resolved_weights["domain_hash"]
            if domain_hash in idx["domain_hash_sets"][i]:
                scores[i] += resolved_weights["domain_hash"]

    # â”€â”€â”€ KEYWORDS (set intersection) â”€â”€â”€
    for i in range(n_entities):
        kw = idx["kw_sets"][i]
        if kw and words:
            active_denominators[i] += resolved_weights["keywords"]
            overlap = len(words & kw)
            scores[i] += min(overlap / 5, 1.0) * resolved_weights["keywords"]

    scores = _normalize_scores_with_active_weights(scores, active_denominators)

    return {idx["names"][i]: float(scores[i]) for i in range(n_entities)}


###############################################
# STREAMING FETCH PIPELINE
###############################################

async def _fetch_url_payload(url, browser_context, semaphore, aio_session, scoring_config):
    """
    Fetch one URL: navigate, screenshot, parse HTML, compute CPU-side scores.
    Returns payload dict for GPU queue, or None on timeout/crash.
    Retries once on TargetClosedError (browser crash).
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    resolved_weights = scoring_config["weights"]
    domain_similarity_floor = scoring_config["domain_similarity_threshold"]

    async def _single_attempt():
        async with semaphore:
            page = await browser_context.new_page()
            try:
                await page.goto(
                    url,
                    timeout=SCRAPER_NAV_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                html_content = await page.content()
                screenshot_bytes = await page.screenshot(
                    full_page=False,
                    timeout=SCRAPER_SCREENSHOT_TIMEOUT_MS,
                    animations="disabled",
                    type="png",
                )
                return html_content, screenshot_bytes
            finally:
                try:
                    if not page.is_closed():
                        await page.close()
                except Exception:
                    pass

    try:
        html_content, screenshot_bytes = await asyncio.wait_for(
            _single_attempt(), timeout=SCRAPER_FETCH_TIMEOUT_S
        )
    except asyncio.TimeoutError:
        return None
    except Exception as exc:
        if "TargetClosedError" in type(exc).__name__:
            try:
                html_content, screenshot_bytes = await asyncio.wait_for(
                    _single_attempt(), timeout=SCRAPER_FETCH_TIMEOUT_S
                )
            except Exception:
                return None
        else:
            return None

    soup = BeautifulSoup(html_content, "html.parser")
    visible_text = " ".join(
        [p.get_text() for p in soup.find_all(["p", "h1", "h2", "h3", "title"])]
    ).lower()
    words = set(visible_text.split())

    ext = tldextract.extract(domain)
    screenshot_name = ".".join(part for part in [ext.domain, ext.suffix] if part) or domain
    screenshot_path = os.path.join(BASE_DIR, "screens", f"{screenshot_name}.png")
    try:
        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
        with open(screenshot_path, "wb") as screenshot_file:
            screenshot_file.write(screenshot_bytes)
    except Exception:
        screenshot_path = ""

    domain_hash = sha256_text(domain)
    html_hash = sha256_text(html_content)
    fav_task = favicon_hash_async(domain, session=aio_session)
    ssl_task = get_ssl_hash_async(domain)
    fav_hash, ssl_hash = await asyncio.gather(fav_task, ssl_task)

    n_entities = len(_entity_index["names"])
    lexical_metrics = _compute_hybrid_lexical_metrics(
        domain,
        top_k=scoring_config["typo_top_k"],
    )
    typo_scores = lexical_metrics["skeleton_scores"]
    candidate_mask = lexical_metrics["candidate_mask"].copy()
    lexical_scores = lexical_metrics["lexical_scores"]
    jw_scores = lexical_metrics["jw_scores"]
    token_scores = lexical_metrics["token_scores"]
    lexical_rule_hit = lexical_metrics["lexical_rule_hit"]
    brand_token_hit = lexical_metrics["brand_token_hit"]
    candidate_reasons = list(lexical_metrics["candidate_reasons"])

    hash_bypass_mask = np.zeros(n_entities, dtype=bool)
    if fav_hash:
        hash_bypass_mask |= np.array(
            [fav_hash in _entity_index["fav_sets"][i] for i in range(n_entities)],
            dtype=bool,
        )
    if ssl_hash:
        hash_bypass_mask |= np.array(
            [ssl_hash in _entity_index["ssl_hash_sets"][i] for i in range(n_entities)],
            dtype=bool,
        )
    if html_hash:
        hash_bypass_mask |= np.array(
            [html_hash in _entity_index["html_hash_sets"][i] for i in range(n_entities)],
            dtype=bool,
        )
    if domain_hash:
        hash_bypass_mask |= np.array(
            [domain_hash in _entity_index["domain_hash_sets"][i] for i in range(n_entities)],
            dtype=bool,
        )
    candidate_mask |= hash_bypass_mask
    for idx in np.where(hash_bypass_mask)[0]:
        candidate_reasons[idx] = f"{candidate_reasons[idx]}|hash_bypass".strip("|")

    cpu_scores = np.zeros(n_entities, dtype="float64")
    cpu_denominators = np.zeros(n_entities, dtype="float64")
    domain_hit = np.zeros(n_entities, dtype=bool)
    lexical_hit = np.array(lexical_rule_hit, dtype=bool)
    favicon_hit = np.zeros(n_entities, dtype=bool)
    ssl_hash_hit = np.zeros(n_entities, dtype=bool)
    html_hash_hit = np.zeros(n_entities, dtype=bool)
    domain_hash_hit = np.zeros(n_entities, dtype=bool)
    keyword_hit = np.zeros(n_entities, dtype=bool)
    for i in range(n_entities):
        if not candidate_mask[i]:
            continue
        entity_domains = _entity_index["domains"][i]
        if entity_domains:
            domain_sim = max(
                domain_similarity(domain, d) for d in entity_domains
            )
            combined_lexical = max(
                float(lexical_scores[i]),
                domain_sim if domain_sim >= domain_similarity_floor else 0.0,
            )
            if bool(lexical_rule_hit[i]) or bool(brand_token_hit[i]) or domain_sim >= domain_similarity_floor:
                cpu_scores[i] += combined_lexical * resolved_weights["domain"]
                cpu_denominators[i] += resolved_weights["domain"]
                domain_hit[i] = combined_lexical > 0
        fav_set = _entity_index["fav_sets"][i]
        if fav_hash and fav_set:
            cpu_denominators[i] += resolved_weights["favicon"]
            if fav_hash in fav_set:
                cpu_scores[i] += resolved_weights["favicon"]
                favicon_hit[i] = True
        ssl_set = _entity_index["ssl_hash_sets"][i]
        if ssl_hash and ssl_set:
            cpu_denominators[i] += resolved_weights["ssl_hash"]
            if ssl_hash in ssl_set:
                cpu_scores[i] += resolved_weights["ssl_hash"]
                ssl_hash_hit[i] = True
        html_set = _entity_index["html_hash_sets"][i]
        if html_hash and html_set:
            cpu_denominators[i] += resolved_weights["html_hash"]
            if html_hash in html_set:
                cpu_scores[i] += resolved_weights["html_hash"]
                html_hash_hit[i] = True
        domain_hash_set = _entity_index["domain_hash_sets"][i]
        if domain_hash and domain_hash_set:
            cpu_denominators[i] += resolved_weights["domain_hash"]
            if domain_hash in domain_hash_set:
                cpu_scores[i] += resolved_weights["domain_hash"]
                domain_hash_hit[i] = True
        if _entity_index["kw_sets"][i] and words:
            cpu_denominators[i] += resolved_weights["keywords"]
            overlap = len(words & _entity_index["kw_sets"][i])
            keyword_score = min(overlap / 5, 1.0) * resolved_weights["keywords"]
            cpu_scores[i] += keyword_score
            keyword_hit[i] = keyword_score > 0

    return {
        "url": url,
        "domain": domain,
        "screenshot_path": screenshot_path,
        "screenshot_bytes": screenshot_bytes,
        "cpu_scores": cpu_scores,
        "cpu_denominators": cpu_denominators,
        "lexical_scores": lexical_scores,
        "jw_scores": jw_scores,
        "token_scores": token_scores,
        "domain_hit": domain_hit,
        "lexical_hit": lexical_hit,
        "lexical_rule_hit": lexical_rule_hit,
        "brand_token_hit": brand_token_hit,
        "favicon_hit": favicon_hit,
        "ssl_hash_hit": ssl_hash_hit,
        "html_hash_hit": html_hash_hit,
        "domain_hash_hit": domain_hash_hit,
        "keyword_hit": keyword_hit,
        "typo_scores": typo_scores,
        "candidate_mask": candidate_mask,
        "candidate_reasons": candidate_reasons,
    }


###############################################
# BROWSER SHARDS
###############################################

async def _run_browser_shard(
    shard_id,
    url_queue,
    gpu_queue,
    metrics,
    aio_session,
    scoring_config,
):
    """
    Long-lived browser shard with SCRAPER_PAGE_CONCURRENCY workers
    pulling URLs from the shared queue.
    """
    p = await async_playwright().start()
    browser = await p.chromium.launch(headless=True)
    ctx = await browser.new_context(
        ignore_https_errors=True, service_workers="block"
    )
    await ctx.route("**/*", _route_nonessential_requests)
    ctx.set_default_navigation_timeout(SCRAPER_NAV_TIMEOUT_MS)
    ctx.set_default_timeout(SCRAPER_SCREENSHOT_TIMEOUT_MS)
    semaphore = asyncio.Semaphore(SCRAPER_PAGE_CONCURRENCY)

    async def _worker():
        while True:
            url = await url_queue.get()
            if url is None:
                url_queue.task_done()
                break
            try:
                payload = await _fetch_url_payload(
                    url,
                    ctx,
                    semaphore,
                    aio_session,
                    scoring_config,
                )
                if payload is None:
                    metrics["fetch_timed_out"] += 1
                else:
                    metrics["hashed_success"] += 1
                    await gpu_queue.put(payload)
                metrics["processed"] += 1
            except Exception as exc:
                metrics["fetch_failed"] += 1
                metrics["processed"] += 1
                _clip_logger.warning(
                    "Shard %d error on %s: %s: %s",
                    shard_id, url, exc.__class__.__name__,
                    _compact_exception_message(exc),
                )
            finally:
                url_queue.task_done()

    workers = [asyncio.create_task(_worker()) for _ in range(SCRAPER_PAGE_CONCURRENCY)]
    try:
        await asyncio.gather(*workers)
    finally:
        for cleanup in (ctx.close, browser.close, p.stop):
            try:
                await cleanup()
            except Exception:
                pass


###############################################
# GPU MICROBATCH SCORER
###############################################

async def _gpu_microbatch_scorer(gpu_queue, results, metrics, threshold, scoring_config):
    """
    Single GPU scorer. Flushes on GPU_MAX_BATCH_SIZE or GPU_MAX_WAIT_MS.
    """
    loop = asyncio.get_running_loop()
    batch = []
    deadline = None
    resolved_weights = scoring_config["weights"]

    async def _flush():
        nonlocal batch, deadline
        if not batch:
            return
        current_batch = batch
        batch = []
        deadline = None
        metrics["gpu_batches_flushed"] += 1

        images, valid_payloads = [], []
        for payload in current_batch:
            try:
                img = Image.open(BytesIO(payload["screenshot_bytes"])).convert("RGB")
                images.append(img)
                valid_payloads.append(payload)
            except Exception as e:
                _clip_logger.debug("Failed to decode screenshot: %s", e)

        if not images:
            return

        clip_vecs = await loop.run_in_executor(
            None, get_clip_embeddings_batch, images, len(images)
        )

        sv = torch.tensor(np.array(clip_vecs), dtype=torch.float32, device=device)
        sv = sv / sv.norm(dim=1, keepdim=True).clamp(min=1e-8)

        n_entities = len(_entity_index["names"])
        eidx = _entity_index["clip_entity_idx"]

        if _gpu_clip_matrix is not None and sv.shape[0] > 0:
            all_sims = torch.mm(_gpu_clip_matrix, sv.T)
        else:
            clip_np = _entity_index["clip_matrix"]
            all_sims_np = clip_np @ sv.cpu().numpy().T
            all_sims = torch.tensor(all_sims_np, dtype=torch.float32)

        for b, payload in enumerate(valid_payloads):
            scores = payload["cpu_scores"].copy()
            denominators = payload["cpu_denominators"].copy()
            sims_b = all_sims[:, b] if all_sims.ndim > 1 else all_sims
            screenshot_hit = np.zeros(n_entities, dtype=bool)
            screenshot_similarity = np.zeros(n_entities, dtype="float64")
            candidate_mask = payload.get("candidate_mask")
            if candidate_mask is None:
                candidate_mask = np.ones(n_entities, dtype=bool)
            else:
                candidate_mask = np.array(candidate_mask, dtype=bool)

            for i in range(n_entities):
                if not candidate_mask[i]:
                    continue
                mask = eidx == i
                if mask.any():
                    if isinstance(sims_b, torch.Tensor):
                        entity_sims = sims_b[torch.tensor(mask, device=sims_b.device)]
                        max_sim = float(entity_sims.max().item())
                        scores[i] += max_sim * resolved_weights["screenshot"]
                    else:
                        max_sim = float(sims_b[mask].max())
                        scores[i] += max_sim * resolved_weights["screenshot"]
                    denominators[i] += resolved_weights["screenshot"]
                    screenshot_hit[i] = max_sim > 0
                    screenshot_similarity[i] = max_sim

            norm_scores = _normalize_scores_with_active_weights(scores, denominators)
            candidate_indices = np.where(candidate_mask)[0]
            if candidate_indices.size == 0:
                candidate_indices = np.arange(n_entities, dtype=int)
            candidate_scores = norm_scores[candidate_indices]
            best_local_idx = int(np.argmax(candidate_scores))
            best_idx = int(candidate_indices[best_local_idx])
            best_score = float(norm_scores[best_idx])
            best_entity = _entity_index["names"][best_idx]
            if candidate_scores.size > 1:
                top2 = np.partition(candidate_scores, -2)[-2:]
                second_best = float(top2.min())
            else:
                second_best = 0.0
            score_margin = best_score - second_best
            confidence_band = _confidence_band_from_score(best_score, scoring_config)
            typo_scores = payload.get("typo_scores")
            best_typo_similarity = (
                float(typo_scores[best_idx]) if typo_scores is not None and len(typo_scores) > best_idx else 0.0
            )
            best_lexical_score = float(payload["lexical_scores"][best_idx])
            best_jw_score = float(payload["jw_scores"][best_idx])
            best_token_score = float(payload["token_scores"][best_idx])
            lexical_rule_hit = bool(payload["lexical_rule_hit"][best_idx])
            brand_token_hit = bool(payload["brand_token_hit"][best_idx])
            typo_anchor = lexical_rule_hit and best_typo_similarity >= scoring_config["typo_min_score"]
            hash_anchor = any(
                (
                    bool(payload["favicon_hit"][best_idx]),
                    bool(payload["ssl_hash_hit"][best_idx]),
                    bool(payload["html_hash_hit"][best_idx]),
                    bool(payload["domain_hash_hit"][best_idx]),
                )
            )
            best_clip_similarity = float(screenshot_similarity[best_idx])
            clip_anchor = (
                bool(screenshot_hit[best_idx])
                and best_clip_similarity >= scoring_config["clip_similarity_floor"]
                and score_margin >= scoring_config["clip_margin_min"]
            )
            evidence_tier = (
                "strong_evidence"
                if lexical_rule_hit and (hash_anchor or clip_anchor)
                else "weak_evidence"
            )
            hash_contribution = float(
                bool(payload["favicon_hit"][best_idx]) * resolved_weights["favicon"]
                + bool(payload["ssl_hash_hit"][best_idx]) * resolved_weights["ssl_hash"]
                + bool(payload["html_hash_hit"][best_idx]) * resolved_weights["html_hash"]
                + bool(payload["domain_hash_hit"][best_idx]) * resolved_weights["domain_hash"]
            )
            lexical_contribution = best_lexical_score * resolved_weights["domain"]
            visual_contribution = best_clip_similarity * resolved_weights["screenshot"]
            dominant_signal_family = max(
                (
                    ("lexical", lexical_contribution),
                    ("visual", visual_contribution),
                    ("hash", hash_contribution),
                ),
                key=lambda item: item[1],
            )[0]
            candidate_generation_reason = payload["candidate_reasons"][best_idx] or "fallback_top_k"

            if best_score > threshold:
                metrics["final_matches_above_threshold"] += 1
                results.append(
                    {
                        "url": payload["url"],
                        "best_entity": best_entity,
                        "best_score": best_score,
                        "score_margin": score_margin,
                        "confidence_band": confidence_band,
                        "evidence_tier": evidence_tier,
                        "lexical_score": best_lexical_score,
                        "jw_primary": best_jw_score,
                        "token_set_primary": best_token_score,
                        "skeleton_similarity": best_typo_similarity,
                        "lexical_rule_hit": bool(lexical_rule_hit),
                        "brand_token_hit": bool(brand_token_hit),
                        "candidate_generation_reason": candidate_generation_reason,
                        "dominant_signal_family": dominant_signal_family,
                        "typo_similarity": best_typo_similarity,
                        "clip_similarity": best_clip_similarity,
                        "typo_anchor": bool(typo_anchor),
                        "hash_anchor": bool(hash_anchor),
                        "clip_anchor": bool(clip_anchor),
                        "signal_hit_screenshot": bool(screenshot_hit[best_idx]),
                        "signal_hit_typo": bool(typo_anchor),
                        "signal_hit_domain": bool(payload["domain_hit"][best_idx]),
                        "signal_hit_favicon": bool(payload["favicon_hit"][best_idx]),
                        "signal_hit_ssl_hash": bool(payload["ssl_hash_hit"][best_idx]),
                        "signal_hit_html_hash": bool(payload["html_hash_hit"][best_idx]),
                        "signal_hit_domain_hash": bool(payload["domain_hash_hit"][best_idx]),
                        "signal_hit_keywords": bool(payload["keyword_hit"][best_idx]),
                        "screenshot_path": payload.get("screenshot_path", ""),
                    }
                )

        metrics["gpu_items_scored"] += len(valid_payloads)
        metrics["avg_gpu_batch_size"] = (
            metrics["gpu_items_scored"] / max(1, metrics["gpu_batches_flushed"])
        )

    while True:
        now = loop.time()
        wait = None if deadline is None else max(0.001, deadline - now)
        try:
            payload = await asyncio.wait_for(gpu_queue.get(), timeout=wait)
            if payload is None:  # sentinel â€” flush and exit
                await _flush()
                break
            batch.append(payload)
            if deadline is None:
                deadline = loop.time() + GPU_MAX_WAIT_MS / 1000
            if len(batch) >= GPU_MAX_BATCH_SIZE:
                await _flush()
        except asyncio.TimeoutError:
            await _flush()


###############################################
# PROGRESS HELPERS
###############################################

def _build_progress_postfix(metrics):
    return {
        "proc": metrics["processed"],
        "dns": metrics["passed_dns_gate"],
        "ok": metrics["hashed_success"],
        "fail": metrics["fetch_failed"],
        "tout": metrics["fetch_timed_out"],
        "match": metrics["final_matches_above_threshold"],
        "gpu": metrics["gpu_batches_flushed"],
    }


def _log_hashing_metrics_summary(
    metrics,
    elapsed,
    threshold,
    shortlisted_results=None,
    typo_min_score=None,
):
    _clip_logger.info(
        "Hashing shortlist completed | passed_dns_gate=%d | processed=%d | "
        "hashed_success=%d | fetch_failed=%d | fetch_timed_out=%d | "
        "final_matches=%d | gpu_batches=%d | avg_gpu_batch=%.1f | "
        "threshold=%s | elapsed=%.1fs",
        metrics["passed_dns_gate"],
        metrics["processed"],
        metrics["hashed_success"],
        metrics["fetch_failed"],
        metrics["fetch_timed_out"],
        metrics["final_matches_above_threshold"],
        metrics["gpu_batches_flushed"],
        metrics["avg_gpu_batch_size"],
        threshold,
        elapsed,
    )

    shortlisted_results = shortlisted_results or []
    typo_anchor_count = sum(1 for result in shortlisted_results if bool(result.get("typo_anchor")))
    hash_anchor_count = sum(1 for result in shortlisted_results if bool(result.get("hash_anchor")))
    clip_anchor_count = sum(1 for result in shortlisted_results if bool(result.get("clip_anchor")))
    _clip_logger.info(
        "Anchor summary (shortlisted) | typo_anchor=%d | hash_anchor=%d | clip_anchor=%d | shortlisted=%d",
        typo_anchor_count,
        hash_anchor_count,
        clip_anchor_count,
        len(shortlisted_results),
    )

    typo_values = []
    for result in shortlisted_results:
        try:
            typo_values.append(float(result.get("typo_similarity", 0.0)))
        except (TypeError, ValueError):
            continue

    if not typo_values:
        return

    typo_array = np.array(typo_values, dtype="float64")
    typo_threshold_text = "n/a" if typo_min_score is None else f"{float(typo_min_score):.4f}"
    _clip_logger.info(
        "Typo similarity summary (shortlisted) | min=%.4f | avg=%.4f | p95=%.4f | max=%.4f | typo_min_score=%s",
        float(np.min(typo_array)),
        float(np.mean(typo_array)),
        float(np.percentile(typo_array, 95)),
        float(np.max(typo_array)),
        typo_threshold_text,
    )


###############################################
# STREAMING ENGINE
###############################################

async def run_hashing_shortlist_streaming(
    url_list,
    threshold=DEFAULT_HASHING_THRESHOLD,
    domain_similarity_threshold=DEFAULT_DOMAIN_SIMILARITY_THRESHOLD,
    high_confidence_threshold=DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
    medium_confidence_threshold=DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD,
    typo_top_k=DEFAULT_TYPO_TOP_K,
    typo_min_score=DEFAULT_TYPO_MIN_SCORE,
    clip_margin_min=DEFAULT_CLIP_MARGIN_MIN,
    dns_timeout=None,
    dns_retries=None,
    dns_max_workers=None,
    weights=None,
):
    """
    Streaming hashing shortlist engine. Uses long-lived browser shards
    feeding a bounded GPU queue. No Ray dependency.
    """
    import pandas as pd

    if not isinstance(threshold, numbers.Real):
        raise ValueError("threshold must be a numeric value")
    threshold = float(threshold)
    if threshold < 0:
        raise ValueError("threshold must be non-negative")

    scoring_config = _resolve_scoring_config(
        weights=weights,
        domain_similarity_threshold=domain_similarity_threshold,
        high_confidence_threshold=high_confidence_threshold,
        medium_confidence_threshold=medium_confidence_threshold,
        typo_top_k=typo_top_k,
        typo_min_score=typo_min_score,
        clip_margin_min=clip_margin_min,
    )
    resolved_weights = scoring_config["weights"]

    input_urls = list(url_list)
    log_path = _configure_hashing_log()
    original_count = len(input_urls)
    metrics = {
        "passed_dns_gate": 0,
        "processed": 0,
        "hashed_success": 0,
        "fetch_failed": 0,
        "fetch_timed_out": 0,
        "final_matches_above_threshold": 0,
        "gpu_batches_flushed": 0,
        "gpu_items_scored": 0,
        "avg_gpu_batch_size": 0.0,
    }

    try:
        from .dns_gate import (
            DEFAULT_DNS_TIMEOUT,
            DEFAULT_DNS_RETRIES,
            _gate_urls_for_hashing_async,
            write_dns_gate_audit,
        )
        if dns_timeout is None:
            dns_timeout_effective = float(DEFAULT_DNS_TIMEOUT)
        else:
            if not isinstance(dns_timeout, numbers.Real):
                raise ValueError("dns_timeout must be numeric")
            dns_timeout_effective = float(dns_timeout)
            if dns_timeout_effective <= 0:
                raise ValueError("dns_timeout must be > 0")

        if dns_retries is None:
            dns_retries_effective = int(DEFAULT_DNS_RETRIES)
        else:
            if not isinstance(dns_retries, numbers.Real):
                raise ValueError("dns_retries must be numeric")
            dns_retries_effective = int(dns_retries)
            if dns_retries_effective < 0:
                raise ValueError("dns_retries must be >= 0")

        if dns_max_workers is None:
            dns_max_workers_effective = None
        else:
            if not isinstance(dns_max_workers, numbers.Real):
                raise ValueError("dns_max_workers must be numeric")
            dns_max_workers_effective = int(dns_max_workers)
            if dns_max_workers_effective <= 0:
                raise ValueError("dns_max_workers must be > 0")

        _clip_logger.info(
            "Hashing shortlist (streaming) started | urls=%d | threshold=%s | "
            "domain_similarity_threshold=%.3f | high_confidence_threshold=%.2f | "
            "medium_confidence_threshold=%.2f | typo_top_k=%d | typo_min_score=%.3f | "
            "clip_margin_min=%.3f | dns_timeout=%.2f | dns_retries=%d | dns_max_workers=%s",
            original_count,
            threshold,
            scoring_config["domain_similarity_threshold"],
            scoring_config["high_confidence_threshold"],
            scoring_config["medium_confidence_threshold"],
            scoring_config["typo_top_k"],
            scoring_config["typo_min_score"],
            scoring_config["clip_margin_min"],
            dns_timeout_effective,
            dns_retries_effective,
            dns_max_workers_effective if dns_max_workers_effective is not None else "adaptive",
        )
        _clip_logger.info(
            "Scoring weights | %s",
            _format_weights_for_logging(resolved_weights),
        )

        shortlisted_urls, audit_rows = await _gate_urls_for_hashing_async(
            input_urls,
            timeout=dns_timeout_effective,
            max_workers=dns_max_workers_effective,
            retries=dns_retries_effective,
        )
        write_dns_gate_audit(audit_rows)
        accepted_count = len(shortlisted_urls)
        metrics["passed_dns_gate"] = accepted_count
        dns_status_counts = Counter(
            str(row.get("dns_status", "")).strip()
            for row in audit_rows
        )
        retry_success_count = sum(1 for row in audit_rows if row.get("retry_success"))
        _clip_logger.info(
            "DNS gate kept %d/%d URLs at %.1fs timeout (retries=%d, retry_success=%d) | "
            "resolved=%d timeout=%d resolver_error=%d no_records=%d dns_error=%d",
            accepted_count,
            original_count,
            dns_timeout_effective,
            dns_retries_effective,
            retry_success_count,
            dns_status_counts.get("resolved", 0),
            dns_status_counts.get("timeout", 0),
            dns_status_counts.get("resolver_error", 0),
            dns_status_counts.get("no_records", 0),
            dns_status_counts.get("dns_error", 0),
        )
        print(
            f"DNS gate kept {accepted_count}/{original_count} URLs "
            f"(timeout={dns_timeout_effective:.1f}s, retries={dns_retries_effective})"
        )
        _clip_logger.info("Hashing log file: %s", log_path)
        print(f"Hashing log: {log_path}")

        if not shortlisted_urls:
            excluded_rows = _build_excluded_url_rows(
                input_urls,
                audit_rows,
                matched_urls=[],
            )
            excluded_path = _write_excluded_urls_audit(excluded_rows)
            _clip_logger.info(
                "Excluded URL audit written to %s with %d rows",
                excluded_path,
                len(excluded_rows),
            )
            print(f"Excluded URLs: {excluded_path} ({len(excluded_rows)} rows)")
            _clip_logger.info("No URLs passed DNS gate; skipping hashing.")
            _clip_logger.info(
                "Anchor summary (shortlisted) | typo_anchor=0 | hash_anchor=0 | clip_anchor=0 | shortlisted=0"
            )
            _clip_logger.info(
                "Typo similarity summary (shortlisted) | min=0.0000 | avg=0.0000 | p95=0.0000 | max=0.0000 | typo_min_score=%.4f",
                scoring_config["typo_min_score"],
            )
            print("No URLs passed the DNS gate. Skipping hashing shortlist.")
            return _empty_shortlist_df()

        t0 = time.perf_counter()
        url_queue = asyncio.Queue()
        gpu_queue = asyncio.Queue(maxsize=GPU_QUEUE_MAXSIZE)
        results = []

        for u in shortlisted_urls:
            await url_queue.put(u)
        # Poison pills: one per worker coroutine across all shards
        for _ in range(BROWSER_SHARDS * SCRAPER_PAGE_CONCURRENCY):
            await url_queue.put(None)

        connector = aiohttp.TCPConnector(
            limit=_AIOHTTP_CONNECTOR_LIMIT, ttl_dns_cache=300
        ) if _has_aiohttp else None
        aio_session = aiohttp.ClientSession(
            connector=connector
        ) if _has_aiohttp else None

        try:
            from tqdm import tqdm
            progress_bar = tqdm(
                total=len(shortlisted_urls),
                desc="Hashing shortlist",
                unit="url",
                leave=True,
            )
        except ImportError:
            progress_bar = None

        try:
            # Install asyncio exception logging
            loop = asyncio.get_running_loop()
            _install_asyncio_exception_logging(loop)

            shard_tasks = [
                asyncio.create_task(
                    _run_browser_shard(
                        i,
                        url_queue,
                        gpu_queue,
                        metrics,
                        aio_session,
                        scoring_config,
                    )
                )
                for i in range(BROWSER_SHARDS)
            ]
            scorer_task = asyncio.create_task(
                _gpu_microbatch_scorer(
                    gpu_queue,
                    results,
                    metrics,
                    threshold,
                    scoring_config,
                )
            )

            # Monitor progress while shards are running
            last_processed = 0
            while not all(t.done() for t in shard_tasks):
                await asyncio.sleep(0.5)
                current = metrics["processed"]
                if progress_bar and current > last_processed:
                    progress_bar.update(current - last_processed)
                    progress_bar.set_postfix(
                        _build_progress_postfix(metrics), refresh=False
                    )
                    last_processed = current

            await asyncio.gather(*shard_tasks)

            # Final progress update before GPU flush
            if progress_bar:
                current = metrics["processed"]
                if current > last_processed:
                    progress_bar.update(current - last_processed)
                    progress_bar.set_postfix(
                        _build_progress_postfix(metrics), refresh=False
                    )

            # Signal scorer to flush remaining batch and exit
            await gpu_queue.put(None)
            await scorer_task

        finally:
            if progress_bar:
                progress_bar.close()
            if aio_session:
                await aio_session.close()

        elapsed = time.perf_counter() - t0
        print(
            f"\nHashing shortlist completed in {elapsed:.1f}s "
            f"({metrics['processed']} processed, "
            f"{metrics['final_matches_above_threshold']} matched)"
        )
        print(
            "Hashing metrics: "
            f"passed_dns_gate={metrics['passed_dns_gate']} "
            f"processed={metrics['processed']} "
            f"hashed_success={metrics['hashed_success']} "
            f"fetch_failed={metrics['fetch_failed']} "
            f"fetch_timed_out={metrics['fetch_timed_out']} "
            f"gpu_batches_flushed={metrics['gpu_batches_flushed']} "
            f"avg_gpu_batch_size={metrics['avg_gpu_batch_size']:.1f} "
            f"final_matches={metrics['final_matches_above_threshold']}"
        )
        _log_hashing_metrics_summary(
            metrics,
            elapsed,
            threshold,
            shortlisted_results=results,
            typo_min_score=scoring_config["typo_min_score"],
        )

        rows = []
        for match in results:
            target_url = match["url"]
            best_entity = match["best_entity"]
            best_score = float(match["best_score"])
            legit_domain = "Unknown"
            parsed = urlparse(normalize_url(target_url))
            target_domain = parsed.netloc.lower()
            try:
                best_idx = _entity_index["names"].index(best_entity)
                entity_domains = _entity_index["domains"][best_idx]
                if entity_domains:
                    legit_domain = max(
                        entity_domains,
                        key=lambda d: domain_similarity(target_domain, d),
                    )
            except ValueError:
                pass

            rows.append({
                "Cooresponding CSE": best_entity,
                "Legitimate Domains": legit_domain,
                "Identified Phishing/Suspected Domain Name": target_url,
                "hash_score": round(best_score, 4),
                "confidence_band": match["confidence_band"],
                "score_margin": round(float(match["score_margin"]), 4),
                "evidence_tier": match.get("evidence_tier", "weak_evidence"),
                "lexical_score": round(float(match.get("lexical_score", 0.0)), 4),
                "jw_primary": round(float(match.get("jw_primary", 0.0)), 4),
                "token_set_primary": round(float(match.get("token_set_primary", 0.0)), 4),
                "skeleton_similarity": round(float(match.get("skeleton_similarity", 0.0)), 4),
                "lexical_rule_hit": bool(match.get("lexical_rule_hit", False)),
                "brand_token_hit": bool(match.get("brand_token_hit", False)),
                "candidate_generation_reason": match.get("candidate_generation_reason", ""),
                "dominant_signal_family": match.get("dominant_signal_family", "lexical"),
                "typo_similarity": round(float(match.get("typo_similarity", 0.0)), 4),
                "typo_min_score_used": round(float(scoring_config["typo_min_score"]), 4),
                "typo_decision_reason": (
                    "anchor_typo" if bool(match.get("typo_anchor", False)) else "below_min_score"
                ),
                "clip_similarity": round(float(match.get("clip_similarity", 0.0)), 4),
                "typo_anchor": bool(match.get("typo_anchor", False)),
                "hash_anchor": bool(match.get("hash_anchor", False)),
                "clip_anchor": bool(match.get("clip_anchor", False)),
                "signal_hit_screenshot": bool(match["signal_hit_screenshot"]),
                "signal_hit_typo": bool(match.get("signal_hit_typo", False)),
                "signal_hit_domain": bool(match["signal_hit_domain"]),
                "signal_hit_favicon": bool(match["signal_hit_favicon"]),
                "signal_hit_ssl_hash": bool(match["signal_hit_ssl_hash"]),
                "signal_hit_html_hash": bool(match["signal_hit_html_hash"]),
                "signal_hit_domain_hash": bool(match["signal_hit_domain_hash"]),
                "signal_hit_keywords": bool(match["signal_hit_keywords"]),
                "screenshot_path": match.get("screenshot_path", ""),
            })

        matched_urls = [match["url"] for match in results]
        excluded_rows = _build_excluded_url_rows(
            input_urls,
            audit_rows,
            matched_urls=matched_urls,
        )
        excluded_path = _write_excluded_urls_audit(excluded_rows)
        _clip_logger.info(
            "Excluded URL audit written to %s with %d rows",
            excluded_path,
            len(excluded_rows),
        )
        print(f"Excluded URLs: {excluded_path} ({len(excluded_rows)} rows)")

        if not rows:
            return _empty_shortlist_df()
        return pd.DataFrame(rows)

    except Exception:
        _clip_logger.exception("Hashing shortlist (streaming) crashed.")
        raise
    finally:
        _close_hashing_log()


###############################################
# PUBLIC API
###############################################

def run_hashing_shortlist(
    url_list,
    threshold=DEFAULT_HASHING_THRESHOLD,
    domain_similarity_threshold=DEFAULT_DOMAIN_SIMILARITY_THRESHOLD,
    high_confidence_threshold=DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
    medium_confidence_threshold=DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD,
    typo_top_k=DEFAULT_TYPO_TOP_K,
    typo_min_score=DEFAULT_TYPO_MIN_SCORE,
    clip_margin_min=DEFAULT_CLIP_MARGIN_MIN,
    dns_timeout=None,
    dns_retries=None,
    dns_max_workers=None,
    weights=None,
):
    """Synchronous entry point for hashing shortlist."""
    return asyncio.run(
        run_hashing_shortlist_streaming(
            url_list,
            threshold=threshold,
            domain_similarity_threshold=domain_similarity_threshold,
            high_confidence_threshold=high_confidence_threshold,
            medium_confidence_threshold=medium_confidence_threshold,
            typo_top_k=typo_top_k,
            typo_min_score=typo_min_score,
            clip_margin_min=clip_margin_min,
            dns_timeout=dns_timeout,
            dns_retries=dns_retries,
            dns_max_workers=dns_max_workers,
            weights=weights,
        )
    )


async def run_hashing_shortlist_async(
    url_list,
    threshold=DEFAULT_HASHING_THRESHOLD,
    domain_similarity_threshold=DEFAULT_DOMAIN_SIMILARITY_THRESHOLD,
    high_confidence_threshold=DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
    medium_confidence_threshold=DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD,
    typo_top_k=DEFAULT_TYPO_TOP_K,
    typo_min_score=DEFAULT_TYPO_MIN_SCORE,
    clip_margin_min=DEFAULT_CLIP_MARGIN_MIN,
    dns_timeout=None,
    dns_retries=None,
    dns_max_workers=None,
    weights=None,
):
    """Async entry point for hashing shortlist."""
    return await run_hashing_shortlist_streaming(
        url_list,
        threshold=threshold,
        domain_similarity_threshold=domain_similarity_threshold,
        high_confidence_threshold=high_confidence_threshold,
        medium_confidence_threshold=medium_confidence_threshold,
        typo_top_k=typo_top_k,
        typo_min_score=typo_min_score,
        clip_margin_min=clip_margin_min,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        dns_max_workers=dns_max_workers,
        weights=weights,
    )


if __name__ == "__main__":
    test_urls = [
        "https://www.onlinesbi.sbi/",
        "http://airtel.in",
        "http://myjio.login.com",
    ]
    df = run_hashing_shortlist(test_urls)
    print(df)
