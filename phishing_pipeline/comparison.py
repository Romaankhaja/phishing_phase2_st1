import json
import hashlib
import numbers
import re
import ssl
import tldextract
import httpx
from concurrent.futures import ProcessPoolExecutor
from collections import Counter
from functools import partial
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
from datetime import datetime, timezone
import logging as _logging
import warnings as _warnings
import unicodedata
import psutil
from contextlib import suppress
try:
    import resource as _resource
except Exception:
    _resource = None
from .config import HASH_EXPORT_DIR, STAGE1_HTTP_CONFIG, resolve_stage1_http_config
from .similarity_hashing import (
    SIMHASH_BITS,
    best_similarity_against_set,
    compute_domain_simhash,
    compute_image_phash,
    compute_ssl_simhash,
)
from .stage1_http_analyzer import (
    _default_stage1_result,
    analyze_stage1_url,
    build_stage1_concurrency_controls,
    enrich_stage1_result,
    fetch_stage1_http_artifacts,
    get_stage1_entity_context,
    parse_stage1_html_payload,
    score_stage1_http_signals,
    should_enrich_stage1_result,
)
from .reliability import (
    CheckpointStore,
    ProgressTracker,
    RunContext,
    StageWatchdog,
    async_with_timeout_and_retry,
    make_record_key,
    normalize_exception,
    stage_result_patch,
    utc_now_iso,
)
from .shortlisting import (
    normalize_url as _legacy_normalize_url,
    get_primary_part as _legacy_get_primary_part,
    is_similar_advanced as _legacy_is_similar_advanced,
)

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
_GENERIC_SERVICE_TOKENS = {
    "mail",
    "cloud",
    "login",
    "portal",
    "secure",
    "account",
    "service",
    "bank",
}
_GENERIC_ENTITY_NAME_TOKENS = {
    "authority",
    "board",
    "centre",
    "center",
    "commission",
    "committee",
    "corporation",
    "council",
    "department",
    "directorate",
    "government",
    "india",
    "indian",
    "limited",
    "ltd",
    "ministry",
    "mission",
    "national",
    "office",
    "official",
    "online",
    "portal",
    "private",
    "public",
    "service",
    "services",
    "state",
    "states",
    "union",
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


def _read_env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        _clip_logger.warning("Invalid float override for %s=%r; using %.3f", name, raw, default)
        return default


def _read_env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    _clip_logger.warning("Invalid boolean override for %s=%r; using %s", name, raw, default)
    return default


def _read_env_int_alias(names: tuple[str, ...], default: int, minimum: int = 1) -> int:
    for name in names:
        raw = os.getenv(name)
        if raw in (None, ""):
            continue
        try:
            return max(minimum, int(raw))
        except ValueError:
            _clip_logger.warning("Invalid integer override for %s=%r; using %d", name, raw, default)
            return default
    return default


def _read_env_float_alias(names: tuple[str, ...], default: float, minimum: float = 0.0) -> float:
    for name in names:
        raw = os.getenv(name)
        if raw in (None, ""):
            continue
        try:
            return max(minimum, float(raw))
        except ValueError:
            _clip_logger.warning("Invalid float override for %s=%r; using %.3f", name, raw, default)
            return default
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
_H100_SERVER_PROFILE = _SERVER_CLASS and _VRAM_GB >= 40

_default_max_pages = 24
_default_page_concurrency = 4

MAX_CONCURRENT_PAGES = _read_env_int("PHISHING_HASH_PAGES", _default_max_pages)
SCRAPER_PAGE_CONCURRENCY = min(
    MAX_CONCURRENT_PAGES,
    _read_env_int("PHISHING_HASH_PAGE_CONCURRENCY", _default_page_concurrency),
)
BROWSER_SHARDS = max(1, math.ceil(MAX_CONCURRENT_PAGES / SCRAPER_PAGE_CONCURRENCY))
HASH_PAGES_PER_NODE = SCRAPER_PAGE_CONCURRENCY
HASH_WORKER_NODES_START = BROWSER_SHARDS
HASH_WORKER_NODES_MAX = BROWSER_SHARDS
HASH_ACTIVE_PAGES_START = MAX_CONCURRENT_PAGES
HASH_ACTIVE_PAGES_MAX = MAX_CONCURRENT_PAGES
HASH_RENDER_WORKER_COUNT = BROWSER_SHARDS * SCRAPER_PAGE_CONCURRENCY
_default_nav_timeout_ms = 15000
_default_screenshot_timeout_ms = 6000
_default_fetch_timeout_s = 20.0
SCRAPER_NAV_TIMEOUT_MS = _read_env_int("PHISHING_HASH_NAV_TIMEOUT_MS", _default_nav_timeout_ms)
SCRAPER_SCREENSHOT_TIMEOUT_MS = _read_env_int("PHISHING_HASH_SCREENSHOT_TIMEOUT_MS", _default_screenshot_timeout_ms)
SCRAPER_FETCH_TIMEOUT_S = _read_env_float("PHISHING_HASH_FETCH_TIMEOUT_S", _default_fetch_timeout_s, minimum=1.0)
HASH_RESULT_QUEUE_MAX = _read_env_int(
    "PHISHING_HASH_RESULT_QUEUE_MAX",
    HASH_RENDER_WORKER_COUNT * 4,
)
GPU_QUEUE_MAXSIZE = _read_env_int(
    "PHISHING_GPU_QUEUE_MAXSIZE",
    BROWSER_SHARDS * SCRAPER_PAGE_CONCURRENCY * (4 if _SERVER_CLASS else 2),
)
GPU_MAX_WAIT_MS = _read_env_int("PHISHING_GPU_MAX_WAIT_MS", 120 if _H100_SERVER_PROFILE else (40 if _SERVER_CLASS else 50))
_default_http_limit = 96
_AIOHTTP_CONNECTOR_LIMIT = _read_env_int("PHISHING_HASH_HTTP_LIMIT", _default_http_limit)
HASH_AUX_HTTP_LIMIT = _AIOHTTP_CONNECTOR_LIMIT
ADAPTIVE_FETCH_DOWNSHIFT_ENABLED = _read_env_bool("PHISHING_HASH_ADAPTIVE_DOWNSHIFT", True)
ACTIVE_FETCH_LIMIT_INITIAL = MAX_CONCURRENT_PAGES
ACTIVE_FETCH_LIMIT_MAX = MAX_CONCURRENT_PAGES
ACTIVE_FETCH_LIMIT_FLOOR = min(
    MAX_CONCURRENT_PAGES,
    _read_env_int(
        "PHISHING_HASH_ACTIVE_PAGES_FLOOR",
        8,
    ),
)
ACTIVE_FETCH_DOWNSHIFT_STEP = 8 if _H100_SERVER_PROFILE else max(1, MAX_CONCURRENT_PAGES // 4)
ACTIVE_FETCH_UPSHIFT_STEP = ACTIVE_FETCH_DOWNSHIFT_STEP
HASH_RAMP_INTERVAL_SECONDS = 15.0
HASH_RENDER_QUEUE_MAX = _read_env_int(
    "PHISHING_HASH_RENDER_QUEUE_MAX",
    HASH_RENDER_WORKER_COUNT * 128,
)
_default_aux_net_limit = 48
AUX_NET_CONCURRENCY_LIMIT = _read_env_int("PHISHING_HASH_AUX_NET_LIMIT", _default_aux_net_limit)
HASH_AUX_SSL_LIMIT = _read_env_int(
    "PHISHING_HASH_AUX_SSL_LIMIT",
    64,
)
HASH_PER_HOST_LIMIT = _read_env_int(
    "PHISHING_HASH_PER_HOST_LIMIT",
    4,
)
HASH_PROGRESS_LOG_INTERVAL_SECONDS = _read_env_int(
    "PHISHING_HASH_PROGRESS_LOG_INTERVAL_SECONDS",
    10,
)
HASH_TARGET_URLS_PER_SEC = _read_env_float_alias(
    ("PHISHING_HASH_TARGET_URLS_PER_SEC",),
    float(MAX_CONCURRENT_PAGES),
    minimum=0.0,
)
ADAPTIVE_FETCH_MIN_PROCESSED = 500
ADAPTIVE_FETCH_PRESSURE_WINDOWS = 2
GPU_QUEUE_BACKLOG_THRESHOLD = max(4, GPU_QUEUE_MAXSIZE // 4)


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
    "Hash shortlist parallelism: pages=%d, shard_workers=%d, shards=%d, nav_timeout_ms=%d, screenshot_timeout_ms=%d, fetch_timeout_s=%.1f, gpu_batch=%d, gpu_queue=%d, http_limit=%d, active_fetch_limit=%d, active_fetch_floor=%d, aux_net_limit=%d, adaptive_downshift=%s",
    MAX_CONCURRENT_PAGES,
    SCRAPER_PAGE_CONCURRENCY,
    BROWSER_SHARDS,
    SCRAPER_NAV_TIMEOUT_MS,
    SCRAPER_SCREENSHOT_TIMEOUT_MS,
    SCRAPER_FETCH_TIMEOUT_S,
    GPU_MAX_BATCH_SIZE,
    GPU_QUEUE_MAXSIZE,
    _AIOHTTP_CONNECTOR_LIMIT,
    ACTIVE_FETCH_LIMIT_INITIAL,
    ACTIVE_FETCH_LIMIT_FLOOR,
    AUX_NET_CONCURRENCY_LIMIT,
    ADAPTIVE_FETCH_DOWNSHIFT_ENABLED,
)


class _AdaptiveFetchLimiter:
    def __init__(self, initial_limit: int):
        self._limit = max(1, int(initial_limit))
        self._active = 0
        self._condition = asyncio.Condition()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def active(self) -> int:
        return self._active

    async def acquire(self):
        async with self._condition:
            while self._active >= self._limit:
                await self._condition.wait()
            self._active += 1

    async def release(self):
        async with self._condition:
            if self._active > 0:
                self._active -= 1
            self._condition.notify_all()

    async def set_limit(self, new_limit: int):
        async with self._condition:
            self._limit = max(1, int(new_limit))
            self._condition.notify_all()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.release()


def _compute_stage1_downshift(
    *,
    current_limit: int,
    floor_limit: int,
    step: int,
    processed_total: int,
    window_processed: int,
    window_failed: int,
    window_timed_out: int,
    gpu_queue_depth: int,
    gpu_backlog_threshold: int,
    consecutive_pressure_windows: int,
) -> dict:
    timeout_ratio = window_timed_out / max(1, window_processed)
    failure_ratio = (window_failed + window_timed_out) / max(1, window_processed)
    queue_clear = gpu_queue_depth <= gpu_backlog_threshold
    over_threshold = (
        processed_total >= ADAPTIVE_FETCH_MIN_PROCESSED
        and window_processed > 0
        and queue_clear
        and (
            timeout_ratio >= 0.35
            or failure_ratio >= 0.70
        )
    )

    if not over_threshold:
        return {
            "next_limit": current_limit,
            "next_consecutive_pressure_windows": 0,
            "should_downshift": False,
            "timeout_ratio": timeout_ratio,
            "failure_ratio": failure_ratio,
        }

    next_consecutive = consecutive_pressure_windows + 1
    if next_consecutive < ADAPTIVE_FETCH_PRESSURE_WINDOWS or current_limit <= floor_limit:
        return {
            "next_limit": current_limit,
            "next_consecutive_pressure_windows": next_consecutive,
            "should_downshift": False,
            "timeout_ratio": timeout_ratio,
            "failure_ratio": failure_ratio,
        }

    return {
        "next_limit": max(floor_limit, current_limit - step),
        "next_consecutive_pressure_windows": 0,
        "should_downshift": current_limit > floor_limit,
        "timeout_ratio": timeout_ratio,
        "failure_ratio": failure_ratio,
    }


def _compute_hash_fetch_adjustment(
    *,
    current_limit: int,
    max_limit: int,
    floor_limit: int,
    step: int,
    processed_total: int,
    window_processed: int,
    window_failed: int,
    window_timed_out: int,
    render_queue_depth: int,
    aux_queue_depth: int,
    finalize_queue_depth: int,
    result_queue_max: int,
    fd_usage_ratio: float,
    ram_usage_ratio: float,
    consecutive_pressure_windows: int,
    consecutive_healthy_windows: int,
) -> dict:
    timeout_ratio = window_timed_out / max(1, window_processed)
    failure_ratio = (window_failed + window_timed_out) / max(1, window_processed)
    queue_pressure_ratio = (
        max(render_queue_depth, aux_queue_depth, finalize_queue_depth) / max(1, result_queue_max)
    )
    over_threshold = (
        processed_total >= ADAPTIVE_FETCH_MIN_PROCESSED
        and window_processed > 0
        and (
            timeout_ratio >= 0.35
            or failure_ratio >= 0.70
            or queue_pressure_ratio >= 0.75
            or fd_usage_ratio >= 0.70
            or ram_usage_ratio >= 0.75
        )
    )
    healthy_window = (
        window_processed > 0
        and timeout_ratio < 0.20
        and failure_ratio < 0.30
        and queue_pressure_ratio < 0.40
        and fd_usage_ratio < 0.70
        and ram_usage_ratio < 0.75
    )

    if not over_threshold:
        next_healthy = consecutive_healthy_windows + 1 if healthy_window else 0
        should_upshift = (
            current_limit < max_limit
            and next_healthy >= 2
            and processed_total >= ADAPTIVE_FETCH_MIN_PROCESSED
        )
        return {
            "next_limit": min(max_limit, current_limit + step) if should_upshift else current_limit,
            "next_consecutive_pressure_windows": 0,
            "next_consecutive_healthy_windows": 0 if should_upshift else next_healthy,
            "should_downshift": False,
            "should_upshift": should_upshift,
            "timeout_ratio": timeout_ratio,
            "failure_ratio": failure_ratio,
            "queue_pressure_ratio": queue_pressure_ratio,
        }

    next_consecutive = consecutive_pressure_windows + 1
    if next_consecutive < ADAPTIVE_FETCH_PRESSURE_WINDOWS or current_limit <= floor_limit:
        return {
            "next_limit": current_limit,
            "next_consecutive_pressure_windows": next_consecutive,
            "next_consecutive_healthy_windows": 0,
            "should_downshift": False,
            "should_upshift": False,
            "timeout_ratio": timeout_ratio,
            "failure_ratio": failure_ratio,
            "queue_pressure_ratio": queue_pressure_ratio,
        }

    return {
        "next_limit": max(floor_limit, current_limit - step),
        "next_consecutive_pressure_windows": 0,
        "next_consecutive_healthy_windows": 0,
        "should_downshift": current_limit > floor_limit,
        "should_upshift": False,
        "timeout_ratio": timeout_ratio,
        "failure_ratio": failure_ratio,
        "queue_pressure_ratio": queue_pressure_ratio,
    }


def _get_hash_runtime_resource_snapshot() -> dict:
    process = psutil.Process(os.getpid())
    memory_ratio = float(psutil.virtual_memory().percent) / 100.0
    fd_count = 0
    fd_limit = 0
    fd_ratio = 0.0
    try:
        if hasattr(process, "num_fds"):
            fd_count = int(process.num_fds())
        elif hasattr(process, "num_handles"):
            fd_count = int(process.num_handles())
    except Exception:
        fd_count = 0
    try:
        if _resource is not None and hasattr(_resource, "getrlimit"):
            soft_limit, _ = _resource.getrlimit(_resource.RLIMIT_NOFILE)
            if soft_limit and soft_limit > 0:
                fd_limit = int(soft_limit)
                fd_ratio = fd_count / max(1, fd_limit)
    except Exception:
        fd_limit = 0
        fd_ratio = 0.0
    return {
        "fd_count": fd_count,
        "fd_limit": fd_limit,
        "fd_usage_ratio": fd_ratio,
        "ram_usage_ratio": memory_ratio,
    }


_aux_http_semaphore = None
_aux_ssl_semaphore = None


def _get_aux_http_semaphore():
    global _aux_http_semaphore
    if _aux_http_semaphore is None:
        _aux_http_semaphore = asyncio.Semaphore(HASH_AUX_HTTP_LIMIT)
    return _aux_http_semaphore


def _get_aux_ssl_semaphore():
    global _aux_ssl_semaphore
    if _aux_ssl_semaphore is None:
        _aux_ssl_semaphore = asyncio.Semaphore(HASH_AUX_SSL_LIMIT)
    return _aux_ssl_semaphore


class _PerHostLimiter:
    def __init__(self, per_host_limit: int):
        self._per_host_limit = max(1, int(per_host_limit))
        self._lock = asyncio.Lock()
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    async def acquire(self, host: str) -> asyncio.Semaphore:
        normalized = str(host or "").strip().lower() or "__blank__"
        async with self._lock:
            semaphore = self._semaphores.get(normalized)
            if semaphore is None:
                semaphore = asyncio.Semaphore(self._per_host_limit)
                self._semaphores[normalized] = semaphore
        await semaphore.acquire()
        return semaphore

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

def _load_entity_db():
    with open(os.path.join(os.path.dirname(BASE_DIR), "data", "entity_hash_db.json"), encoding="utf-8") as fh:
        raw_data = json.load(fh)
    if not isinstance(raw_data, dict):
        raise ValueError("entity_hash_db.json must contain a top-level object")
    metadata = raw_data.get("_meta") if isinstance(raw_data.get("_meta"), dict) else {}
    entities = {
        key: value
        for key, value in raw_data.items()
        if key != "_meta" and isinstance(value, dict)
    }
    return entities, metadata


entity_db, _entity_db_meta = _load_entity_db()
_USE_SIMILARITY_HASHING = int(_entity_db_meta.get("hash_schema_version", 1) or 1) >= 2


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

DEFAULT_HASHING_THRESHOLD = 58.0
DEFAULT_DOMAIN_SIMILARITY_THRESHOLD = 0.85
DEFAULT_HIGH_CONFIDENCE_THRESHOLD = 78.0
DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD = 68.0
DEFAULT_TYPO_TOP_K = 10
DEFAULT_TYPO_MIN_SCORE = 0.75
DEFAULT_LEXICAL_PASS_MIN_SCORE = 0.85
DEFAULT_CLIP_MARGIN_MIN = 0.20
DEFAULT_CLIP_STRONG_SIMILARITY = 0.97
DEFAULT_CONTENT_SPOOF_STRONG_DIRECT_BRAND_MIN = 3
DEFAULT_STAGE1_DEBUG_CSV = os.path.join(ROOT_DIR, "output", "stage1_lexical_debug.csv")
STAGE1_METHODS_DEBUG_PATH = os.path.join(ROOT_DIR, "output", "stage1_methods_debug.csv")
STAGE1_DEEP_ANALYSIS_CANDIDATES_PATH = os.path.join(ROOT_DIR, "output", "stage1_deep_analysis_candidates.csv")
FETCH_FAILED_LEXICAL_HITS_PATH = os.path.join(ROOT_DIR, "output", "fetch_failed_lexical_hits.csv")
STAGE1_REVIEW_QUEUE_PATH = os.path.join(ROOT_DIR, "output", "hash_review_queue.csv")
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
_HASH_SIMILARITY_BITS = SIMHASH_BITS
_FAVICON_HASH_HIT_DISTANCE = 8
_FAVICON_HASH_ANCHOR_DISTANCE = 4
_PAGE_HASH_HIT_DISTANCE = 10
_PAGE_HASH_ANCHOR_DISTANCE = 5
_SSL_HASH_HIT_DISTANCE = 8
_SSL_HASH_ANCHOR_DISTANCE = 3
_DOMAIN_HASH_HIT_DISTANCE = 6


def _format_weights_for_logging(weights: dict) -> str:
    return ", ".join(f"{key}={weights[key]:g}" for key in _SCORING_WEIGHT_KEYS)


def _normalize_source_workbook_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        ordered = []
        seen = set()
        for item in value:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            ordered.append(text)
        return "|".join(ordered)
    return str(value or "").strip()


def _resolve_source_workbook_map(url_sources: dict | None) -> dict[str, str]:
    resolved = {}
    for raw_url, raw_value in (url_sources or {}).items():
        normalized_url = normalize_url(str(raw_url or "").strip()) if raw_url else ""
        if not normalized_url:
            continue
        resolved[normalized_url] = _normalize_source_workbook_value(raw_value)
    return resolved


def _upsert_shortlist_checkpoint(
    *,
    run_context: RunContext | None,
    checkpoint_store: CheckpointStore | None,
    raw_url: str,
    normalized_url: str,
    source_workbook: str,
    stage_name: str,
    stage_status: str,
    current_stage: str | None = None,
    retry_count: int = 0,
    timeout_hit: bool = False,
    fallback_taken: str = "",
    worker_id: str = "",
    error_type: str = "",
    error_message: str = "",
    final_pipeline_status: str | None = None,
    failure_reason: str | None = None,
) -> None:
    if checkpoint_store is None or run_context is None:
        return
    checkpoint_store.upsert_url_result(
        stage_result_patch(
            run_id=run_context.run_id,
            raw_url=raw_url,
            normalized_url=normalized_url,
            source_workbook=source_workbook,
            stage_name=stage_name,
            stage_status=stage_status,
            current_stage=current_stage or stage_name,
            retry_count=retry_count,
            timeout_hit=timeout_hit,
            fallback_taken=fallback_taken,
            worker_id=worker_id,
            error_type=error_type,
            error_message=error_message,
            final_pipeline_status=final_pipeline_status,
            failure_reason=failure_reason,
        )
    )


def _append_shortlist_stage_event(
    *,
    run_context: RunContext | None,
    checkpoint_store: CheckpointStore | None,
    raw_url: str,
    normalized_url: str,
    source_workbook: str,
    stage_name: str,
    worker_id: str,
    started_at: str,
    started_monotonic: float,
    status: str,
    retry_count: int = 0,
    timeout_flag: bool = False,
    error_type: str = "",
    error_message: str = "",
    fallback_taken: str = "",
) -> None:
    if checkpoint_store is None or run_context is None:
        return
    checkpoint_store.append_stage_event(
        {
            "run_id": run_context.run_id,
            "record_key": make_record_key(normalized_url, source_workbook),
            "source_workbook": source_workbook,
            "normalized_url": normalized_url,
            "stage_name": stage_name,
            "attempt_index": max(1, int(retry_count) + 1),
            "worker_id": worker_id,
            "started_at": started_at,
            "finished_at": utc_now_iso(),
            "duration_ms": int(max(0.0, (time.perf_counter() - started_monotonic) * 1000.0)),
            "status": status,
            "error_type": error_type,
            "error_message": error_message,
            "retry_count": int(retry_count),
            "timeout_flag": int(bool(timeout_flag)),
            "fallback_taken": fallback_taken,
        }
    )


def _coerce_optional_stage1_threshold(
    name: str,
    value,
) -> int | None:
    if value is None:
        return None
    if not isinstance(value, numbers.Real):
        raise ValueError(f"{name} must be numeric")
    coerced = int(value)
    if coerced < 0:
        raise ValueError(f"{name} must be non-negative")
    return coerced


def _resolve_stage1_runtime_config(
    *,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
) -> dict:
    overrides = {
        "escalate_total_threshold": _coerce_optional_stage1_threshold(
            "stage1_escalate_total_threshold",
            stage1_escalate_total_threshold,
        ),
        "brand_min": _coerce_optional_stage1_threshold(
            "stage1_brand_min",
            stage1_brand_min,
        ),
        "credential_min": _coerce_optional_stage1_threshold(
            "stage1_credential_min",
            stage1_credential_min,
        ),
        "low_band_min": _coerce_optional_stage1_threshold(
            "stage1_low_band_min",
            stage1_low_band_min,
        ),
        "hard_trigger_brand_min": _coerce_optional_stage1_threshold(
            "stage1_hard_trigger_brand_min",
            stage1_hard_trigger_brand_min,
        ),
    }
    return resolve_stage1_http_config(overrides)


def _resolve_scoring_config(
    weights: dict | None = None,
    domain_similarity_threshold: float = DEFAULT_DOMAIN_SIMILARITY_THRESHOLD,
    high_confidence_threshold: float = DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
    medium_confidence_threshold: float = DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD,
    typo_top_k: int = DEFAULT_TYPO_TOP_K,
    typo_min_score: float = DEFAULT_TYPO_MIN_SCORE,
    lexical_pass_min_score: float = DEFAULT_LEXICAL_PASS_MIN_SCORE,
    clip_margin_min: float = DEFAULT_CLIP_MARGIN_MIN,
    keep_stage1_suspected: bool = False,
    keep_fetch_failed_strict_lexical: bool = False,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
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
    if not isinstance(lexical_pass_min_score, numbers.Real):
        raise ValueError("lexical_pass_min_score must be numeric")
    lexical_pass_min_score = float(lexical_pass_min_score)
    if lexical_pass_min_score < 0 or lexical_pass_min_score > 1:
        raise ValueError("lexical_pass_min_score must be in [0, 1]")
    if not isinstance(clip_margin_min, numbers.Real):
        raise ValueError("clip_margin_min must be numeric")
    clip_margin_min = float(clip_margin_min)
    if clip_margin_min < 0:
        raise ValueError("clip_margin_min must be non-negative")
    keep_stage1_suspected = bool(keep_stage1_suspected)
    keep_fetch_failed_strict_lexical = bool(keep_fetch_failed_strict_lexical)

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

    stage1_http_config = _resolve_stage1_runtime_config(
        stage1_escalate_total_threshold=stage1_escalate_total_threshold,
        stage1_brand_min=stage1_brand_min,
        stage1_credential_min=stage1_credential_min,
        stage1_low_band_min=stage1_low_band_min,
        stage1_hard_trigger_brand_min=stage1_hard_trigger_brand_min,
    )

    return {
        "weights": resolved_weights,
        "total_weight": total_weight,
        "domain_similarity_threshold": domain_similarity_threshold,
        "high_confidence_threshold": high_confidence_threshold,
        "medium_confidence_threshold": medium_confidence_threshold,
        "typo_top_k": typo_top_k,
        "typo_min_score": typo_min_score,
        "lexical_pass_min_score": lexical_pass_min_score,
        "clip_margin_min": clip_margin_min,
        "clip_similarity_floor": DEFAULT_CLIP_STRONG_SIMILARITY,
        "keep_stage1_suspected": keep_stage1_suspected,
        "keep_fetch_failed_strict_lexical": keep_fetch_failed_strict_lexical,
        "stage1_http_config": stage1_http_config,
    }


_DEFAULT_SCORING_CONFIG = _resolve_scoring_config()

# Backward-compat aliases retained for external imports.
WEIGHTS = dict(_DEFAULT_SCORING_CONFIG["weights"])
_TOTAL_WEIGHT = _DEFAULT_SCORING_CONFIG["total_weight"]

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _resolve_effective_headless_target(
    normalized_url: str,
    final_landing_url: str = "",
    *,
    original_domain: str = "",
) -> tuple[str, str]:
    effective_url = str(final_landing_url or normalized_url or "").strip()
    effective_domain = (urlparse(effective_url).hostname or str(original_domain or "").strip()).strip().lower()
    return effective_url, effective_domain


def _collapse_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _is_generic_service_token(token: str) -> bool:
    token = str(token or "").strip().lower()
    return bool(token) and (token in _GENERIC_DOMAIN_PARTS or token in _GENERIC_SERVICE_TOKENS)


def _configure_hashing_log(log_path: str = HASHING_LOG_PATH) -> str:
    return _ensure_hashing_log(log_path=log_path, reset=True)


def _ensure_hashing_log(log_path: str = HASHING_LOG_PATH, reset: bool = False) -> str:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    target_loggers = (
        _clip_logger,
        _logging.getLogger("py.warnings"),
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


def _passes_lexical_gate(prefetch_metrics: dict) -> bool:
    strict_lexical_hit = bool(prefetch_metrics.get("strict_lexical_hit", False))
    lexical_score_pass = bool(prefetch_metrics.get("lexical_score_pass", False))
    fallback_rank_only = bool(prefetch_metrics.get("fallback_rank_only", False))
    return bool(strict_lexical_hit or (lexical_score_pass and not fallback_rank_only))


def _classify_fetch_exception(exc: Exception, stage: str) -> tuple[str, str, bool]:
    detail = _compact_exception_message(exc)
    exception_name = exc.__class__.__name__
    text = f"{exception_name}: {detail}".lower()

    if "timeout" in text:
        retryable = stage == "navigation"
        return f"{stage}_timeout", detail, retryable

    if any(
        marker in text
        for marker in (
            "targetclosederror",
            "target page, context or browser has been closed",
            "page was closed",
            "frame was detached",
            "net::err_aborted",
            "page is navigating",
            "navigation failed because page was closed",
        )
    ):
        return f"{stage}_transient_browser_error", detail, True

    if any(
        marker in text
        for marker in (
            "net::err_ssl_protocol_error",
            "net::err_ssl_version_or_cipher_mismatch",
            "ssl protocol error",
            "ssl version or cipher mismatch",
        )
    ):
        return "ssl_error", detail, False

    if "net::err_connection_reset" in text:
        return "connection_reset", detail, True

    return f"{stage}_error", detail, False


def _build_fetch_failure_payload(
    url: str,
    normalized_url: str,
    *,
    fetch_status: str,
    visual_status: str = "not_attempted",
    error_type: str = "",
    error_detail: str = "",
) -> dict:
    return {
        "url": url,
        "normalized_url": normalized_url,
        "fetch_status": fetch_status,
        "visual_status": visual_status,
        "fetch_error_type": error_type,
        "fetch_error_detail": error_detail,
        "final_landing_url": "",
        "parking_provider": "",
        "parking_reason": "",
    }


_PARKED_PROVIDER_HOST_HINTS = {
    "hugedomains": "HugeDomains",
    "sedo": "Sedo",
    "afternic": "Afternic",
    "dan.com": "Dan",
    "undeveloped": "Dan",
    "bodis": "Bodis",
    "parkingcrew": "ParkingCrew",
    "smartname": "SmartName",
    "above.com": "Above.com",
}

_PARKED_PROVIDER_TEXT_HINTS = {
    "hugedomains": "HugeDomains",
    "sedo": "Sedo",
    "afternic": "Afternic",
    "dan.com": "Dan",
    "bodis": "Bodis",
    "parkingcrew": "ParkingCrew",
    "smartname": "SmartName",
}

_PARKED_SALE_TEXT_PATTERNS = (
    "buy this domain",
    "this domain is for sale",
    "domain is for sale",
    "purchase this domain",
    "make an offer",
    "inquire about this domain",
    "domain may be for sale",
    "own this domain",
    "get this domain",
)


def _extract_candidate_host(url: str) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    try:
        return (urlparse(text).hostname or "").strip().lower()
    except Exception:
        return ""


def _detect_parked_sale_signal(
    *,
    final_landing_url: str = "",
    title_text: str = "",
    visible_text: str = "",
) -> tuple[str, str]:
    landing_host = _extract_candidate_host(final_landing_url)
    full_text = " ".join(
        part.strip().lower()
        for part in (str(title_text or ""), str(visible_text or ""))
        if str(part or "").strip()
    )

    for host_hint, provider_name in _PARKED_PROVIDER_HOST_HINTS.items():
        if host_hint in landing_host:
            return provider_name, "provider_hosted_parking_redirect"

    for text_hint, provider_name in _PARKED_PROVIDER_TEXT_HINTS.items():
        if text_hint in full_text:
            return provider_name, "provider_branded_parking_template"

    if any(pattern in full_text for pattern in _PARKED_SALE_TEXT_PATTERNS):
        return "", "parking_or_sale_keywords"

    return "", ""


def _has_suspicious_fetch_network_state(
    fetch_status: str,
    *,
    fetch_error_type: str = "",
    fetch_error_detail: str = "",
) -> bool:
    status = str(fetch_status or "").strip().lower()
    if status in {"failed", "timeout"}:
        return True

    detail = " ".join(
        part.strip().lower()
        for part in (str(fetch_error_type or ""), str(fetch_error_detail or ""))
        if str(part or "").strip()
    )
    if not detail:
        return False
    suspicious_markers = (
        "err_name_not_resolved",
        "err_connection_refused",
        "no_records",
        "nxdomain",
        "not_registered",
        "not registered",
        "dns",
    )
    return any(marker in detail for marker in suspicious_markers)


def _has_stage1_signal_seed(stage1_analysis: dict | None) -> bool:
    stage1_analysis = stage1_analysis or {}
    if bool(stage1_analysis.get("candidate_entities")):
        return True
    if bool(stage1_analysis.get("hard_trigger_hit", False)):
        return True
    if any(
        int(stage1_analysis.get(field, 0) or 0) > 0
        for field in (
            "brand_score",
            "credential_score",
            "infra_score",
            "evasion_score",
            "total_stage1_score",
        )
    ):
        return True
    return bool(str(stage1_analysis.get("parking_reason", "") or "").strip())


def _has_high_risk_prefetch_lexical_seed(
    prefetch_metrics: dict | None,
    scoring_config: dict | None,
) -> bool:
    prefetch_metrics = prefetch_metrics or {}
    scoring_config = scoring_config or _DEFAULT_SCORING_CONFIG
    if bool(prefetch_metrics.get("fallback_rank_only", False)):
        return False

    strict_lexical_hit = bool(prefetch_metrics.get("strict_lexical_hit", False))
    lexical_score_pass = bool(prefetch_metrics.get("lexical_score_pass", False))
    old_fuzzy_hit = bool(prefetch_metrics.get("old_fuzzy_hit", False))
    try:
        best_lexical_score = float(prefetch_metrics.get("best_lexical_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        best_lexical_score = 0.0
    try:
        best_typo_similarity = float(prefetch_metrics.get("best_typo_similarity", 0.0) or 0.0)
    except (TypeError, ValueError):
        best_typo_similarity = 0.0
    typo_min_score = float(scoring_config.get("typo_min_score", _DEFAULT_SCORING_CONFIG["typo_min_score"]) or _DEFAULT_SCORING_CONFIG["typo_min_score"])
    lexical_pass_min = float(scoring_config.get("lexical_pass_min_score", _DEFAULT_SCORING_CONFIG["lexical_pass_min_score"]) or _DEFAULT_SCORING_CONFIG["lexical_pass_min_score"])
    lexical_rescue_floor = max(0.70, lexical_pass_min - 0.10)
    typo_anchor = best_typo_similarity >= typo_min_score

    return bool(
        strict_lexical_hit
        or lexical_score_pass
        or old_fuzzy_hit
        or (typo_anchor and best_lexical_score >= lexical_rescue_floor)
    )


def _should_rescue_stage1_failure_to_hashing(
    prefetch_metrics: dict | None,
    stage1_analysis: dict | None,
    *,
    scoring_config: dict | None,
) -> bool:
    stage1_analysis = stage1_analysis or {}
    if not _has_suspicious_fetch_network_state(
        str(stage1_analysis.get("fetch_status", "") or ""),
        fetch_error_type=str(stage1_analysis.get("fetch_error_type", "") or ""),
        fetch_error_detail=str(stage1_analysis.get("fetch_error_detail", "") or ""),
    ):
        return False
    return bool(
        _has_high_risk_prefetch_lexical_seed(prefetch_metrics, scoring_config)
        or _has_stage1_signal_seed(stage1_analysis)
    )


def _should_retry_high_risk_hash_fetch(
    prefetch_metrics: dict | None,
    stage1_analysis: dict | None,
    *,
    scoring_config: dict | None,
) -> bool:
    return bool(
        _has_high_risk_prefetch_lexical_seed(prefetch_metrics, scoring_config)
        or _has_stage1_signal_seed(stage1_analysis)
    )


def _build_prefetch_decision_row(
    normalized_url: str,
    fetch_status: str,
    prefetch_metrics: dict,
    scoring_config: dict,
    raw_url: str = "",
    final_landing_url: str = "",
    screenshot_path: str = "",
    visual_status: str = "not_attempted",
    fetch_error_type: str = "",
    fetch_error_detail: str = "",
    parking_provider: str = "",
    parking_reason: str = "",
    stage1_analysis: dict | None = None,
) -> dict:
    strict_lexical_hit = bool(prefetch_metrics.get("strict_lexical_hit", False))
    lexical_score_pass = bool(prefetch_metrics.get("lexical_score_pass", False))
    fallback_rank_only = bool(prefetch_metrics.get("fallback_rank_only", False))
    fetch_status = str(fetch_status or "").strip().lower()
    stage1_analysis = stage1_analysis or {}

    lexical_contribution = float(prefetch_metrics.get("best_lexical_score", 0.0)) * scoring_config["weights"]["domain"]
    domain = (urlparse(normalized_url).hostname or "").strip().lower()
    final_domain = (urlparse(final_landing_url).hostname or "").strip().lower() if final_landing_url else domain
    decision_row = {
        "raw_url": str(raw_url or normalized_url),
        "normalized_url": normalized_url,
        "hashed_at_utc": utc_now_iso(),
        "target_url_sha256": sha256_text(normalized_url) if normalized_url else "",
        "hash_mode": _hash_mode_label(),
        "domain": domain,
        "final_domain": final_domain,
        "fetch_status": fetch_status,
        "visual_status": str(visual_status or "not_attempted"),
        "fetch_error_type": str(fetch_error_type or ""),
        "fetch_error_detail": str(fetch_error_detail or ""),
        "final_landing_url": final_landing_url,
        "parking_provider": str(parking_provider or ""),
        "parking_reason": str(parking_reason or ""),
        "screenshot_path": str(screenshot_path or ""),
        "placeholder_or_parking_reason": str(parking_reason or ""),
        "source_workbook": str(prefetch_metrics.get("source_workbook", "") or ""),
        "admitted": False,
        "old_fuzzy_hit": bool(prefetch_metrics.get("old_fuzzy_hit", False)),
        "old_fuzzy_cse": prefetch_metrics.get("old_fuzzy_cse", ""),
        "hybrid_lexical_hit": bool(prefetch_metrics.get("hybrid_lexical_hit", False)),
        "strict_lexical_hit": strict_lexical_hit,
        "lexical_score_pass": lexical_score_pass,
        "fallback_rank_only": fallback_rank_only,
        "admission_reason": "",
        "admission_path": "",
        "candidate_generation_reason": prefetch_metrics.get("candidate_generation_reason", ""),
        "best_entity": prefetch_metrics.get("best_entity", ""),
        "best_matching_domain": prefetch_metrics.get("best_matching_domain", ""),
        "best_score": 0.0,
        "score_margin": 0.0,
        "confidence_band": "Low",
        "lexical_score": round(float(prefetch_metrics.get("best_lexical_score", 0.0)), 4),
        "review_reason": "",
        "hash_anchor": False,
        "favicon_hash_raw": "",
        "ssl_hash_raw": "",
        "html_hash_raw": "",
        "page_hash_raw": "",
        "domain_hash_raw": "",
        **_stage1_signal_defaults(),
        "clip_similarity": 0.0,
        "favicon_hash_similarity": 0.0,
        "favicon_hash_distance": -1,
        "page_hash_similarity": 0.0,
        "page_hash_distance": -1,
        "domain_hash_similarity": 0.0,
        "domain_hash_distance": -1,
        "ssl_hash_similarity": 0.0,
        "ssl_hash_distance": -1,
        "typo_similarity": round(float(prefetch_metrics.get("best_typo_similarity", 0.0)), 4),
        "generic_token_only_match": bool(prefetch_metrics.get("generic_token_only_match", False)),
        "direct_brand_evidence_count": 0,
        "deceptive_host_embedding": False,
        "content_spoof_strong": False,
        "clip_corroborated": False,
        "stage1_passthrough": False,
        "survival_path": "",
        "drop_path": "",
        "domain_component": round(lexical_contribution, 4),
        "clip_component": 0.0,
        "hash_component": 0.0,
        "signal_hit_favicon": False,
        "signal_hit_ssl_hash": False,
        "signal_hit_html_hash": False,
        "signal_hit_domain_hash": False,
    }
    decision_row.update(
        {
            key: stage1_analysis.get(key, decision_row.get(key))
            for key in _STAGE1_SIGNAL_FIELD_DEFAULTS
        }
    )
    return decision_row


def _build_prefetch_admitted_failure_match(
    decision_row: dict,
    *,
    scoring_config: dict,
) -> dict | None:
    if not isinstance(decision_row, dict):
        return None
    lexical_survivor = bool(
        decision_row.get("strict_lexical_hit", False)
        or decision_row.get("lexical_score_pass", False)
    )
    if not lexical_survivor or bool(decision_row.get("fallback_rank_only", False)):
        return None
    if not _has_suspicious_fetch_network_state(
        str(decision_row.get("fetch_status", "") or ""),
        fetch_error_type=str(decision_row.get("fetch_error_type", "") or ""),
        fetch_error_detail=str(decision_row.get("fetch_error_detail", "") or ""),
    ):
        return None
    return _build_stage1_passthrough_holdout_row(
        decision_row,
        scoring_config,
        passthrough_path_override="failed_fetch_strict_lexical_suspected",
    )


def _handle_stage1_fetch_payload(
    payload: dict,
    normalized_url: str,
    prefetch_metrics: dict,
    scoring_config: dict,
    stage1_analysis: dict | None = None,
) -> dict:
    fetch_status = str(payload.get("fetch_status", "")).strip().lower()
    if fetch_status in {"fetched", "fetched_visual_missing"}:
        return {
            "decision_row": None,
            "admitted_prefetch_match": None,
            "queue_payload": payload,
            "metric_key": "hashed_success",
        }

    decision_row = _build_prefetch_decision_row(
        normalized_url=payload.get("normalized_url", normalized_url),
        fetch_status=fetch_status,
        prefetch_metrics=prefetch_metrics,
        scoring_config=scoring_config,
        raw_url=str(payload.get("url", normalized_url) or normalized_url),
        final_landing_url=str(payload.get("final_landing_url", "") or ""),
        screenshot_path=str(payload.get("screenshot_path", "") or ""),
        visual_status=str(payload.get("visual_status", "not_attempted") or "not_attempted"),
        fetch_error_type=str(payload.get("fetch_error_type", "") or ""),
        fetch_error_detail=str(payload.get("fetch_error_detail", "") or ""),
        parking_provider=str(payload.get("parking_provider", "") or ""),
        parking_reason=str(payload.get("parking_reason", "") or ""),
        stage1_analysis=stage1_analysis,
    )
    metric_key = "fetch_failed"
    if fetch_status == "timeout":
        metric_key = "fetch_timed_out"

    return {
        "decision_row": decision_row,
        "admitted_prefetch_match": _build_prefetch_admitted_failure_match(
            decision_row,
            scoring_config=scoring_config,
        ),
        "queue_payload": None,
        "metric_key": metric_key,
    }


def _empty_shortlist_df():
    import pandas as pd

    return pd.DataFrame(
        columns=[
            "Cooresponding CSE",
            "Legitimate Domains",
            "Identified Phishing/Suspected Domain Name",
            "source_workbook",
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
            "stage1_passthrough",
            "survival_path",
            "drop_path",
            "old_fuzzy_hit",
            "old_fuzzy_cse",
            "hybrid_lexical_hit",
            "strict_lexical_hit",
            "lexical_score_pass",
            "fallback_rank_only",
            "admission_reason",
            "admission_path",
            "lexical_hit",
            "brand_score",
            "credential_score",
            "infra_score",
            "evasion_score",
            "total_stage1_score",
            "hard_trigger_hit",
            "stage1_reasons",
            "page_has_password_field",
            "page_has_login_form",
            "form_action_mismatch",
            "csc_mention_count",
            "redirect_count",
            "final_domain",
            "favicon_domain",
            "html_bytes_read",
            "escalate_to_hashing",
            "escalate_reason",
            "fetch_status",
            "visual_status",
            "fetch_error_type",
            "fetch_error_detail",
            "final_landing_url",
            "parking_provider",
            "parking_reason",
            "best_score",
            "domain_component",
            "clip_component",
            "hash_component",
            "typo_similarity",
            "typo_min_score_used",
            "typo_decision_reason",
            "clip_similarity",
            "favicon_hash_similarity",
            "favicon_hash_distance",
            "page_hash_similarity",
            "page_hash_distance",
            "domain_hash_similarity",
            "domain_hash_distance",
            "ssl_hash_similarity",
            "ssl_hash_distance",
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
            "html_title_text",
            "visible_text_excerpt",
        ]
    )


def _legacy_fuzzy_similarity_score(candidate_primary: str, legit_primary: str) -> float:
    if not candidate_primary or not legit_primary:
        return 0.0
    try:
        jw_score = float(jellyfish.jaro_winkler_similarity(candidate_primary, legit_primary)) if jellyfish is not None else 0.0
    except Exception:
        jw_score = 0.0
    try:
        token_score = float(fuzz.token_set_ratio(candidate_primary, legit_primary)) / 100.0
    except Exception:
        token_score = 0.0
    return max(jw_score, token_score)


def _compute_legacy_fuzzy_metrics(target_url: str) -> dict:
    candidate_norm = _legacy_normalize_url(target_url)
    candidate_primary = _legacy_get_primary_part(candidate_norm)
    best_entity = ""
    best_domain = ""
    best_score = 0.0
    best_hit = False

    for idx, entity_name in enumerate(_entity_index["names"]):
        entity_domains = _entity_index["domains"][idx]
        for entity_domain in entity_domains:
            legit_norm = _legacy_normalize_url(entity_domain)
            legit_primary = _legacy_get_primary_part(legit_norm)
            is_hit = _legacy_is_similar_advanced(
                candidate_norm,
                legit_norm,
                candidate_primary,
                legit_primary,
                set(),
            )
            score = _legacy_fuzzy_similarity_score(candidate_primary, legit_primary)
            if is_hit and (not best_hit or score > best_score):
                best_entity = entity_name
                best_domain = entity_domain
                best_score = score
                best_hit = True
            elif not best_hit and score > best_score:
                best_entity = entity_name
                best_domain = entity_domain
                best_score = score

    return {
        "old_fuzzy_hit": bool(best_hit),
        "old_fuzzy_cse": best_entity if best_hit else "",
        "old_fuzzy_domain": best_domain if best_hit else "",
        "old_fuzzy_score": float(best_score),
    }


def _compute_prefetch_lexical_state(target_url: str, scoring_config: dict) -> dict:
    normalized_url = normalize_url(target_url)
    parsed = urlparse(normalized_url)
    domain = parsed.netloc.lower() or normalized_url.lower()
    n_entities = len(_entity_index["names"])

    lexical_metrics = _compute_hybrid_lexical_metrics(
        domain,
        top_k=scoring_config["typo_top_k"],
    )
    legacy_metrics = _compute_legacy_fuzzy_metrics(domain)

    candidate_mask = np.array(lexical_metrics["candidate_mask"], dtype=bool)
    candidate_indices = np.where(candidate_mask)[0]
    if candidate_indices.size == 0:
        candidate_indices = np.arange(n_entities, dtype=int)

    if candidate_indices.size > 0:
        lexical_scores = np.asarray(lexical_metrics["lexical_scores"], dtype="float64")
        best_local_idx = int(np.argmax(lexical_scores[candidate_indices]))
        best_idx = int(candidate_indices[best_local_idx])
    else:
        best_idx = 0

    best_lexical_score = float(lexical_metrics["lexical_scores"][best_idx]) if n_entities else 0.0
    best_jw_score = float(lexical_metrics["jw_scores"][best_idx]) if n_entities else 0.0
    best_token_score = float(lexical_metrics["token_scores"][best_idx]) if n_entities else 0.0
    best_typo_similarity = float(lexical_metrics["skeleton_scores"][best_idx]) if n_entities else 0.0
    lexical_rule_hit = bool(lexical_metrics["lexical_rule_hit"][best_idx]) if n_entities else False
    brand_token_hit = bool(lexical_metrics["brand_token_hit"][best_idx]) if n_entities else False
    generic_token_only_match = bool(lexical_metrics["generic_token_only_match"][best_idx]) if n_entities else False
    hybrid_lexical_hit = bool(lexical_rule_hit or brand_token_hit)
    strict_lexical_hit = bool((legacy_metrics["old_fuzzy_hit"] or hybrid_lexical_hit) and not generic_token_only_match)
    candidate_generation_reason = (
        str(lexical_metrics["candidate_reasons"][best_idx] or "fallback_top_k")
        if n_entities
        else ""
    )
    if generic_token_only_match:
        candidate_generation_reason = f"{candidate_generation_reason}|generic_token_only".strip("|")
    fallback_rank_only = "fallback_top_k" in candidate_generation_reason and not strict_lexical_hit
    lexical_score_pass = bool(
        best_lexical_score >= scoring_config["lexical_pass_min_score"]
        and not fallback_rank_only
        and not generic_token_only_match
    )

    return {
        "normalized_url": normalized_url,
        "domain": domain,
        "best_idx": int(best_idx),
        "best_entity": _entity_index["names"][best_idx] if n_entities else "",
        "best_lexical_score": best_lexical_score,
        "best_jw_score": best_jw_score,
        "best_token_score": best_token_score,
        "best_typo_similarity": best_typo_similarity,
        "best_matching_domain": str(lexical_metrics["best_matching_domains"][best_idx] or "") if n_entities else "",
        "candidate_generation_reason": candidate_generation_reason,
        "lexical_rule_hit": lexical_rule_hit,
        "brand_token_hit": brand_token_hit,
        "generic_token_only_match": generic_token_only_match,
        "hybrid_lexical_hit": hybrid_lexical_hit,
        "strict_lexical_hit": strict_lexical_hit,
        "lexical_score_pass": lexical_score_pass,
        "fallback_rank_only": fallback_rank_only,
        "lexical_scores": lexical_metrics["lexical_scores"],
        "jw_scores": lexical_metrics["jw_scores"],
        "token_scores": lexical_metrics["token_scores"],
        "typo_scores": lexical_metrics["skeleton_scores"],
        "lexical_rule_hits": lexical_metrics["lexical_rule_hit"],
        "brand_token_hits": lexical_metrics["brand_token_hit"],
        "generic_token_only_hits": lexical_metrics["generic_token_only_match"],
        "candidate_mask": lexical_metrics["candidate_mask"],
        "candidate_reasons": lexical_metrics["candidate_reasons"],
        "best_matching_domains": lexical_metrics["best_matching_domains"],
        "old_fuzzy_hit": bool(legacy_metrics["old_fuzzy_hit"]),
        "old_fuzzy_cse": legacy_metrics["old_fuzzy_cse"],
        "old_fuzzy_domain": legacy_metrics["old_fuzzy_domain"],
        "old_fuzzy_score": float(legacy_metrics["old_fuzzy_score"]),
    }


_STAGE1_SIGNAL_FIELD_DEFAULTS = {
    "lexical_hit": False,
    "brand_score": 0,
    "credential_score": 0,
    "infra_score": 0,
    "evasion_score": 0,
    "total_stage1_score": 0,
    "hard_trigger_hit": False,
    "stage1_reasons": "",
    "page_has_password_field": False,
    "page_has_login_form": False,
    "form_action_mismatch": False,
    "csc_mention_count": 0,
    "redirect_count": 0,
    "final_domain": "",
    "favicon_domain": "",
    "html_bytes_read": 0,
    "escalate_to_hashing": False,
    "escalate_reason": "",
}


def _stage1_signal_defaults() -> dict:
    return dict(_STAGE1_SIGNAL_FIELD_DEFAULTS)


def _build_lexical_stage1_state(prefetch_metrics: dict) -> dict:
    state = _stage1_signal_defaults()
    state.update(
        {
            "lexical_hit": True,
            "stage1_reasons": "lexical_hit",
            "escalate_to_hashing": True,
            "escalate_reason": "lexical_hit",
            "final_domain": str(prefetch_metrics.get("domain", "") or ""),
        }
    )
    return state


def _stage1_passthrough_path(row: dict, scoring_config: dict | None = None) -> str:
    scoring_config = scoring_config or _DEFAULT_SCORING_CONFIG
    reason = str(row.get("reason", "") or "").strip()
    lexical_survivor = bool(
        row.get("strict_lexical_hit", False)
        or row.get("lexical_score_pass", False)
    )
    if (
        reason == "stage1_suspected_non_escalated"
        and (
            lexical_survivor
            or bool(scoring_config.get("keep_stage1_suspected", False))
        )
    ):
        return "stage1_suspected_passthrough"
    if (
        reason == "fetch_timeout_or_fetch_failed"
        and lexical_survivor
        and (
            _has_suspicious_fetch_network_state(
                str(row.get("fetch_status", "") or ""),
                fetch_error_type=str(row.get("fetch_error_type", "") or ""),
                fetch_error_detail=str(row.get("fetch_error_detail", "") or ""),
            )
            or bool(scoring_config.get("keep_fetch_failed_strict_lexical", False))
        )
    ):
        return "failed_fetch_strict_lexical_suspected"
    return ""


def _build_stage1_passthrough_holdout_row(
    stage1_row: dict,
    scoring_config: dict,
    passthrough_path_override: str | None = None,
) -> dict:
    passthrough_path = str(passthrough_path_override or "") or _stage1_passthrough_path(stage1_row, scoring_config)
    if not passthrough_path:
        return {}

    passthrough_fetch_status = str(stage1_row.get("fetch_status", "") or "").strip().lower()

    typo_similarity = float(stage1_row.get("typo_similarity", 0.0) or 0.0)
    stage1_direct_evidence = any(
        (
            int(stage1_row.get("brand_score", 0) or 0) > 0,
            int(stage1_row.get("credential_score", 0) or 0) > 0,
            int(stage1_row.get("infra_score", 0) or 0) > 0,
            int(stage1_row.get("evasion_score", 0) or 0) > 0,
            bool(stage1_row.get("hard_trigger_hit", False)),
        )
    )
    return {
        "Cooresponding CSE": stage1_row.get("best_entity", ""),
        "Legitimate Domains": stage1_row.get("best_matching_domain", ""),
        "Identified Phishing/Suspected Domain Name": stage1_row.get("normalized_url", stage1_row.get("input_url", "")),
        "source_workbook": stage1_row.get("source_workbook", ""),
        "hash_score": round(float(stage1_row.get("best_score", 0.0) or 0.0), 4),
        "confidence_band": stage1_row.get("confidence_band", "Low") or "Low",
        "score_margin": 0.0,
        "evidence_tier": "weak_evidence",
        "lexical_score": round(float(stage1_row.get("lexical_score", 0.0) or 0.0), 4),
        "jw_primary": 0.0,
        "token_set_primary": 0.0,
        "skeleton_similarity": round(typo_similarity, 4),
        "lexical_rule_hit": bool(stage1_row.get("strict_lexical_hit", False)),
        "brand_token_hit": bool(stage1_row.get("hybrid_lexical_hit", False)),
        "candidate_generation_reason": stage1_row.get("candidate_generation_reason", ""),
        "dominant_signal_family": "stage1_passthrough",
        "stage1_passthrough": True,
        "survival_path": passthrough_path,
        "drop_path": "",
        "old_fuzzy_hit": bool(stage1_row.get("old_fuzzy_hit", False)),
        "old_fuzzy_cse": stage1_row.get("old_fuzzy_cse", ""),
        "hybrid_lexical_hit": bool(stage1_row.get("hybrid_lexical_hit", False)),
        "strict_lexical_hit": bool(stage1_row.get("strict_lexical_hit", False)),
        "lexical_score_pass": bool(stage1_row.get("lexical_score_pass", False)),
        "fallback_rank_only": bool(stage1_row.get("fallback_rank_only", False)),
        "admission_reason": passthrough_path,
        "admission_path": passthrough_path,
        "fetch_status": passthrough_fetch_status,
        "visual_status": stage1_row.get("visual_status", "not_attempted"),
        "fetch_error_type": stage1_row.get("fetch_error_type", ""),
        "fetch_error_detail": stage1_row.get("fetch_error_detail", ""),
        "final_landing_url": stage1_row.get("final_landing_url", ""),
        "parking_provider": stage1_row.get("parking_provider", ""),
        "parking_reason": stage1_row.get("parking_reason", ""),
        "placeholder_or_parking_reason": stage1_row.get("placeholder_or_parking_reason", ""),
        "best_score": round(float(stage1_row.get("best_score", 0.0) or 0.0), 4),
        "domain_component": round(float(stage1_row.get("domain_component", 0.0) or 0.0), 4),
        "clip_component": 0.0,
        "hash_component": 0.0,
        "lexical_hit": bool(stage1_row.get("lexical_hit", False)),
        "brand_score": int(stage1_row.get("brand_score", 0) or 0),
        "credential_score": int(stage1_row.get("credential_score", 0) or 0),
        "infra_score": int(stage1_row.get("infra_score", 0) or 0),
        "evasion_score": int(stage1_row.get("evasion_score", 0) or 0),
        "total_stage1_score": int(stage1_row.get("total_stage1_score", 0) or 0),
        "hard_trigger_hit": bool(stage1_row.get("hard_trigger_hit", False)),
        "stage1_reasons": stage1_row.get("stage1_reasons", ""),
        "page_has_password_field": bool(stage1_row.get("page_has_password_field", False)),
        "page_has_login_form": bool(stage1_row.get("page_has_login_form", False)),
        "form_action_mismatch": bool(stage1_row.get("form_action_mismatch", False)),
        "csc_mention_count": int(stage1_row.get("csc_mention_count", 0) or 0),
        "redirect_count": int(stage1_row.get("redirect_count", 0) or 0),
        "final_domain": stage1_row.get("final_domain", ""),
        "favicon_domain": stage1_row.get("favicon_domain", ""),
        "html_bytes_read": int(stage1_row.get("html_bytes_read", 0) or 0),
        "escalate_to_hashing": bool(stage1_row.get("escalate_to_hashing", False)),
        "escalate_reason": stage1_row.get("escalate_reason", ""),
        "typo_similarity": round(typo_similarity, 4),
        "typo_min_score_used": round(float(scoring_config["typo_min_score"]), 4),
        "typo_decision_reason": (
            "anchor_typo"
            if bool(stage1_row.get("strict_lexical_hit", False)) and typo_similarity >= scoring_config["typo_min_score"]
            else "below_min_score"
        ),
        "clip_similarity": 0.0,
        "favicon_hash_similarity": 0.0,
        "favicon_hash_distance": -1,
        "page_hash_similarity": 0.0,
        "page_hash_distance": -1,
        "domain_hash_similarity": 0.0,
        "domain_hash_distance": -1,
        "ssl_hash_similarity": 0.0,
        "ssl_hash_distance": -1,
        "typo_anchor": bool(stage1_row.get("strict_lexical_hit", False)) and typo_similarity >= scoring_config["typo_min_score"],
        "hash_anchor": False,
        "clip_anchor": False,
        "signal_hit_screenshot": False,
        "signal_hit_domain": bool(stage1_row.get("strict_lexical_hit", False)),
        "signal_hit_favicon": False,
        "signal_hit_ssl_hash": False,
        "signal_hit_html_hash": False,
        "signal_hit_domain_hash": False,
        "signal_hit_keywords": stage1_direct_evidence,
        "signal_hit_typo": bool(stage1_row.get("strict_lexical_hit", False)) and typo_similarity >= scoring_config["typo_min_score"],
        "generic_token_only_match": bool(stage1_row.get("generic_token_only_match", False)),
        "direct_brand_evidence_count": 1 if stage1_direct_evidence else 0,
        "deceptive_host_embedding": False,
        "content_spoof_strong": False,
        "clip_corroborated": False,
        "screenshot_path": "",
        "html_title_text": "",
        "visible_text_excerpt": "",
    }


_STAGE1_DEBUG_FIELDNAMES = [
    "input_position",
    "input_url",
    "normalized_url",
    "source_workbook",
    "raw_url",
    "hashed_at_utc",
    "target_url_sha256",
    "hash_mode",
    "domain",
    "dns_status",
    "dns_decision",
    "fetch_status",
    "visual_status",
    "fetch_error_type",
    "fetch_error_detail",
    "final_landing_url",
    "parking_provider",
    "parking_reason",
    "placeholder_or_parking_reason",
    "admitted",
    "admitted_to_holdout",
    "kept_for_review_only",
    "review_only_reason",
    "survival_path",
    "drop_path",
    "exclusion_stage",
    "reason",
    "old_fuzzy_hit",
    "old_fuzzy_cse",
    "hybrid_lexical_hit",
    "strict_lexical_hit",
    "lexical_score_pass",
    "fallback_rank_only",
    "admission_reason",
    "admission_path",
    "candidate_generation_reason",
    "best_entity",
    "best_matching_domain",
    "best_score",
    "score_margin",
    "confidence_band",
    "lexical_score",
    "lexical_hit",
    "brand_score",
    "credential_score",
    "infra_score",
    "evasion_score",
    "total_stage1_score",
    "hard_trigger_hit",
    "stage1_reasons",
    "page_has_password_field",
    "page_has_login_form",
    "form_action_mismatch",
    "csc_mention_count",
    "redirect_count",
    "final_domain",
    "favicon_domain",
    "html_bytes_read",
    "escalate_to_hashing",
    "escalate_reason",
    "clip_similarity",
    "favicon_hash_similarity",
    "favicon_hash_distance",
    "page_hash_similarity",
    "page_hash_distance",
    "domain_hash_similarity",
    "domain_hash_distance",
    "ssl_hash_similarity",
    "ssl_hash_distance",
    "typo_similarity",
    "generic_token_only_match",
    "direct_brand_evidence_count",
    "deceptive_host_embedding",
    "content_spoof_strong",
    "clip_corroborated",
    "stage1_passthrough",
    "domain_component",
    "clip_component",
    "hash_component",
    "hash_anchor",
    "review_reason",
    "screenshot_path",
    "favicon_hash_raw",
    "ssl_hash_raw",
    "html_hash_raw",
    "page_hash_raw",
    "domain_hash_raw",
    "signal_hit_favicon",
    "signal_hit_ssl_hash",
    "signal_hit_html_hash",
    "signal_hit_domain_hash",
]


_STAGE1_METHOD_FIELDNAMES = [
    "input_position",
    "input_url",
    "normalized_url",
    "source_workbook",
    "best_entity",
    "best_matching_domain",
    "lexical_score",
    "lexical_hit",
    "strict_lexical_hit",
    "lexical_score_pass",
    "fallback_rank_only",
    "brand_score",
    "credential_score",
    "infra_score",
    "evasion_score",
    "total_stage1_score",
    "hard_trigger_hit",
    "stage1_reasons",
    "page_has_password_field",
    "page_has_login_form",
    "form_action_mismatch",
    "csc_mention_count",
    "redirect_count",
    "direct_brand_evidence_count",
    "deceptive_host_embedding",
    "content_spoof_strong",
    "final_domain",
    "favicon_domain",
    "html_bytes_read",
    "escalate_to_hashing",
    "escalate_reason",
    "deep_analysis_candidate",
    "deep_analysis_dns_accepted",
    "deep_analysis_attempted",
    "dns_status",
    "dns_decision",
    "fetch_status",
    "visual_status",
    "fetch_error_type",
    "fetch_error_detail",
    "final_landing_url",
    "parking_provider",
    "parking_reason",
    "confidence_band",
    "best_score",
    "admitted",
    "admitted_to_holdout",
    "kept_for_review_only",
    "review_only_reason",
    "survival_path",
    "drop_path",
    "reason",
    "exclusion_stage",
]


_EXCLUDED_AUDIT_FIELDNAMES = [
    "input_position",
    "input_url",
    "normalized_url",
    "source_workbook",
    "exclusion_stage",
    "reason",
    "survival_path",
    "drop_path",
    "dns_status",
    "dns_decision",
    "fetch_status",
    "visual_status",
    "fetch_error_type",
    "fetch_error_detail",
    "final_landing_url",
    "parking_provider",
    "parking_reason",
    "placeholder_or_parking_reason",
    "admitted_to_holdout",
    "kept_for_review_only",
    "review_only_reason",
    "strict_lexical_hit",
    "lexical_score_pass",
    "fallback_rank_only",
    "candidate_generation_reason",
    "best_matching_domain",
    "generic_token_only_match",
    "direct_brand_evidence_count",
    "deceptive_host_embedding",
    "content_spoof_strong",
    "lexical_hit",
    "brand_score",
    "credential_score",
    "infra_score",
    "evasion_score",
    "total_stage1_score",
    "hard_trigger_hit",
    "stage1_reasons",
    "page_has_password_field",
    "page_has_login_form",
    "form_action_mismatch",
    "csc_mention_count",
    "redirect_count",
    "final_domain",
    "favicon_domain",
    "html_bytes_read",
    "escalate_to_hashing",
    "escalate_reason",
    "stage1_passthrough",
]


def _build_stage1_debug_rows(
    input_urls,
    audit_rows,
    decision_rows,
    prefetch_metrics_map=None,
    lexical_reject_urls=None,
    stage1_analysis_map=None,
    scoring_config: dict | None = None,
    source_workbook_map: dict | None = None,
):
    scoring_config = scoring_config or _DEFAULT_SCORING_CONFIG
    decision_index = {}
    for row in decision_rows:
        normalized_url = str(row.get("normalized_url", "")).strip()
        if normalized_url:
            decision_index[normalized_url] = dict(row)

    audit_index = {}
    for audit_row in audit_rows:
        normalized_target = normalize_url(str(audit_row.get("target_url", "")).strip())
        if normalized_target:
            audit_index[normalized_target] = dict(audit_row)

    lexical_reject_urls = set(lexical_reject_urls or [])
    stage1_analysis_map = stage1_analysis_map or {}
    source_workbook_map = source_workbook_map or {}

    stage1_rows = []
    for idx, raw_url in enumerate(input_urls):
        input_text = str(raw_url or "").strip()
        normalized_url = normalize_url(input_text) if input_text else ""
        audit_row = audit_index.get(normalized_url, {})
        dns_status = str(audit_row.get("dns_status", "")).strip()
        dns_decision = str(audit_row.get("decision", "")).strip()
        prefetch_row = (prefetch_metrics_map or {}).get(normalized_url, {})
        stage1_info = dict(stage1_analysis_map.get(normalized_url, {}) or {})
        stage_row = {
            "input_position": idx + 1,
            "input_url": input_text,
            "normalized_url": normalized_url,
            "source_workbook": str(
                prefetch_row.get("source_workbook", "")
                or source_workbook_map.get(normalized_url, "")
            ),
            "dns_status": dns_status,
            "dns_decision": dns_decision or "",
            "fetch_status": "",
            "visual_status": "not_attempted",
            "fetch_error_type": "",
            "fetch_error_detail": "",
            "final_landing_url": "",
            "parking_provider": "",
            "parking_reason": "",
            "placeholder_or_parking_reason": "",
            "admitted": False,
            "admitted_to_holdout": False,
            "kept_for_review_only": False,
            "review_only_reason": "",
            "survival_path": "",
            "drop_path": "",
            "exclusion_stage": "",
            "reason": "",
            "old_fuzzy_hit": bool(prefetch_row.get("old_fuzzy_hit", False)),
            "old_fuzzy_cse": prefetch_row.get("old_fuzzy_cse", ""),
            "hybrid_lexical_hit": bool(prefetch_row.get("hybrid_lexical_hit", False)),
            "strict_lexical_hit": bool(prefetch_row.get("strict_lexical_hit", False)),
            "lexical_score_pass": bool(prefetch_row.get("lexical_score_pass", False)),
            "fallback_rank_only": bool(prefetch_row.get("fallback_rank_only", False)),
            "admission_reason": "",
            "admission_path": "",
            "candidate_generation_reason": prefetch_row.get("candidate_generation_reason", ""),
            "best_entity": prefetch_row.get("best_entity", ""),
            "best_matching_domain": prefetch_row.get("best_matching_domain", ""),
            "best_score": 0.0,
            "confidence_band": "",
            "lexical_score": round(float(prefetch_row.get("best_lexical_score", 0.0)), 4),
            **_stage1_signal_defaults(),
            "clip_similarity": 0.0,
            "typo_similarity": round(float(prefetch_row.get("best_typo_similarity", 0.0)), 4),
            "generic_token_only_match": bool(prefetch_row.get("generic_token_only_match", False)),
            "direct_brand_evidence_count": 0,
            "deceptive_host_embedding": False,
            "content_spoof_strong": False,
            "clip_corroborated": False,
            "stage1_passthrough": False,
            "domain_component": 0.0,
            "clip_component": 0.0,
            "hash_component": 0.0,
        }
        stage_row.update(
            {
                key: stage1_info.get(key, stage_row.get(key))
                for key in _STAGE1_SIGNAL_FIELD_DEFAULTS
            }
        )
        if stage1_info.get("best_entity"):
            stage_row["best_entity"] = stage1_info.get("best_entity", stage_row["best_entity"])
        if stage1_info.get("best_matching_domain"):
            stage_row["best_matching_domain"] = stage1_info.get("best_matching_domain", stage_row["best_matching_domain"])
        if stage1_info.get("final_landing_url"):
            stage_row["final_landing_url"] = stage1_info.get("final_landing_url", "")
        if stage1_info.get("fetch_status"):
            stage_row["fetch_status"] = stage1_info.get("fetch_status", "")
        if stage1_info.get("fetch_error_type"):
            stage_row["fetch_error_type"] = stage1_info.get("fetch_error_type", "")
        if stage1_info.get("fetch_error_detail"):
            stage_row["fetch_error_detail"] = stage1_info.get("fetch_error_detail", "")

        if normalized_url in lexical_reject_urls:
            stage_row["dns_status"] = "skipped"
            stage_row["dns_decision"] = "skipped"
            stage_row["exclusion_stage"] = "lexical_gate"
            stage_row["reason"] = (
                "generic_token_only_lexical_rejected"
                if stage_row.get("generic_token_only_match")
                else "lexical_prefilter_rejected"
            )
            stage_row["drop_path"] = stage_row["reason"]
            stage1_rows.append(stage_row)
            continue

        if not bool(stage_row.get("escalate_to_hashing")):
            stage_row["dns_status"] = "skipped"
            stage_row["dns_decision"] = "skipped"
            stage_row["exclusion_stage"] = "stage1_http"
            stage_row["reason"] = stage_row.get("escalate_reason", "") or "stage1_low_suspicion"
            passthrough_path = _stage1_passthrough_path(stage_row, scoring_config)
            if passthrough_path:
                stage_row["stage1_passthrough"] = True
                stage_row["survival_path"] = passthrough_path
            else:
                stage_row["drop_path"] = stage_row["reason"]
            stage1_rows.append(stage_row)
            continue

        if not stage_row["dns_decision"]:
            stage_row["dns_decision"] = "accepted"

        decision_row = decision_index.get(normalized_url, {})
        stage_row.update(decision_row)
        fetch_status = str(stage_row.get("fetch_status", "")).strip().lower()
        if stage_row.get("admitted"):
            stage_row["exclusion_stage"] = ""
            stage_row["reason"] = ""
            stage_row["survival_path"] = (
                str(stage_row.get("admission_path", "") or "")
                or str(stage_row.get("admission_reason", "") or "")
                or "score_threshold"
            )
            stage_row["drop_path"] = ""
        else:
            if not stage_row.get("exclusion_stage"):
                stage_row["exclusion_stage"] = "hashing_shortlist"
            if not stage_row.get("reason"):
                if stage_row.get("kept_for_review_only"):
                    stage_row["reason"] = stage_row.get("review_only_reason", "") or "stage1_review_only"
                elif fetch_status in {"timeout", "failed"}:
                    stage_row["reason"] = "fetch_timeout_or_fetch_failed"
                else:
                    stage_row["reason"] = "not_admitted_after_lexical_and_hash_checks"
            passthrough_path = _stage1_passthrough_path(stage_row, scoring_config)
            if passthrough_path:
                stage_row["stage1_passthrough"] = True
                stage_row["survival_path"] = passthrough_path
                stage_row["drop_path"] = ""
            elif stage_row.get("kept_for_review_only"):
                stage_row["survival_path"] = stage_row.get("review_only_reason", "") or "stage1_review_only"
                stage_row["drop_path"] = ""
            else:
                stage_row["drop_path"] = stage_row.get("reason", "")
        stage1_rows.append(stage_row)

    return stage1_rows


def _build_excluded_url_rows(stage1_debug_rows):
    excluded_rows = []
    for row in stage1_debug_rows:
        if bool(row.get("admitted")) or str(row.get("survival_path", "") or "").strip():
            continue
        excluded_rows.append(
            {
                "input_position": row.get("input_position", ""),
                "input_url": row.get("input_url", ""),
                "normalized_url": row.get("normalized_url", ""),
                "source_workbook": row.get("source_workbook", ""),
                "exclusion_stage": row.get("exclusion_stage", ""),
                "reason": row.get("reason", ""),
                "survival_path": row.get("survival_path", ""),
                "drop_path": row.get("drop_path", ""),
                "dns_status": row.get("dns_status", ""),
                "dns_decision": row.get("dns_decision", ""),
                "fetch_status": row.get("fetch_status", ""),
                "visual_status": row.get("visual_status", ""),
                "fetch_error_type": row.get("fetch_error_type", ""),
                "fetch_error_detail": row.get("fetch_error_detail", ""),
                "final_landing_url": row.get("final_landing_url", ""),
                "parking_provider": row.get("parking_provider", ""),
                "parking_reason": row.get("parking_reason", ""),
                "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", row.get("parking_reason", "")),
                "admitted_to_holdout": row.get("admitted_to_holdout", False),
                "kept_for_review_only": row.get("kept_for_review_only", False),
                "review_only_reason": row.get("review_only_reason", ""),
                "strict_lexical_hit": row.get("strict_lexical_hit", False),
                "lexical_score_pass": row.get("lexical_score_pass", False),
                "fallback_rank_only": row.get("fallback_rank_only", False),
                "candidate_generation_reason": row.get("candidate_generation_reason", ""),
                "best_matching_domain": row.get("best_matching_domain", ""),
                "generic_token_only_match": row.get("generic_token_only_match", False),
                "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                "deceptive_host_embedding": row.get("deceptive_host_embedding", False),
                "content_spoof_strong": row.get("content_spoof_strong", False),
                "lexical_hit": row.get("lexical_hit", False),
                "brand_score": row.get("brand_score", 0),
                "credential_score": row.get("credential_score", 0),
                "infra_score": row.get("infra_score", 0),
                "evasion_score": row.get("evasion_score", 0),
                "total_stage1_score": row.get("total_stage1_score", 0),
                "hard_trigger_hit": row.get("hard_trigger_hit", False),
                "stage1_reasons": row.get("stage1_reasons", ""),
                "page_has_password_field": row.get("page_has_password_field", False),
                "page_has_login_form": row.get("page_has_login_form", False),
                "form_action_mismatch": row.get("form_action_mismatch", False),
                "csc_mention_count": row.get("csc_mention_count", 0),
                "redirect_count": row.get("redirect_count", 0),
                "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                "deceptive_host_embedding": row.get("deceptive_host_embedding", False),
                "content_spoof_strong": row.get("content_spoof_strong", False),
                "final_domain": row.get("final_domain", ""),
                "favicon_domain": row.get("favicon_domain", ""),
                "html_bytes_read": row.get("html_bytes_read", 0),
                "escalate_to_hashing": row.get("escalate_to_hashing", False),
                "escalate_reason": row.get("escalate_reason", ""),
                "stage1_passthrough": row.get("stage1_passthrough", False),
            }
        )
    return excluded_rows


def _resolve_stage1_terminal_checkpoint_outcome(stage1_row: dict) -> tuple[str | None, str, str]:
    reason = str(stage1_row.get("reason", "") or "").strip()
    fetch_status = str(stage1_row.get("fetch_status", "") or "").strip().lower()
    if bool(stage1_row.get("admitted")) or bool(stage1_row.get("stage1_passthrough")):
        return "holdout_ready", "admitted", ""
    if bool(stage1_row.get("kept_for_review_only")):
        return (
            "review_only",
            "review_only",
            str(stage1_row.get("review_only_reason", "") or "stage1_review_only"),
        )
    if fetch_status in {"failed", "timeout"}:
        return "hash_failed", "fetch_failed", str(reason or "fetch_timeout_or_fetch_failed")
    if str(stage1_row.get("exclusion_stage", "")).strip() in {"stage1_http", "lexical_gate"}:
        return "filtered_lexical_miss", "filtered", str(reason or "filtered_lexical_miss")
    return None, "pending", ""


_HASH_EXPORT_COLUMNS = (
    "run_id",
    "hashed_at_utc",
    "source_workbook",
    "export_workbook",
    "raw_url",
    "normalized_url",
    "final_landing_url",
    "domain",
    "final_domain",
    "hash_mode",
    "fetch_status",
    "visual_status",
    "fetch_error_type",
    "fetch_error_detail",
    "parking_provider",
    "parking_reason",
    "screenshot_path",
    "target_url_sha256",
    "favicon_hash_raw",
    "ssl_hash_raw",
    "html_hash_raw",
    "page_hash_raw",
    "domain_hash_raw",
    "best_entity",
    "best_matching_domain",
    "hash_score",
    "confidence_band",
    "score_margin",
    "lexical_score",
    "direct_brand_evidence_count",
    "deceptive_host_embedding",
    "content_spoof_strong",
    "favicon_hash_similarity",
    "favicon_hash_distance",
    "page_hash_similarity",
    "page_hash_distance",
    "domain_hash_similarity",
    "domain_hash_distance",
    "ssl_hash_similarity",
    "ssl_hash_distance",
    "signal_hit_favicon",
    "signal_hit_ssl_hash",
    "signal_hit_html_hash",
    "signal_hit_domain_hash",
    "hash_anchor",
    "admission_path",
    "review_reason",
)


def _hash_mode_label() -> str:
    return "similarity" if bool(_entity_index.get("use_similarity_hashing", False)) else "exact"


def _hash_export_timestamp_token(run_context: RunContext | None) -> str:
    raw = str(getattr(run_context, "started_at", "") or utc_now_iso())
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y%m%d_%H%M%S")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _safe_hash_export_workbook_stem(workbook_name: str) -> str:
    base_name = os.path.basename(str(workbook_name or "").strip())
    stem = os.path.splitext(base_name)[0].strip() or "unknown_source"
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return safe_stem or "unknown_source"


def _split_hash_export_workbooks(source_workbook: str) -> list[str]:
    workbooks = []
    seen = set()
    for item in str(source_workbook or "").split("|"):
        workbook = str(item or "").strip()
        if not workbook:
            continue
        if workbook in seen:
            continue
        seen.add(workbook)
        workbooks.append(workbook)
    return workbooks or ["unknown_source"]


def _coerce_hash_export_text(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"none", "nan"} else text


def _coerce_hash_export_int(value, default: int = -1) -> int:
    if value is None or value == "":
        return int(default)
    try:
        return int(value)
    except Exception:
        return int(default)


def _resolve_hash_export_final_domain(decision_row: dict) -> str:
    for candidate in (
        str(decision_row.get("final_domain", "") or "").strip(),
        str(decision_row.get("domain", "") or "").strip(),
    ):
        if candidate:
            return candidate.lower()
    final_landing_url = str(decision_row.get("final_landing_url", "") or "").strip()
    if final_landing_url:
        host = (urlparse(final_landing_url).hostname or "").strip().lower()
        if host:
            return host
    normalized_url = str(decision_row.get("normalized_url", "") or "").strip()
    return (urlparse(normalized_url).hostname or "").strip().lower()


def _build_stage2_hash_export_row(decision_row: dict, *, run_id: str, export_workbook: str) -> dict:
    normalized_url = str(decision_row.get("normalized_url", "") or "").strip()
    raw_url = str(decision_row.get("raw_url", "") or decision_row.get("url", "") or normalized_url).strip()
    final_landing_url = str(decision_row.get("final_landing_url", "") or "").strip()
    domain = str(decision_row.get("domain", "") or "").strip().lower()
    if not domain and normalized_url:
        domain = (urlparse(normalized_url).hostname or "").strip().lower()
    final_domain = _resolve_hash_export_final_domain(decision_row)
    return {
        "run_id": run_id,
        "hashed_at_utc": str(decision_row.get("hashed_at_utc", "") or utc_now_iso()),
        "source_workbook": str(decision_row.get("source_workbook", "") or ""),
        "export_workbook": export_workbook,
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "final_landing_url": final_landing_url,
        "domain": domain,
        "final_domain": final_domain,
        "hash_mode": str(decision_row.get("hash_mode", "") or _hash_mode_label()),
        "fetch_status": str(decision_row.get("fetch_status", "") or ""),
        "visual_status": str(decision_row.get("visual_status", "") or ""),
        "fetch_error_type": str(decision_row.get("fetch_error_type", "") or ""),
        "fetch_error_detail": str(decision_row.get("fetch_error_detail", "") or ""),
        "parking_provider": str(decision_row.get("parking_provider", "") or ""),
        "parking_reason": str(decision_row.get("parking_reason", "") or ""),
        "screenshot_path": str(decision_row.get("screenshot_path", "") or ""),
        "target_url_sha256": str(decision_row.get("target_url_sha256", "") or (sha256_text(normalized_url) if normalized_url else "")),
        "favicon_hash_raw": _coerce_hash_export_text(decision_row.get("favicon_hash_raw", "")),
        "ssl_hash_raw": _coerce_hash_export_text(decision_row.get("ssl_hash_raw", "")),
        "html_hash_raw": _coerce_hash_export_text(decision_row.get("html_hash_raw", "")),
        "page_hash_raw": _coerce_hash_export_text(decision_row.get("page_hash_raw", "")),
        "domain_hash_raw": _coerce_hash_export_text(decision_row.get("domain_hash_raw", "")),
        "best_entity": str(decision_row.get("best_entity", "") or ""),
        "best_matching_domain": str(decision_row.get("best_matching_domain", "") or ""),
        "hash_score": round(float(decision_row.get("best_score", decision_row.get("hash_score", 0.0)) or 0.0), 4),
        "confidence_band": str(decision_row.get("confidence_band", "") or ""),
        "score_margin": round(float(decision_row.get("score_margin", 0.0) or 0.0), 4),
        "lexical_score": round(float(decision_row.get("lexical_score", 0.0) or 0.0), 4),
        "direct_brand_evidence_count": _coerce_hash_export_int(decision_row.get("direct_brand_evidence_count", 0), default=0),
        "deceptive_host_embedding": bool(decision_row.get("deceptive_host_embedding", False)),
        "content_spoof_strong": bool(decision_row.get("content_spoof_strong", False)),
        "favicon_hash_similarity": round(float(decision_row.get("favicon_hash_similarity", 0.0) or 0.0), 4),
        "favicon_hash_distance": _coerce_hash_export_int(decision_row.get("favicon_hash_distance", -1), default=-1),
        "page_hash_similarity": round(float(decision_row.get("page_hash_similarity", 0.0) or 0.0), 4),
        "page_hash_distance": _coerce_hash_export_int(decision_row.get("page_hash_distance", -1), default=-1),
        "domain_hash_similarity": round(float(decision_row.get("domain_hash_similarity", 0.0) or 0.0), 4),
        "domain_hash_distance": _coerce_hash_export_int(decision_row.get("domain_hash_distance", -1), default=-1),
        "ssl_hash_similarity": round(float(decision_row.get("ssl_hash_similarity", 0.0) or 0.0), 4),
        "ssl_hash_distance": _coerce_hash_export_int(decision_row.get("ssl_hash_distance", -1), default=-1),
        "signal_hit_favicon": bool(decision_row.get("signal_hit_favicon", False)),
        "signal_hit_ssl_hash": bool(decision_row.get("signal_hit_ssl_hash", False)),
        "signal_hit_html_hash": bool(decision_row.get("signal_hit_html_hash", False)),
        "signal_hit_domain_hash": bool(decision_row.get("signal_hit_domain_hash", False)),
        "hash_anchor": bool(decision_row.get("hash_anchor", False)),
        "admission_path": str(decision_row.get("admission_path", "") or ""),
        "review_reason": str(decision_row.get("review_reason", "") or decision_row.get("review_only_reason", "") or ""),
    }


def _write_stage2_hash_exports(decision_rows: list[dict], *, run_context: RunContext | None) -> list[str]:
    if not decision_rows:
        return []
    output_dir = os.path.join(getattr(run_context, "output_dir", "") or os.path.dirname(HASH_EXPORT_DIR), "hash_folder")
    os.makedirs(output_dir, exist_ok=True)
    run_id = str(getattr(run_context, "run_id", "") or "")
    timestamp_token = _hash_export_timestamp_token(run_context)
    grouped_rows: dict[str, list[dict]] = {}
    for decision_row in decision_rows:
        source_workbook = str(decision_row.get("source_workbook", "") or "")
        for export_workbook in _split_hash_export_workbooks(source_workbook):
            grouped_rows.setdefault(export_workbook, []).append(
                _build_stage2_hash_export_row(
                    decision_row,
                    run_id=run_id,
                    export_workbook=export_workbook,
                )
            )
    written_paths = []
    for export_workbook, workbook_rows in grouped_rows.items():
        output_path = os.path.join(
            output_dir,
            f"{_safe_hash_export_workbook_stem(export_workbook)}__stage2_hashes__{timestamp_token}.csv",
        )
        temp_path = f"{output_path}.tmp"
        with open(temp_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(_HASH_EXPORT_COLUMNS), extrasaction="ignore")
            writer.writeheader()
            for row in workbook_rows:
                writer.writerow({column: row.get(column, "") for column in _HASH_EXPORT_COLUMNS})
        os.replace(temp_path, output_path)
        written_paths.append(output_path)
    return written_paths


def _build_stage1_review_queue_rows(stage1_debug_rows, scoring_config: dict | None = None):
    scoring_config = scoring_config or _DEFAULT_SCORING_CONFIG
    review_rows = []
    for row in stage1_debug_rows:
        reason = str(row.get("reason", "") or "")
        if reason not in {
            "strict_lexical_below_holdout_threshold",
            "generic_token_only_lexical_rejected",
            "stage1_suspected_non_escalated",
        }:
            continue
        if (
            reason == "stage1_suspected_non_escalated"
            and bool(scoring_config.get("keep_stage1_suspected", False))
        ):
            continue
        review_rows.append(
            {
                "Cooresponding CSE": row.get("best_entity", ""),
                "Legitimate Domains": row.get("best_matching_domain", ""),
                "Identified Phishing/Suspected Domain Name": row.get("normalized_url", row.get("input_url", "")),
                "source_workbook": row.get("source_workbook", ""),
                "hash_score": round(float(row.get("best_score", 0.0) or 0.0), 4),
                "confidence_band": row.get("confidence_band", "Low") or "Low",
                "evidence_tier": "weak_evidence",
                "lexical_score": round(float(row.get("lexical_score", 0.0) or 0.0), 4),
                "strict_lexical_hit": bool(row.get("strict_lexical_hit", False)),
                "lexical_score_pass": bool(row.get("lexical_score_pass", False)),
                "fallback_rank_only": bool(row.get("fallback_rank_only", False)),
                "candidate_generation_reason": row.get("candidate_generation_reason", ""),
                "fetch_status": row.get("fetch_status", ""),
                "visual_status": row.get("visual_status", "not_attempted"),
                "fetch_error_type": row.get("fetch_error_type", ""),
                "fetch_error_detail": row.get("fetch_error_detail", ""),
                "final_landing_url": row.get("final_landing_url", ""),
                "parking_provider": row.get("parking_provider", ""),
                "parking_reason": row.get("parking_reason", ""),
                "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", ""),
                "generic_token_only_match": bool(row.get("generic_token_only_match", False)),
                "direct_brand_evidence_count": int(row.get("direct_brand_evidence_count", 0) or 0),
                "deceptive_host_embedding": bool(row.get("deceptive_host_embedding", False)),
                "content_spoof_strong": bool(row.get("content_spoof_strong", False)),
                "clip_corroborated": bool(row.get("clip_corroborated", False)),
                "lexical_hit": bool(row.get("lexical_hit", False)),
                "brand_score": int(row.get("brand_score", 0) or 0),
                "credential_score": int(row.get("credential_score", 0) or 0),
                "infra_score": int(row.get("infra_score", 0) or 0),
                "evasion_score": int(row.get("evasion_score", 0) or 0),
                "total_stage1_score": int(row.get("total_stage1_score", 0) or 0),
                "hard_trigger_hit": bool(row.get("hard_trigger_hit", False)),
                "stage1_reasons": row.get("stage1_reasons", ""),
                "page_has_password_field": bool(row.get("page_has_password_field", False)),
                "page_has_login_form": bool(row.get("page_has_login_form", False)),
                "form_action_mismatch": bool(row.get("form_action_mismatch", False)),
                "csc_mention_count": int(row.get("csc_mention_count", 0) or 0),
                "redirect_count": int(row.get("redirect_count", 0) or 0),
                "final_domain": row.get("final_domain", ""),
                "favicon_domain": row.get("favicon_domain", ""),
                "html_bytes_read": int(row.get("html_bytes_read", 0) or 0),
                "escalate_to_hashing": bool(row.get("escalate_to_hashing", False)),
                "escalate_reason": row.get("escalate_reason", ""),
                "review_reason": reason,
            }
        )
    return review_rows


def _write_stage1_debug_csv(stage1_rows, output_path: str = DEFAULT_STAGE1_DEBUG_CSV) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_STAGE1_DEBUG_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(stage1_rows)
    return output_path


def _build_stage1_method_rows(stage1_rows):
    method_rows = []
    for row in stage1_rows:
        dns_decision = str(row.get("dns_decision", "") or "").strip().lower()
        fetch_status = str(row.get("fetch_status", "") or "").strip().lower()
        deep_analysis_candidate = bool(row.get("escalate_to_hashing", False))
        deep_analysis_dns_accepted = bool(deep_analysis_candidate and dns_decision == "accepted")
        deep_analysis_attempted = bool(
            deep_analysis_dns_accepted and fetch_status not in {"", "not_attempted"}
        )
        method_rows.append(
            {
                "input_position": row.get("input_position", ""),
                "input_url": row.get("input_url", ""),
                "normalized_url": row.get("normalized_url", ""),
                "source_workbook": row.get("source_workbook", ""),
                "best_entity": row.get("best_entity", ""),
                "best_matching_domain": row.get("best_matching_domain", ""),
                "lexical_score": row.get("lexical_score", 0.0),
                "lexical_hit": row.get("lexical_hit", False),
                "strict_lexical_hit": row.get("strict_lexical_hit", False),
                "lexical_score_pass": row.get("lexical_score_pass", False),
                "fallback_rank_only": row.get("fallback_rank_only", False),
                "brand_score": row.get("brand_score", 0),
                "credential_score": row.get("credential_score", 0),
                "infra_score": row.get("infra_score", 0),
                "evasion_score": row.get("evasion_score", 0),
                "total_stage1_score": row.get("total_stage1_score", 0),
                "hard_trigger_hit": row.get("hard_trigger_hit", False),
                "stage1_reasons": row.get("stage1_reasons", ""),
                "page_has_password_field": row.get("page_has_password_field", False),
                "page_has_login_form": row.get("page_has_login_form", False),
                "form_action_mismatch": row.get("form_action_mismatch", False),
                "csc_mention_count": row.get("csc_mention_count", 0),
                "redirect_count": row.get("redirect_count", 0),
                "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                "deceptive_host_embedding": row.get("deceptive_host_embedding", False),
                "content_spoof_strong": row.get("content_spoof_strong", False),
                "final_domain": row.get("final_domain", ""),
                "favicon_domain": row.get("favicon_domain", ""),
                "html_bytes_read": row.get("html_bytes_read", 0),
                "escalate_to_hashing": deep_analysis_candidate,
                "escalate_reason": row.get("escalate_reason", ""),
                "deep_analysis_candidate": deep_analysis_candidate,
                "deep_analysis_dns_accepted": deep_analysis_dns_accepted,
                "deep_analysis_attempted": deep_analysis_attempted,
                "dns_status": row.get("dns_status", ""),
                "dns_decision": row.get("dns_decision", ""),
                "fetch_status": row.get("fetch_status", ""),
                "visual_status": row.get("visual_status", ""),
                "fetch_error_type": row.get("fetch_error_type", ""),
                "fetch_error_detail": row.get("fetch_error_detail", ""),
                "final_landing_url": row.get("final_landing_url", ""),
                "parking_provider": row.get("parking_provider", ""),
                "parking_reason": row.get("parking_reason", ""),
                "confidence_band": row.get("confidence_band", ""),
                "best_score": row.get("best_score", 0.0),
                "admitted": row.get("admitted", False),
                "admitted_to_holdout": row.get("admitted_to_holdout", False),
                "kept_for_review_only": row.get("kept_for_review_only", False),
                "review_only_reason": row.get("review_only_reason", ""),
                "survival_path": row.get("survival_path", ""),
                "drop_path": row.get("drop_path", ""),
                "reason": row.get("reason", ""),
                "exclusion_stage": row.get("exclusion_stage", ""),
            }
        )
    return method_rows


def _write_stage1_method_rows_csv(method_rows, output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_STAGE1_METHOD_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(method_rows)
    return output_path


def _write_stage1_methods_csv(stage1_rows, output_path: str = STAGE1_METHODS_DEBUG_PATH) -> str:
    method_rows = _build_stage1_method_rows(stage1_rows)
    return _write_stage1_method_rows_csv(method_rows, output_path)


def _write_stage1_deep_analysis_candidates_csv(
    stage1_rows,
    output_path: str = STAGE1_DEEP_ANALYSIS_CANDIDATES_PATH,
) -> str:
    method_rows = [
        row
        for row in _build_stage1_method_rows(stage1_rows)
        if bool(row.get("deep_analysis_candidate", False))
    ]
    return _write_stage1_method_rows_csv(method_rows, output_path)


def _log_stage1_method_summary(stage1_rows) -> None:
    method_rows = _build_stage1_method_rows(stage1_rows)
    if not method_rows:
        _clip_logger.info("Stage1 methods summary | rows=0")
        return

    deep_candidates = sum(1 for row in method_rows if bool(row.get("deep_analysis_candidate", False)))
    dns_accepted = sum(1 for row in method_rows if bool(row.get("deep_analysis_dns_accepted", False)))
    deep_attempted = sum(1 for row in method_rows if bool(row.get("deep_analysis_attempted", False)))
    hard_triggers = sum(1 for row in method_rows if bool(row.get("hard_trigger_hit", False)))
    lexical_hits = sum(1 for row in method_rows if bool(row.get("lexical_hit", False)))
    password_pages = sum(1 for row in method_rows if bool(row.get("page_has_password_field", False)))
    login_forms = sum(1 for row in method_rows if bool(row.get("page_has_login_form", False)))
    action_mismatches = sum(1 for row in method_rows if bool(row.get("form_action_mismatch", False)))
    escalate_reason_counts = Counter(
        str(row.get("escalate_reason", "") or "").strip()
        for row in method_rows
        if str(row.get("escalate_reason", "") or "").strip()
    )
    top_reasons = ", ".join(
        f"{reason}:{count}"
        for reason, count in escalate_reason_counts.most_common(5)
    ) or "none"
    _clip_logger.info(
        "Stage1 methods summary | rows=%d | lexical_hits=%d | hard_triggers=%d | "
        "password_pages=%d | login_forms=%d | action_mismatches=%d | "
        "deep_candidates=%d | dns_accepted=%d | deep_attempted=%d | top_escalate_reasons=%s",
        len(method_rows),
        lexical_hits,
        hard_triggers,
        password_pages,
        login_forms,
        action_mismatches,
        deep_candidates,
        dns_accepted,
        deep_attempted,
        top_reasons,
    )


def _write_stage1_method_artifacts(stage1_rows) -> tuple[str, str]:
    method_rows = _build_stage1_method_rows(stage1_rows)
    methods_path = _write_stage1_method_rows_csv(method_rows, STAGE1_METHODS_DEBUG_PATH)
    deep_analysis_path = _write_stage1_method_rows_csv(
        [row for row in method_rows if bool(row.get("deep_analysis_candidate", False))],
        STAGE1_DEEP_ANALYSIS_CANDIDATES_PATH,
    )
    if not method_rows:
        _clip_logger.info("Stage1 methods summary | rows=0")
    else:
        deep_candidates = sum(1 for row in method_rows if bool(row.get("deep_analysis_candidate", False)))
        dns_accepted = sum(1 for row in method_rows if bool(row.get("deep_analysis_dns_accepted", False)))
        deep_attempted = sum(1 for row in method_rows if bool(row.get("deep_analysis_attempted", False)))
        hard_triggers = sum(1 for row in method_rows if bool(row.get("hard_trigger_hit", False)))
        lexical_hits = sum(1 for row in method_rows if bool(row.get("lexical_hit", False)))
        password_pages = sum(1 for row in method_rows if bool(row.get("page_has_password_field", False)))
        login_forms = sum(1 for row in method_rows if bool(row.get("page_has_login_form", False)))
        action_mismatches = sum(1 for row in method_rows if bool(row.get("form_action_mismatch", False)))
        escalate_reason_counts = Counter(
            str(row.get("escalate_reason", "") or "").strip()
            for row in method_rows
            if str(row.get("escalate_reason", "") or "").strip()
        )
        top_reasons = ", ".join(
            f"{reason}:{count}"
            for reason, count in escalate_reason_counts.most_common(5)
        ) or "none"
        _clip_logger.info(
            "Stage1 methods summary | rows=%d | lexical_hits=%d | hard_triggers=%d | "
            "password_pages=%d | login_forms=%d | action_mismatches=%d | "
            "deep_candidates=%d | dns_accepted=%d | deep_attempted=%d | top_escalate_reasons=%s",
            len(method_rows),
            lexical_hits,
            hard_triggers,
            password_pages,
            login_forms,
            action_mismatches,
            deep_candidates,
            dns_accepted,
            deep_attempted,
            top_reasons,
        )
    _clip_logger.info("Stage1 methods CSV written to %s", methods_path)
    _clip_logger.info("Stage1 deep-analysis candidates CSV written to %s", deep_analysis_path)
    return methods_path, deep_analysis_path


def _write_stage1_subset_csv(stage1_rows, output_path: str, predicate) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    subset_rows = [row for row in stage1_rows if predicate(row)]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_STAGE1_DEBUG_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(subset_rows)
    return output_path


def _write_excluded_urls_audit(
    excluded_rows,
    output_path: str = HASHING_EXCLUDED_URLS_PATH,
) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_EXCLUDED_AUDIT_FIELDNAMES)
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
    """Fetch favicon perceptual hash using aiohttp (non-blocking) or requests fallback."""
    async with _get_aux_http_semaphore():
        if _has_aiohttp and session is not None:
            try:
                async with session.get(
                    f"https://{domain}/favicon.ico",
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        if _USE_SIMILARITY_HASHING:
                            return compute_image_phash(data)
                        return hashlib.sha256(data).hexdigest()
            except Exception:
                pass
            return None
        else:
            # Sync fallback run in thread so we don't block the loop.
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _favicon_hash_sync, domain)


def _favicon_hash_sync(domain):
    """Sync favicon fetch (used as thread-pool fallback)."""
    import requests
    try:
        r = requests.get(f"https://{domain}/favicon.ico", timeout=5)
        if r.status_code == 200:
            if _USE_SIMILARITY_HASHING:
                return compute_image_phash(r.content)
            return hashlib.sha256(r.content).hexdigest()
    except Exception:
        pass
    return None


# Keep old sync version for backward compat if anyone imports it
def favicon_hash(domain):
    return _favicon_hash_sync(domain)


async def get_ssl_hash_async(domain):
    """Non-blocking SSL identity similarity-hash fetch."""
    async with _get_aux_ssl_semaphore():
        writer = None
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
                cert_info = ssl_obj.getpeercert()
                cert_der = ssl_obj.getpeercert(binary_form=True)
                if _USE_SIMILARITY_HASHING and cert_info:
                    return compute_ssl_simhash(cert_info)
                if cert_der:
                    return hashlib.sha256(cert_der).hexdigest()
        except Exception:
            pass
        finally:
            if writer is not None:
                with suppress(Exception):
                    writer.close()
                with suppress(Exception):
                    await writer.wait_closed()
    return None


def get_ssl_hash(domain):
    """Sync SSL identity similarity-hash fetch (backward-compatible helper)."""
    import socket

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_info = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                if _USE_SIMILARITY_HASHING and cert_info:
                    return compute_ssl_simhash(cert_info)
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


def _canonical_host(value: str) -> str:
    text = str(value or "").strip().lower().strip(".")
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return (parsed.hostname or text).strip().lower().strip(".")


def _registered_domain(value: str) -> str:
    host = _canonical_host(value)
    if not host:
        return ""
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    if ext.domain:
        return ext.domain.lower()
    if ext.suffix:
        return ext.suffix.lower()
    return host


def _host_embedding_signature(value: str) -> str:
    host = _canonical_host(value)
    if not host:
        return ""
    registered = _registered_domain(host)
    if not registered:
        return host
    labels = [label for label in registered.split(".") if label]
    if labels and any(not _is_generic_service_token(label) for label in labels):
        return registered
    return host


def _has_deceptive_host_embedding(final_domain: str, legitimate_domain: str) -> bool:
    final_host = _canonical_host(final_domain)
    legit_host = _canonical_host(legitimate_domain)
    if not final_host or not legit_host:
        return False

    final_registered = _registered_domain(final_host)
    legit_registered = _registered_domain(legit_host)
    if not final_registered or not legit_registered:
        return False
    if final_registered == legit_registered:
        return False

    signature = _host_embedding_signature(legitimate_domain)
    signature_labels = [label for label in signature.split(".") if label]
    final_labels = [label for label in final_host.split(".") if label]
    if not signature_labels or len(signature_labels) >= len(final_labels):
        return False

    max_start = len(final_labels) - len(signature_labels)
    for start in range(max_start + 1):
        stop = start + len(signature_labels)
        if final_labels[start:stop] == signature_labels and stop < len(final_labels):
            return True
    return False


def _extract_brand_tokens(value: str) -> set[str]:
    host = _normalized_host_for_similarity(value)
    if not host:
        return set()
    tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", host)
        if token and not _is_generic_service_token(token) and len(token) > 2
    }
    ext = tldextract.extract(str(value or ""))
    primary = _domain_label_skeleton(ext.domain)
    if primary and not _is_generic_service_token(primary) and len(primary) > 2:
        tokens.add(primary)
    return tokens


def _extract_page_brand_tokens(value: str) -> set[str]:
    text = _collapse_text(value)
    if not text:
        return set()
    return {
        token
        for token in re.split(r"[^a-z0-9]+", text)
        if token and len(token) > 2 and not _is_generic_service_token(token)
    }


def _extract_entity_name_tokens(value: str) -> set[str]:
    text = _collapse_text(value)
    if not text:
        return set()
    return {
        token
        for token in re.split(r"[^a-z0-9]+", text)
        if (
            token
            and len(token) > 2
            and token not in _GENERIC_ENTITY_NAME_TOKENS
            and not _is_generic_service_token(token)
        )
    }


def _best_matching_entity_domain(target_domain: str, entity_domains: list[str]) -> str:
    target_domain = str(target_domain or "").strip().lower()
    best_domain = ""
    best_score = -1.0
    for entity_domain in entity_domains or []:
        score = max(
            _jaro_winkler_similarity(
                _normalized_primary_for_similarity(target_domain),
                _normalized_primary_for_similarity(entity_domain),
            ),
            typosquat_similarity(target_domain, entity_domain),
            domain_similarity(target_domain, entity_domain),
        )
        if score > best_score:
            best_score = score
            best_domain = str(entity_domain or "").strip().lower()
    return best_domain


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
            "generic_token_only_match": empty_mask,
            "candidate_mask": empty_mask,
            "candidate_reasons": [],
            "best_matching_domains": [],
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
    generic_token_only_match = np.zeros(n_entities, dtype=bool)
    candidate_mask = np.zeros(n_entities, dtype=bool)
    candidate_reasons = [""] * n_entities
    best_matching_domains = [""] * n_entities

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
        best_matching_domain = ""
        best_domain_primary_generic = False

        for entity_domain in entity_domains:
            entity_primary = _normalized_primary_for_similarity(entity_domain)
            entity_host = _normalized_host_for_similarity(entity_domain)
            entity_primary_generic = _is_generic_service_token(entity_primary)
            target_primary_generic = _is_generic_service_token(target_primary)
            allow_primary_string_rules = bool(
                target_primary
                and entity_primary
                and not target_primary_generic
                and not entity_primary_generic
            )

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
                best_matching_domain = str(entity_domain or "").strip().lower()
                best_domain_primary_generic = entity_primary_generic
                if allow_primary_string_rules and jw_score >= 0.85:
                    best_domain_reasons.append("jw_primary")
                if allow_primary_string_rules and token_score >= 0.90:
                    best_domain_reasons.append("token_set_primary")
                if allow_primary_string_rules and skeleton_score >= 0.88:
                    best_domain_reasons.append("skeleton_similarity")
                if entity_brand_tokens and host_score >= 0.90:
                    best_domain_reasons.append("host_similarity")

        lexical_scores[i] = best_lexical
        jw_scores[i] = best_jw
        token_scores[i] = best_token
        skeleton_scores[i] = best_skeleton
        host_scores[i] = best_host
        best_matching_domains[i] = best_matching_domain

        if best_domain_reasons:
            lexical_rule_hit[i] = True
            best_reason_parts.extend(best_domain_reasons)
        elif best_lexical > 0 and not brand_token_hit[i] and best_domain_primary_generic:
            generic_token_only_match[i] = True

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
        "generic_token_only_match": generic_token_only_match,
        "candidate_mask": candidate_mask,
        "candidate_reasons": candidate_reasons,
        "best_matching_domains": best_matching_domains,
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
    hash_schema_version = int(_entity_db_meta.get("hash_schema_version", 1) or 1)
    use_similarity_hashing = hash_schema_version >= 2
    if not use_similarity_hashing:
        _clip_logger.warning(
            "entity_hash_db.json is using legacy hash schema v%d; shortlist will use exact-match hashing until the DB is regenerated.",
            hash_schema_version,
        )

    entity_names = list(entity_db.keys())

    entity_domains = []            # list of domain-lists, aligned with entity_names
    entity_fav_sets = []           # list of favicon-hash-sets
    entity_ssl_hash_sets = []      # list of SSL cert hash sets
    entity_html_hash_sets = []     # list of HTML hash sets
    entity_domain_hash_sets = []   # list of domain hash sets
    entity_fav_similarity_refs = []
    entity_ssl_similarity_refs = []
    entity_page_similarity_refs = []
    entity_domain_similarity_refs = []
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
        entity_fav_similarity_refs.append(tuple(str(item).strip().lower() for item in data.get("favicon_phashes", []) if item))
        entity_ssl_similarity_refs.append(tuple(str(item).strip().lower() for item in data.get("ssl_simhashes", []) if item))
        entity_page_similarity_refs.append(tuple(str(item).strip().lower() for item in data.get("page_phashes", []) if item))
        entity_domain_similarity_refs.append(tuple(str(item).strip().lower() for item in data.get("domain_simhashes", []) if item))
        keyword_set = set(data.get("keywords", []))
        entity_kw_sets.append(keyword_set)
        brand_tokens = set()
        for domain in domains:
            brand_tokens |= _extract_brand_tokens(domain)
        for keyword in keyword_set:
            brand_tokens |= _extract_brand_tokens(keyword)
        entity_brand_tokens.append(brand_tokens)

    return {
        "hash_schema_version": hash_schema_version,
        "use_similarity_hashing": use_similarity_hashing,
        "names": entity_names,
        "clip_matrix": np.empty((0, _CLIP_DIM), dtype="float32"),
        "clip_entity_idx": np.empty((0,), dtype="int32"),
        "domains": entity_domains,
        "fav_sets": entity_fav_sets,
        "ssl_hash_sets": entity_ssl_hash_sets,
        "html_hash_sets": entity_html_hash_sets,
        "domain_hash_sets": entity_domain_hash_sets,
        "fav_similarity_refs": entity_fav_similarity_refs,
        "ssl_similarity_refs": entity_ssl_similarity_refs,
        "page_similarity_refs": entity_page_similarity_refs,
        "domain_similarity_refs": entity_domain_similarity_refs,
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


def _distance_to_similarity(max_distance: int) -> float:
    return max(0.0, 1.0 - (float(max_distance) / float(_HASH_SIMILARITY_BITS)))


def _similarity_arrays_from_reference_sets(
    candidate_hash: str | None,
    reference_sets,
    *,
    hit_distance: int,
    anchor_distance: int | None = None,
):
    n_entities = len(reference_sets)
    similarity = np.zeros(n_entities, dtype="float64")
    distance = np.full(n_entities, -1, dtype="int32")
    hit = np.zeros(n_entities, dtype=bool)
    anchor = np.zeros(n_entities, dtype=bool)
    if not candidate_hash:
        return similarity, distance, hit, anchor

    hit_similarity_floor = _distance_to_similarity(hit_distance)
    anchor_similarity_floor = _distance_to_similarity(anchor_distance) if anchor_distance is not None else None

    for idx, reference_hashes in enumerate(reference_sets):
        best_similarity, best_distance = best_similarity_against_set(candidate_hash, reference_hashes, hash_bits=_HASH_SIMILARITY_BITS)
        similarity[idx] = float(best_similarity)
        if best_distance is not None:
            distance[idx] = int(best_distance)
        if best_similarity >= hit_similarity_floor:
            hit[idx] = True
        if anchor_similarity_floor is not None and best_similarity >= anchor_similarity_floor:
            anchor[idx] = True
    return similarity, distance, hit, anchor


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

async def _fetch_url_payload(
    url,
    browser_context,
    semaphore,
    active_fetch_limiter,
    aio_session,
    scoring_config,
    prefetch_metrics=None,
    stage1_analysis=None,
):
    """
    Fetch one URL: navigate, screenshot, parse HTML, compute CPU-side scores.
    Returns payload dict for scoring on success, or a status dict on timeout/crash.
    Retries once on transient navigation/browser failures.
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    resolved_weights = scoring_config["weights"]
    domain_similarity_floor = scoring_config["domain_similarity_threshold"]
    prefetch_metrics = prefetch_metrics or _compute_prefetch_lexical_state(url, scoring_config)
    stage1_analysis = stage1_analysis or {}

    attempt_configs = [
        {
            "wait_until": "domcontentloaded",
            "post_wait_ms": 0,
        }
    ]
    if _should_retry_high_risk_hash_fetch(
        prefetch_metrics,
        stage1_analysis,
        scoring_config=scoring_config,
    ):
        attempt_configs.append(
            {
                "wait_until": "commit",
                "post_wait_ms": 1000,
            }
        )

    async def _single_attempt(*, wait_until: str, post_wait_ms: int):
        async with semaphore:
            async with active_fetch_limiter:
                page = await browser_context.new_page()
                current_op = None
                try:
                    current_op = asyncio.create_task(
                        page.goto(
                            url,
                            timeout=SCRAPER_NAV_TIMEOUT_MS,
                            wait_until=wait_until,
                        )
                    )
                    await current_op
                    if post_wait_ms > 0:
                        current_op = asyncio.create_task(page.wait_for_timeout(post_wait_ms))
                        await current_op
                    current_op = asyncio.create_task(page.content())
                    html_content = await current_op
                    final_landing_url = page.url
                    _, effective_domain = _resolve_effective_headless_target(
                        url,
                        final_landing_url,
                        original_domain=domain,
                    )
                    soup = BeautifulSoup(html_content, "html.parser")
                    title_text = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
                    visible_text = " ".join(
                        [p.get_text() for p in soup.find_all(["p", "h1", "h2", "h3", "title"])]
                    ).lower()
                    words = set(visible_text.split())
                    visible_text_excerpt = visible_text[:500]
                    parking_provider, parking_reason = _detect_parked_sale_signal(
                        final_landing_url=final_landing_url,
                        title_text=title_text,
                        visible_text=visible_text,
                    )
                    screenshot_bytes = None
                    fetch_status = "fetched"
                    visual_status = "available"
                    fetch_error_type = ""
                    fetch_error_detail = ""
                    try:
                        current_op = asyncio.create_task(
                            page.screenshot(
                                full_page=False,
                                timeout=SCRAPER_SCREENSHOT_TIMEOUT_MS,
                                animations="disabled",
                                type="png",
                            )
                        )
                        screenshot_bytes = await current_op
                    except Exception as exc:
                        error_type, error_detail, _ = _classify_fetch_exception(exc, stage="screenshot")
                        fetch_status = "fetched_visual_missing"
                        visual_status = "missing"
                        fetch_error_type = error_type
                        fetch_error_detail = error_detail
                    finally:
                        current_op = None

                    screenshot_path = ""
                    if screenshot_bytes:
                        ext = tldextract.extract(domain)
                        screenshot_name = ".".join(part for part in [ext.domain, ext.suffix] if part) or domain
                        screenshot_path = os.path.join(BASE_DIR, "screens", f"{screenshot_name}.png")
                        try:
                            os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
                            with open(screenshot_path, "wb") as screenshot_file:
                                screenshot_file.write(screenshot_bytes)
                        except Exception:
                            screenshot_path = ""

                    domain_hash = (
                        compute_domain_simhash(effective_domain)
                        if _USE_SIMILARITY_HASHING
                        else sha256_text(effective_domain)
                    )
                    html_hash = None if _USE_SIMILARITY_HASHING else sha256_text(html_content)
                    page_hash = compute_image_phash(screenshot_bytes) if (_USE_SIMILARITY_HASHING and screenshot_bytes) else None
                    fav_task = favicon_hash_async(effective_domain, session=aio_session)
                    ssl_task = get_ssl_hash_async(effective_domain)
                    fav_hash, ssl_hash = await asyncio.gather(fav_task, ssl_task)

                    n_entities = len(_entity_index["names"])
                    typo_scores = np.asarray(prefetch_metrics["typo_scores"], dtype="float64")
                    candidate_mask = np.array(prefetch_metrics["candidate_mask"], dtype=bool).copy()
                    lexical_scores = np.asarray(prefetch_metrics["lexical_scores"], dtype="float64")
                    jw_scores = np.asarray(prefetch_metrics["jw_scores"], dtype="float64")
                    token_scores = np.asarray(prefetch_metrics["token_scores"], dtype="float64")
                    lexical_rule_hit = np.array(prefetch_metrics["lexical_rule_hits"], dtype=bool)
                    brand_token_hit = np.array(prefetch_metrics["brand_token_hits"], dtype=bool)
                    candidate_reasons = list(prefetch_metrics["candidate_reasons"])
                    stage1_candidate_entities = list(stage1_analysis.get("candidate_entities", []) or [])
                    if stage1_candidate_entities:
                        seeded_mask = np.zeros(n_entities, dtype=bool)
                        stage1_best_domains = stage1_analysis.get("candidate_best_matching_domains", {}) or {}
                        for entity_name in stage1_candidate_entities:
                            try:
                                entity_idx = _entity_index["names"].index(entity_name)
                            except ValueError:
                                continue
                            seeded_mask[entity_idx] = True
                            candidate_reasons[entity_idx] = f"{candidate_reasons[entity_idx]}|stage1_brand_seed".strip("|")
                            best_domain = str(stage1_best_domains.get(entity_name, "") or "")
                            if best_domain and len(prefetch_metrics.get("best_matching_domains", [])) > entity_idx:
                                prefetch_metrics["best_matching_domains"][entity_idx] = best_domain
                        if seeded_mask.any():
                            candidate_mask = seeded_mask

                    use_similarity_hashing = bool(_entity_index.get("use_similarity_hashing", False))
                    if use_similarity_hashing:
                        (
                            favicon_similarity,
                            favicon_distance,
                            favicon_hit,
                            favicon_anchor,
                        ) = _similarity_arrays_from_reference_sets(
                            fav_hash,
                            _entity_index["fav_similarity_refs"],
                            hit_distance=_FAVICON_HASH_HIT_DISTANCE,
                            anchor_distance=_FAVICON_HASH_ANCHOR_DISTANCE,
                        )
                        (
                            ssl_hash_similarity,
                            ssl_hash_distance,
                            ssl_hash_hit,
                            ssl_hash_anchor,
                        ) = _similarity_arrays_from_reference_sets(
                            ssl_hash,
                            _entity_index["ssl_similarity_refs"],
                            hit_distance=_SSL_HASH_HIT_DISTANCE,
                            anchor_distance=_SSL_HASH_ANCHOR_DISTANCE,
                        )
                        (
                            page_hash_similarity,
                            page_hash_distance,
                            html_hash_hit,
                            html_hash_anchor,
                        ) = _similarity_arrays_from_reference_sets(
                            page_hash,
                            _entity_index["page_similarity_refs"],
                            hit_distance=_PAGE_HASH_HIT_DISTANCE,
                            anchor_distance=_PAGE_HASH_ANCHOR_DISTANCE,
                        )
                        (
                            domain_hash_similarity,
                            domain_hash_distance,
                            domain_hash_hit,
                            domain_hash_anchor,
                        ) = _similarity_arrays_from_reference_sets(
                            domain_hash,
                            _entity_index["domain_similarity_refs"],
                            hit_distance=_DOMAIN_HASH_HIT_DISTANCE,
                            anchor_distance=None,
                        )
                        hash_hit_count = (
                            favicon_hit.astype(int)
                            + ssl_hash_hit.astype(int)
                            + html_hash_hit.astype(int)
                            + domain_hash_hit.astype(int)
                        )
                        hash_bypass_mask = np.array(
                            favicon_anchor | ssl_hash_anchor | html_hash_anchor | (hash_hit_count >= 2),
                            dtype=bool,
                        )
                    else:
                        hash_bypass_mask = np.zeros(n_entities, dtype=bool)
                        favicon_similarity = np.zeros(n_entities, dtype="float64")
                        favicon_distance = np.full(n_entities, -1, dtype="int32")
                        favicon_hit = np.zeros(n_entities, dtype=bool)
                        favicon_anchor = np.zeros(n_entities, dtype=bool)
                        ssl_hash_similarity = np.zeros(n_entities, dtype="float64")
                        ssl_hash_distance = np.full(n_entities, -1, dtype="int32")
                        ssl_hash_hit = np.zeros(n_entities, dtype=bool)
                        ssl_hash_anchor = np.zeros(n_entities, dtype=bool)
                        page_hash_similarity = np.zeros(n_entities, dtype="float64")
                        page_hash_distance = np.full(n_entities, -1, dtype="int32")
                        html_hash_hit = np.zeros(n_entities, dtype=bool)
                        html_hash_anchor = np.zeros(n_entities, dtype=bool)
                        domain_hash_similarity = np.zeros(n_entities, dtype="float64")
                        domain_hash_distance = np.full(n_entities, -1, dtype="int32")
                        domain_hash_hit = np.zeros(n_entities, dtype=bool)
                        domain_hash_anchor = np.zeros(n_entities, dtype=bool)
                        if fav_hash:
                            favicon_hit = np.array(
                                [fav_hash in _entity_index["fav_sets"][i] for i in range(n_entities)],
                                dtype=bool,
                            )
                            hash_bypass_mask |= favicon_hit
                            favicon_similarity = favicon_hit.astype("float64")
                            favicon_distance = np.where(favicon_hit, 0, -1).astype("int32")
                            favicon_anchor = favicon_hit.copy()
                        if ssl_hash:
                            ssl_hash_hit = np.array(
                                [ssl_hash in _entity_index["ssl_hash_sets"][i] for i in range(n_entities)],
                                dtype=bool,
                            )
                            hash_bypass_mask |= ssl_hash_hit
                            ssl_hash_similarity = ssl_hash_hit.astype("float64")
                            ssl_hash_distance = np.where(ssl_hash_hit, 0, -1).astype("int32")
                            ssl_hash_anchor = ssl_hash_hit.copy()
                        if html_hash:
                            html_hash_hit = np.array(
                                [html_hash in _entity_index["html_hash_sets"][i] for i in range(n_entities)],
                                dtype=bool,
                            )
                            hash_bypass_mask |= html_hash_hit
                            page_hash_similarity = html_hash_hit.astype("float64")
                            page_hash_distance = np.where(html_hash_hit, 0, -1).astype("int32")
                            html_hash_anchor = html_hash_hit.copy()
                        if domain_hash:
                            domain_hash_hit = np.array(
                                [domain_hash in _entity_index["domain_hash_sets"][i] for i in range(n_entities)],
                                dtype=bool,
                            )
                            hash_bypass_mask |= domain_hash_hit
                            domain_hash_similarity = domain_hash_hit.astype("float64")
                            domain_hash_distance = np.where(domain_hash_hit, 0, -1).astype("int32")
                    candidate_mask |= hash_bypass_mask
                    for idx in np.where(hash_bypass_mask)[0]:
                        candidate_reasons[idx] = f"{candidate_reasons[idx]}|hash_bypass".strip("|")

                    cpu_scores = np.zeros(n_entities, dtype="float64")
                    cpu_denominators = np.zeros(n_entities, dtype="float64")
                    domain_hit = np.zeros(n_entities, dtype=bool)
                    keyword_hit = np.zeros(n_entities, dtype=bool)
                    for i in range(n_entities):
                        if not candidate_mask[i]:
                            continue
                        entity_domains = _entity_index["domains"][i]
                        if entity_domains:
                            domain_sim = max(
                                domain_similarity(effective_domain, d) for d in entity_domains
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
                            if favicon_hit[i]:
                                cpu_scores[i] += resolved_weights["favicon"] * float(favicon_similarity[i])
                        ssl_set = _entity_index["ssl_hash_sets"][i]
                        if ssl_hash and ssl_set:
                            cpu_denominators[i] += resolved_weights["ssl_hash"]
                            if ssl_hash_hit[i]:
                                cpu_scores[i] += resolved_weights["ssl_hash"] * float(ssl_hash_similarity[i])
                        html_candidate_hash = page_hash if use_similarity_hashing else html_hash
                        html_set = _entity_index["page_similarity_refs"][i] if use_similarity_hashing else _entity_index["html_hash_sets"][i]
                        if html_candidate_hash and html_set:
                            cpu_denominators[i] += resolved_weights["html_hash"]
                            if html_hash_hit[i]:
                                cpu_scores[i] += resolved_weights["html_hash"] * float(page_hash_similarity[i])
                        domain_hash_set = _entity_index["domain_similarity_refs"][i] if use_similarity_hashing else _entity_index["domain_hash_sets"][i]
                        if domain_hash and domain_hash_set:
                            cpu_denominators[i] += resolved_weights["domain_hash"]
                            if domain_hash_hit[i]:
                                cpu_scores[i] += resolved_weights["domain_hash"] * float(domain_hash_similarity[i])
                        if _entity_index["kw_sets"][i] and words:
                            cpu_denominators[i] += resolved_weights["keywords"]
                            overlap = len(words & _entity_index["kw_sets"][i])
                            keyword_score = min(overlap / 5, 1.0) * resolved_weights["keywords"]
                            cpu_scores[i] += keyword_score
                            keyword_hit[i] = keyword_score > 0

                    return {
                        "url": url,
                        "normalized_url": url,
                        "source_workbook": prefetch_metrics.get("source_workbook", ""),
                        "domain": domain,
                        "fetch_status": fetch_status,
                        "visual_status": visual_status,
                        "fetch_error_type": fetch_error_type,
                        "fetch_error_detail": fetch_error_detail,
                        "final_landing_url": final_landing_url,
                        "parking_provider": parking_provider,
                        "parking_reason": parking_reason,
                        "screenshot_path": screenshot_path,
                        "html_title_text": title_text,
                        "visible_text_excerpt": visible_text_excerpt,
                        "screenshot_bytes": screenshot_bytes,
                        "cpu_scores": cpu_scores,
                        "cpu_denominators": cpu_denominators,
                        "lexical_scores": lexical_scores,
                        "jw_scores": jw_scores,
                        "token_scores": token_scores,
                        "domain_hit": domain_hit,
                        "lexical_hit": np.array(lexical_rule_hit, dtype=bool),
                        "lexical_rule_hit": lexical_rule_hit,
                        "brand_token_hit": brand_token_hit,
                        "generic_token_only_hit": np.array(prefetch_metrics.get("generic_token_only_hits", np.zeros(n_entities, dtype=bool)), dtype=bool),
                        "favicon_hit": favicon_hit,
                        "favicon_anchor": favicon_anchor,
                        "favicon_hash_similarity": favicon_similarity,
                        "favicon_hash_distance": favicon_distance,
                        "ssl_hash_hit": ssl_hash_hit,
                        "ssl_hash_anchor": ssl_hash_anchor,
                        "ssl_hash_similarity": ssl_hash_similarity,
                        "ssl_hash_distance": ssl_hash_distance,
                        "html_hash_hit": html_hash_hit,
                        "html_hash_anchor": html_hash_anchor,
                        "page_hash_similarity": page_hash_similarity,
                        "page_hash_distance": page_hash_distance,
                        "domain_hash_hit": domain_hash_hit,
                        "domain_hash_anchor": domain_hash_anchor,
                        "domain_hash_similarity": domain_hash_similarity,
                        "domain_hash_distance": domain_hash_distance,
                        "keyword_hit": keyword_hit,
                        "typo_scores": typo_scores,
                        "candidate_mask": candidate_mask,
                        "candidate_reasons": candidate_reasons,
                        "best_matching_domains": list(prefetch_metrics.get("best_matching_domains", [])),
                        "old_fuzzy_hit": prefetch_metrics["old_fuzzy_hit"],
                        "old_fuzzy_cse": prefetch_metrics["old_fuzzy_cse"],
                        "old_fuzzy_domain": prefetch_metrics["old_fuzzy_domain"],
                        "old_fuzzy_score": prefetch_metrics["old_fuzzy_score"],
                        "strict_lexical_hit": prefetch_metrics["strict_lexical_hit"],
                        "lexical_score_pass": prefetch_metrics["lexical_score_pass"],
                        "fallback_rank_only": prefetch_metrics["fallback_rank_only"],
                        **{
                            key: stage1_analysis.get(key, _STAGE1_SIGNAL_FIELD_DEFAULTS[key])
                            for key in _STAGE1_SIGNAL_FIELD_DEFAULTS
                        },
                        "final_domain": effective_domain,
                    }
                finally:
                    if current_op is not None and not current_op.done():
                        current_op.cancel()
                        with suppress(asyncio.CancelledError, Exception):
                            await current_op
                    with suppress(Exception):
                        if not page.is_closed():
                            await page.close()

    for attempt_index, attempt_config in enumerate(attempt_configs, start=1):
        try:
            return await asyncio.wait_for(
                _single_attempt(
                    wait_until=str(attempt_config.get("wait_until", "domcontentloaded") or "domcontentloaded"),
                    post_wait_ms=int(attempt_config.get("post_wait_ms", 0) or 0),
                ),
                timeout=SCRAPER_FETCH_TIMEOUT_S,
            )
        except Exception as exc:
            error_type, error_detail, retryable = _classify_fetch_exception(exc, stage="navigation")
            fetch_status = "timeout" if error_type.endswith("_timeout") else "failed"
            if attempt_index < len(attempt_configs) and (retryable or fetch_status == "timeout"):
                continue
            return _build_fetch_failure_payload(
                url=url,
                normalized_url=url,
                fetch_status=fetch_status,
                error_type=error_type,
                error_detail=error_detail,
            )

    return _build_fetch_failure_payload(
        url=url,
        normalized_url=url,
        fetch_status="failed",
        error_type="navigation_error",
        error_detail="navigation failed",
    )


async def _render_hash_payload_on_page(
    url,
    page,
    active_fetch_limiter,
    host_limiter,
    prefetch_metrics=None,
    stage1_analysis=None,
):
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    prefetch_metrics = prefetch_metrics or {}
    stage1_analysis = stage1_analysis or {}
    attempt_configs = [
        {
            "wait_until": "domcontentloaded",
            "post_wait_ms": 0,
        }
    ]
    if _should_retry_high_risk_hash_fetch(
        prefetch_metrics,
        stage1_analysis,
        scoring_config=_DEFAULT_SCORING_CONFIG,
    ):
        attempt_configs.append(
            {
                "wait_until": "commit",
                "post_wait_ms": 1000,
            }
        )

    async def _single_attempt(*, wait_until: str, post_wait_ms: int):
        current_op = None
        host_gate = await host_limiter.acquire(domain) if host_limiter is not None else None
        try:
            async with active_fetch_limiter:
                current_op = asyncio.create_task(
                    page.goto(
                        url,
                        timeout=SCRAPER_NAV_TIMEOUT_MS,
                        wait_until=wait_until,
                    )
                )
                await current_op
                if post_wait_ms > 0:
                    current_op = asyncio.create_task(page.wait_for_timeout(post_wait_ms))
                    await current_op
                current_op = asyncio.create_task(page.content())
                html_content = await current_op
                final_landing_url = page.url
                _, effective_domain = _resolve_effective_headless_target(
                    url,
                    final_landing_url,
                    original_domain=domain,
                )
                soup = BeautifulSoup(html_content, "html.parser")
                title_text = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
                visible_text = " ".join(
                    [p.get_text() for p in soup.find_all(["p", "h1", "h2", "h3", "title"])]
                ).lower()
                words = set(visible_text.split())
                visible_text_excerpt = visible_text[:500]
                parking_provider, parking_reason = _detect_parked_sale_signal(
                    final_landing_url=final_landing_url,
                    title_text=title_text,
                    visible_text=visible_text,
                )
                screenshot_bytes = None
                fetch_status = "fetched"
                visual_status = "available"
                fetch_error_type = ""
                fetch_error_detail = ""
                try:
                    current_op = asyncio.create_task(
                        page.screenshot(
                            full_page=False,
                            timeout=SCRAPER_SCREENSHOT_TIMEOUT_MS,
                            animations="disabled",
                            type="png",
                        )
                    )
                    screenshot_bytes = await current_op
                except Exception as exc:
                    error_type, error_detail, _ = _classify_fetch_exception(exc, stage="screenshot")
                    fetch_status = "fetched_visual_missing"
                    visual_status = "missing"
                    fetch_error_type = error_type
                    fetch_error_detail = error_detail
                finally:
                    current_op = None

                screenshot_path = ""
                if screenshot_bytes:
                    ext = tldextract.extract(domain)
                    screenshot_name = ".".join(part for part in [ext.domain, ext.suffix] if part) or domain
                    screenshot_path = os.path.join(BASE_DIR, "screens", f"{screenshot_name}.png")
                    try:
                        os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)
                        with open(screenshot_path, "wb") as screenshot_file:
                            screenshot_file.write(screenshot_bytes)
                    except Exception:
                        screenshot_path = ""

                return {
                    "url": url,
                    "normalized_url": url,
                    "source_workbook": prefetch_metrics.get("source_workbook", ""),
                    "domain": domain,
                    "final_domain": effective_domain,
                    "fetch_status": fetch_status,
                    "visual_status": visual_status,
                    "fetch_error_type": fetch_error_type,
                    "fetch_error_detail": fetch_error_detail,
                    "final_landing_url": final_landing_url,
                    "parking_provider": parking_provider,
                    "parking_reason": parking_reason,
                    "screenshot_path": screenshot_path,
                    "html_title_text": title_text,
                    "visible_text_excerpt": visible_text_excerpt,
                    "screenshot_bytes": screenshot_bytes,
                    "html_content": html_content,
                    "visible_text_words": words,
                    "page_hash": compute_image_phash(screenshot_bytes) if (_USE_SIMILARITY_HASHING and screenshot_bytes) else None,
                    "domain_hash": (
                        compute_domain_simhash(effective_domain)
                        if _USE_SIMILARITY_HASHING
                        else sha256_text(effective_domain)
                    ),
                    "html_hash": None if _USE_SIMILARITY_HASHING else sha256_text(html_content),
                }
        finally:
            if current_op is not None and not current_op.done():
                current_op.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await current_op
            if host_gate is not None:
                host_gate.release()

    for attempt_index, attempt_config in enumerate(attempt_configs, start=1):
        try:
            return await asyncio.wait_for(
                _single_attempt(
                    wait_until=str(attempt_config.get("wait_until", "domcontentloaded") or "domcontentloaded"),
                    post_wait_ms=int(attempt_config.get("post_wait_ms", 0) or 0),
                ),
                timeout=SCRAPER_FETCH_TIMEOUT_S,
            )
        except Exception as exc:
            error_type, error_detail, retryable = _classify_fetch_exception(exc, stage="navigation")
            fetch_status = "timeout" if error_type.endswith("_timeout") else "failed"
            if attempt_index < len(attempt_configs) and (retryable or fetch_status == "timeout"):
                continue
            return _build_fetch_failure_payload(
                url=url,
                normalized_url=url,
                fetch_status=fetch_status,
                error_type=error_type,
                error_detail=error_detail,
            )


async def _enrich_render_payload_for_hashing(
    render_payload,
    *,
    aio_session,
    scoring_config,
    prefetch_metrics,
    stage1_analysis,
):
    payload = dict(render_payload or {})
    prefetch_metrics = prefetch_metrics or {}
    stage1_analysis = stage1_analysis or {}
    domain = str(payload.get("domain", "") or "").strip().lower()
    _, effective_domain = _resolve_effective_headless_target(
        str(payload.get("normalized_url", payload.get("url", "")) or ""),
        str(payload.get("final_landing_url", "") or ""),
        original_domain=domain,
    )
    html_content = str(payload.get("html_content", "") or "")
    words = set(payload.get("visible_text_words", set()) or set())
    resolved_weights = scoring_config["weights"]
    domain_similarity_floor = scoring_config["domain_similarity_threshold"]

    fav_task = favicon_hash_async(effective_domain, session=aio_session)
    ssl_task = get_ssl_hash_async(effective_domain)
    fav_hash, ssl_hash = await asyncio.gather(fav_task, ssl_task)

    n_entities = len(_entity_index["names"])
    typo_scores = np.asarray(prefetch_metrics["typo_scores"], dtype="float64")
    candidate_mask = np.array(prefetch_metrics["candidate_mask"], dtype=bool).copy()
    lexical_scores = np.asarray(prefetch_metrics["lexical_scores"], dtype="float64")
    jw_scores = np.asarray(prefetch_metrics["jw_scores"], dtype="float64")
    token_scores = np.asarray(prefetch_metrics["token_scores"], dtype="float64")
    lexical_rule_hit = np.array(prefetch_metrics["lexical_rule_hits"], dtype=bool)
    brand_token_hit = np.array(prefetch_metrics["brand_token_hits"], dtype=bool)
    candidate_reasons = list(prefetch_metrics["candidate_reasons"])
    stage1_candidate_entities = list(stage1_analysis.get("candidate_entities", []) or [])
    if stage1_candidate_entities:
        seeded_mask = np.zeros(n_entities, dtype=bool)
        stage1_best_domains = stage1_analysis.get("candidate_best_matching_domains", {}) or {}
        for entity_name in stage1_candidate_entities:
            try:
                entity_idx = _entity_index["names"].index(entity_name)
            except ValueError:
                continue
            seeded_mask[entity_idx] = True
            candidate_reasons[entity_idx] = f"{candidate_reasons[entity_idx]}|stage1_brand_seed".strip("|")
            best_domain = str(stage1_best_domains.get(entity_name, "") or "")
            if best_domain and len(prefetch_metrics.get("best_matching_domains", [])) > entity_idx:
                prefetch_metrics["best_matching_domains"][entity_idx] = best_domain
        if seeded_mask.any():
            candidate_mask = seeded_mask

    use_similarity_hashing = bool(_entity_index.get("use_similarity_hashing", False))
    page_hash = payload.get("page_hash")
    html_hash = payload.get("html_hash")
    domain_hash = payload.get("domain_hash")
    if use_similarity_hashing:
        (
            favicon_similarity,
            favicon_distance,
            favicon_hit,
            favicon_anchor,
        ) = _similarity_arrays_from_reference_sets(
            fav_hash,
            _entity_index["fav_similarity_refs"],
            hit_distance=_FAVICON_HASH_HIT_DISTANCE,
            anchor_distance=_FAVICON_HASH_ANCHOR_DISTANCE,
        )
        (
            ssl_hash_similarity,
            ssl_hash_distance,
            ssl_hash_hit,
            ssl_hash_anchor,
        ) = _similarity_arrays_from_reference_sets(
            ssl_hash,
            _entity_index["ssl_similarity_refs"],
            hit_distance=_SSL_HASH_HIT_DISTANCE,
            anchor_distance=_SSL_HASH_ANCHOR_DISTANCE,
        )
        (
            page_hash_similarity,
            page_hash_distance,
            html_hash_hit,
            html_hash_anchor,
        ) = _similarity_arrays_from_reference_sets(
            page_hash,
            _entity_index["page_similarity_refs"],
            hit_distance=_PAGE_HASH_HIT_DISTANCE,
            anchor_distance=_PAGE_HASH_ANCHOR_DISTANCE,
        )
        (
            domain_hash_similarity,
            domain_hash_distance,
            domain_hash_hit,
            domain_hash_anchor,
        ) = _similarity_arrays_from_reference_sets(
            domain_hash,
            _entity_index["domain_similarity_refs"],
            hit_distance=_DOMAIN_HASH_HIT_DISTANCE,
            anchor_distance=None,
        )
        hash_hit_count = (
            favicon_hit.astype(int)
            + ssl_hash_hit.astype(int)
            + html_hash_hit.astype(int)
            + domain_hash_hit.astype(int)
        )
        hash_bypass_mask = np.array(
            favicon_anchor | ssl_hash_anchor | html_hash_anchor | (hash_hit_count >= 2),
            dtype=bool,
        )
    else:
        hash_bypass_mask = np.zeros(n_entities, dtype=bool)
        favicon_similarity = np.zeros(n_entities, dtype="float64")
        favicon_distance = np.full(n_entities, -1, dtype="int32")
        favicon_hit = np.zeros(n_entities, dtype=bool)
        favicon_anchor = np.zeros(n_entities, dtype=bool)
        ssl_hash_similarity = np.zeros(n_entities, dtype="float64")
        ssl_hash_distance = np.full(n_entities, -1, dtype="int32")
        ssl_hash_hit = np.zeros(n_entities, dtype=bool)
        ssl_hash_anchor = np.zeros(n_entities, dtype=bool)
        page_hash_similarity = np.zeros(n_entities, dtype="float64")
        page_hash_distance = np.full(n_entities, -1, dtype="int32")
        html_hash_hit = np.zeros(n_entities, dtype=bool)
        html_hash_anchor = np.zeros(n_entities, dtype=bool)
        domain_hash_similarity = np.zeros(n_entities, dtype="float64")
        domain_hash_distance = np.full(n_entities, -1, dtype="int32")
        domain_hash_hit = np.zeros(n_entities, dtype=bool)
        domain_hash_anchor = np.zeros(n_entities, dtype=bool)
        if fav_hash:
            favicon_hit = np.array([fav_hash in _entity_index["fav_sets"][i] for i in range(n_entities)], dtype=bool)
            hash_bypass_mask |= favicon_hit
            favicon_similarity = favicon_hit.astype("float64")
            favicon_distance = np.where(favicon_hit, 0, -1).astype("int32")
            favicon_anchor = favicon_hit.copy()
        if ssl_hash:
            ssl_hash_hit = np.array([ssl_hash in _entity_index["ssl_hash_sets"][i] for i in range(n_entities)], dtype=bool)
            hash_bypass_mask |= ssl_hash_hit
            ssl_hash_similarity = ssl_hash_hit.astype("float64")
            ssl_hash_distance = np.where(ssl_hash_hit, 0, -1).astype("int32")
            ssl_hash_anchor = ssl_hash_hit.copy()
        if html_hash:
            html_hash_hit = np.array([html_hash in _entity_index["html_hash_sets"][i] for i in range(n_entities)], dtype=bool)
            hash_bypass_mask |= html_hash_hit
            page_hash_similarity = html_hash_hit.astype("float64")
            page_hash_distance = np.where(html_hash_hit, 0, -1).astype("int32")
            html_hash_anchor = html_hash_hit.copy()
        if domain_hash:
            domain_hash_hit = np.array([domain_hash in _entity_index["domain_hash_sets"][i] for i in range(n_entities)], dtype=bool)
            hash_bypass_mask |= domain_hash_hit
            domain_hash_similarity = domain_hash_hit.astype("float64")
            domain_hash_distance = np.where(domain_hash_hit, 0, -1).astype("int32")
    candidate_mask |= hash_bypass_mask
    for idx in np.where(hash_bypass_mask)[0]:
        candidate_reasons[idx] = f"{candidate_reasons[idx]}|hash_bypass".strip("|")

    cpu_scores = np.zeros(n_entities, dtype="float64")
    cpu_denominators = np.zeros(n_entities, dtype="float64")
    domain_hit = np.zeros(n_entities, dtype=bool)
    keyword_hit = np.zeros(n_entities, dtype=bool)
    for i in range(n_entities):
        if not candidate_mask[i]:
            continue
        entity_domains = _entity_index["domains"][i]
        if entity_domains:
            domain_sim = max(domain_similarity(effective_domain, d) for d in entity_domains)
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
            if favicon_hit[i]:
                cpu_scores[i] += resolved_weights["favicon"] * float(favicon_similarity[i])
        ssl_set = _entity_index["ssl_hash_sets"][i]
        if ssl_hash and ssl_set:
            cpu_denominators[i] += resolved_weights["ssl_hash"]
            if ssl_hash_hit[i]:
                cpu_scores[i] += resolved_weights["ssl_hash"] * float(ssl_hash_similarity[i])
        html_candidate_hash = page_hash if use_similarity_hashing else html_hash
        html_set = _entity_index["page_similarity_refs"][i] if use_similarity_hashing else _entity_index["html_hash_sets"][i]
        if html_candidate_hash and html_set:
            cpu_denominators[i] += resolved_weights["html_hash"]
            if html_hash_hit[i]:
                cpu_scores[i] += resolved_weights["html_hash"] * float(page_hash_similarity[i])
        domain_hash_set = _entity_index["domain_similarity_refs"][i] if use_similarity_hashing else _entity_index["domain_hash_sets"][i]
        if domain_hash and domain_hash_set:
            cpu_denominators[i] += resolved_weights["domain_hash"]
            if domain_hash_hit[i]:
                cpu_scores[i] += resolved_weights["domain_hash"] * float(domain_hash_similarity[i])
        if _entity_index["kw_sets"][i] and words:
            cpu_denominators[i] += resolved_weights["keywords"]
            overlap = len(words & _entity_index["kw_sets"][i])
            keyword_score = min(overlap / 5, 1.0) * resolved_weights["keywords"]
            cpu_scores[i] += keyword_score
            keyword_hit[i] = keyword_score > 0

    return {
        "url": payload["url"],
        "normalized_url": payload.get("normalized_url", payload["url"]),
        "source_workbook": payload.get("source_workbook", ""),
        "domain": domain,
        "final_domain": str(payload.get("final_domain", "") or effective_domain),
        "hash_mode": _hash_mode_label(),
        "fetch_status": payload.get("fetch_status", "fetched"),
        "visual_status": payload.get("visual_status", "available"),
        "fetch_error_type": payload.get("fetch_error_type", ""),
        "fetch_error_detail": payload.get("fetch_error_detail", ""),
        "final_landing_url": payload.get("final_landing_url", ""),
        "parking_provider": payload.get("parking_provider", ""),
        "parking_reason": payload.get("parking_reason", ""),
        "screenshot_path": payload.get("screenshot_path", ""),
        "favicon_hash_raw": fav_hash if fav_hash is not None else "",
        "ssl_hash_raw": ssl_hash if ssl_hash is not None else "",
        "html_hash_raw": html_hash if not use_similarity_hashing and html_hash is not None else "",
        "page_hash_raw": page_hash if use_similarity_hashing and page_hash is not None else "",
        "domain_hash_raw": domain_hash if domain_hash is not None else "",
        "html_title_text": payload.get("html_title_text", ""),
        "visible_text_excerpt": payload.get("visible_text_excerpt", ""),
        "screenshot_bytes": payload.get("screenshot_bytes"),
        "cpu_scores": cpu_scores,
        "cpu_denominators": cpu_denominators,
        "lexical_scores": lexical_scores,
        "jw_scores": jw_scores,
        "token_scores": token_scores,
        "domain_hit": domain_hit,
        "lexical_hit": np.array(lexical_rule_hit, dtype=bool),
        "lexical_rule_hit": lexical_rule_hit,
        "brand_token_hit": brand_token_hit,
        "generic_token_only_hit": np.array(prefetch_metrics.get("generic_token_only_hits", np.zeros(n_entities, dtype=bool)), dtype=bool),
        "favicon_hit": favicon_hit,
        "favicon_anchor": favicon_anchor,
        "favicon_hash_similarity": favicon_similarity,
        "favicon_hash_distance": favicon_distance,
        "ssl_hash_hit": ssl_hash_hit,
        "ssl_hash_anchor": ssl_hash_anchor,
        "ssl_hash_similarity": ssl_hash_similarity,
        "ssl_hash_distance": ssl_hash_distance,
        "html_hash_hit": html_hash_hit,
        "html_hash_anchor": html_hash_anchor,
        "page_hash_similarity": page_hash_similarity,
        "page_hash_distance": page_hash_distance,
        "domain_hash_hit": domain_hash_hit,
        "domain_hash_anchor": domain_hash_anchor,
        "domain_hash_similarity": domain_hash_similarity,
        "domain_hash_distance": domain_hash_distance,
        "keyword_hit": keyword_hit,
        "typo_scores": typo_scores,
        "candidate_mask": candidate_mask,
        "candidate_reasons": candidate_reasons,
        "best_matching_domains": list(prefetch_metrics.get("best_matching_domains", [])),
        "old_fuzzy_hit": prefetch_metrics["old_fuzzy_hit"],
        "old_fuzzy_cse": prefetch_metrics["old_fuzzy_cse"],
        "old_fuzzy_domain": prefetch_metrics["old_fuzzy_domain"],
        "old_fuzzy_score": prefetch_metrics["old_fuzzy_score"],
        "strict_lexical_hit": prefetch_metrics["strict_lexical_hit"],
        "lexical_score_pass": prefetch_metrics["lexical_score_pass"],
        "fallback_rank_only": prefetch_metrics["fallback_rank_only"],
        **{
            key: stage1_analysis.get(key, _STAGE1_SIGNAL_FIELD_DEFAULTS[key])
            for key in _STAGE1_SIGNAL_FIELD_DEFAULTS
        },
    }


###############################################
# BROWSER SHARDS
###############################################

async def _run_browser_shard(
    shard_id,
    url_queue,
    gpu_queue,
    metrics,
    decision_rows,
    prefetch_metrics_map,
    stage1_analysis_map,
    prefetch_admitted_failures,
    active_fetch_limiter,
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
                normalized_url = normalize_url(url)
                prefetch_metrics = prefetch_metrics_map.get(normalized_url)
                if prefetch_metrics is None:
                    prefetch_metrics = _compute_prefetch_lexical_state(url, scoring_config)
                    prefetch_metrics_map[normalized_url] = prefetch_metrics
                stage1_analysis = stage1_analysis_map.get(normalized_url, {})
                payload = await _fetch_url_payload(
                    url,
                    ctx,
                    semaphore,
                    active_fetch_limiter,
                    aio_session,
                    scoring_config,
                    prefetch_metrics=prefetch_metrics,
                    stage1_analysis=stage1_analysis,
                )
                payload_outcome = _handle_stage1_fetch_payload(
                    payload=payload,
                    normalized_url=normalized_url,
                    prefetch_metrics=prefetch_metrics,
                    scoring_config=scoring_config,
                    stage1_analysis=stage1_analysis,
                )
                queue_payload = _commit_legacy_shard_fetch_outcome(
                    payload_outcome,
                    metrics=metrics,
                    decision_rows=decision_rows,
                    prefetch_admitted_failures=prefetch_admitted_failures,
                )
                if queue_payload is not None:
                    await asyncio.wait_for(gpu_queue.put(queue_payload), timeout=5.0)
            except Exception as exc:
                normalized_url = normalize_url(url)
                prefetch_metrics = prefetch_metrics_map.get(normalized_url)
                if prefetch_metrics is None:
                    prefetch_metrics = _compute_prefetch_lexical_state(url, scoring_config)
                    prefetch_metrics_map[normalized_url] = prefetch_metrics
                stage1_analysis = stage1_analysis_map.get(normalized_url, {})
                payload_outcome = _handle_stage1_fetch_payload(
                    payload={
                        "url": normalized_url,
                        "normalized_url": normalized_url,
                        "fetch_status": "failed",
                        "visual_status": "not_attempted",
                        "fetch_error_type": "worker_error",
                        "fetch_error_detail": _compact_exception_message(exc),
                        "final_landing_url": "",
                        "parking_provider": "",
                        "parking_reason": "",
                    },
                    normalized_url=normalized_url,
                    prefetch_metrics=prefetch_metrics,
                    scoring_config=scoring_config,
                    stage1_analysis=stage1_analysis,
                )
                _commit_legacy_shard_fetch_outcome(
                    payload_outcome,
                    metrics=metrics,
                    decision_rows=decision_rows,
                    prefetch_admitted_failures=prefetch_admitted_failures,
                )
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


def _classify_stage1_admission(
    best_score: float,
    threshold: float,
    *,
    strict_lexical_hit: bool,
    lexical_score_pass: bool,
    hash_anchor: bool,
    clip_anchor: bool,
    weak_direct_evidence: bool = False,
    network_corroborated: bool = False,
    parked_sale_signal: bool = False,
) -> dict:
    admission_paths = []
    if best_score >= threshold:
        admission_paths.append("score_threshold")
    if hash_anchor:
        admission_paths.append("hash_bypass_hit")
    if clip_anchor:
        admission_paths.append("clip_anchor")
    lexical_survivor = bool(strict_lexical_hit or lexical_score_pass)
    if lexical_survivor and weak_direct_evidence:
        admission_paths.append("weak_direct_evidence")
    if lexical_survivor and network_corroborated:
        admission_paths.append("network_corroboration")
    if lexical_survivor and parked_sale_signal:
        admission_paths.append("parked_sale_signal")

    admitted_to_holdout = bool(admission_paths)
    kept_for_review_only = bool(not admitted_to_holdout and lexical_survivor)
    review_only_reason = ""
    if kept_for_review_only:
        review_only_reason = (
            "strict_lexical_below_holdout_threshold"
            if strict_lexical_hit
            else "lexical_score_pass_below_holdout_threshold"
        )

    return {
        "admitted_to_holdout": admitted_to_holdout,
        "kept_for_review_only": kept_for_review_only,
        "admission_paths": admission_paths,
        "admission_reason": "|".join(dict.fromkeys(admission_paths)),
        "review_only_reason": review_only_reason,
    }


def _build_shortlist_output_row(match: dict, scoring_config: dict) -> dict:
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

    return {
        "Cooresponding CSE": best_entity,
        "Legitimate Domains": legit_domain,
        "Identified Phishing/Suspected Domain Name": target_url,
        "source_workbook": match.get("source_workbook", ""),
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
        "stage1_passthrough": bool(match.get("stage1_passthrough", False)),
        "survival_path": match.get("survival_path", ""),
        "drop_path": match.get("drop_path", ""),
        "old_fuzzy_hit": bool(match.get("old_fuzzy_hit", False)),
        "old_fuzzy_cse": match.get("old_fuzzy_cse", ""),
        "hybrid_lexical_hit": bool(match.get("hybrid_lexical_hit", False)),
        "strict_lexical_hit": bool(match.get("strict_lexical_hit", False)),
        "lexical_score_pass": bool(match.get("lexical_score_pass", False)),
        "fallback_rank_only": bool(match.get("fallback_rank_only", False)),
        "admission_reason": match.get("admission_reason", ""),
        "admission_path": match.get("admission_path", ""),
        "fetch_status": match.get("fetch_status", "fetched"),
        "visual_status": match.get("visual_status", "not_attempted"),
        "fetch_error_type": match.get("fetch_error_type", ""),
        "fetch_error_detail": match.get("fetch_error_detail", ""),
        "final_landing_url": match.get("final_landing_url", ""),
        "parking_provider": match.get("parking_provider", ""),
        "parking_reason": match.get("parking_reason", ""),
        "placeholder_or_parking_reason": match.get("placeholder_or_parking_reason", match.get("parking_reason", "")),
        "best_score": round(float(match.get("best_score", best_score)), 4),
        "domain_component": round(float(match.get("domain_component", 0.0)), 4),
        "clip_component": round(float(match.get("clip_component", 0.0)), 4),
        "hash_component": round(float(match.get("hash_component", 0.0)), 4),
        "lexical_hit": bool(match.get("lexical_hit", False)),
        "brand_score": int(match.get("brand_score", 0) or 0),
        "credential_score": int(match.get("credential_score", 0) or 0),
        "infra_score": int(match.get("infra_score", 0) or 0),
        "evasion_score": int(match.get("evasion_score", 0) or 0),
        "total_stage1_score": int(match.get("total_stage1_score", 0) or 0),
        "hard_trigger_hit": bool(match.get("hard_trigger_hit", False)),
        "stage1_reasons": match.get("stage1_reasons", ""),
        "page_has_password_field": bool(match.get("page_has_password_field", False)),
        "page_has_login_form": bool(match.get("page_has_login_form", False)),
        "form_action_mismatch": bool(match.get("form_action_mismatch", False)),
        "csc_mention_count": int(match.get("csc_mention_count", 0) or 0),
        "redirect_count": int(match.get("redirect_count", 0) or 0),
        "final_domain": match.get("final_domain", ""),
        "favicon_domain": match.get("favicon_domain", ""),
        "html_bytes_read": int(match.get("html_bytes_read", 0) or 0),
        "escalate_to_hashing": bool(match.get("escalate_to_hashing", False)),
        "escalate_reason": match.get("escalate_reason", ""),
        "typo_similarity": round(float(match.get("typo_similarity", 0.0)), 4),
        "typo_min_score_used": round(float(scoring_config["typo_min_score"]), 4),
        "typo_decision_reason": (
            "anchor_typo" if bool(match.get("typo_anchor", False)) else "below_min_score"
        ),
        "clip_similarity": round(float(match.get("clip_similarity", 0.0)), 4),
        "favicon_hash_similarity": round(float(match.get("favicon_hash_similarity", 0.0) or 0.0), 4),
        "favicon_hash_distance": int(match.get("favicon_hash_distance", -1) or -1),
        "page_hash_similarity": round(float(match.get("page_hash_similarity", 0.0) or 0.0), 4),
        "page_hash_distance": int(match.get("page_hash_distance", -1) or -1),
        "domain_hash_similarity": round(float(match.get("domain_hash_similarity", 0.0) or 0.0), 4),
        "domain_hash_distance": int(match.get("domain_hash_distance", -1) or -1),
        "ssl_hash_similarity": round(float(match.get("ssl_hash_similarity", 0.0) or 0.0), 4),
        "ssl_hash_distance": int(match.get("ssl_hash_distance", -1) or -1),
        "typo_anchor": bool(match.get("typo_anchor", False)),
        "hash_anchor": bool(match.get("hash_anchor", False)),
        "clip_anchor": bool(match.get("clip_anchor", False)),
        "generic_token_only_match": bool(match.get("generic_token_only_match", False)),
        "direct_brand_evidence_count": int(match.get("direct_brand_evidence_count", 0) or 0),
        "deceptive_host_embedding": bool(match.get("deceptive_host_embedding", False)),
        "content_spoof_strong": bool(match.get("content_spoof_strong", False)),
        "clip_corroborated": bool(match.get("clip_corroborated", False)),
        "signal_hit_screenshot": bool(match["signal_hit_screenshot"]),
        "signal_hit_typo": bool(match.get("signal_hit_typo", False)),
        "signal_hit_domain": bool(match["signal_hit_domain"]),
        "signal_hit_favicon": bool(match["signal_hit_favicon"]),
        "signal_hit_ssl_hash": bool(match["signal_hit_ssl_hash"]),
        "signal_hit_html_hash": bool(match["signal_hit_html_hash"]),
        "signal_hit_domain_hash": bool(match["signal_hit_domain_hash"]),
        "signal_hit_keywords": bool(match["signal_hit_keywords"]),
        "screenshot_path": match.get("screenshot_path", ""),
        "html_title_text": match.get("html_title_text", ""),
        "visible_text_excerpt": match.get("visible_text_excerpt", ""),
    }


def _count_shortlist_aligned_page_brand_evidence(best_idx: int, payload: dict) -> int:
    page_tokens = _extract_page_brand_tokens(
        " ".join(
            part
            for part in [
                str(payload.get("html_title_text", "") or ""),
                str(payload.get("visible_text_excerpt", "") or ""),
            ]
            if part
        )
    )
    redirect_tokens = set()
    for value in (
        str(payload.get("final_landing_url", "") or ""),
        str(payload.get("final_domain", "") or ""),
    ):
        redirect_tokens |= _extract_brand_tokens(value)
    surface_tokens = page_tokens | redirect_tokens
    if not surface_tokens or best_idx < 0:
        return 0
    entity_tokens = {
        token
        for token in _entity_index["brand_tokens"][best_idx]
        if token and not _is_generic_service_token(token)
    }
    if len(_entity_index["names"]) > best_idx:
        entity_tokens |= _extract_entity_name_tokens(_entity_index["names"][best_idx])
    keyword_tokens = set()
    for keyword in _entity_index["kw_sets"][best_idx]:
        keyword_tokens |= _extract_page_brand_tokens(keyword)
    aligned_tokens = surface_tokens & (entity_tokens | keyword_tokens)
    return len(aligned_tokens)


def _finalize_scored_hash_payload(
    payload: dict,
    scores: np.ndarray,
    denominators: np.ndarray,
    screenshot_hit: np.ndarray,
    screenshot_similarity: np.ndarray,
    metrics: dict,
    results: list,
    review_results: list,
    decision_rows: list,
    threshold: float,
    scoring_config: dict,
) -> None:
    resolved_weights = scoring_config["weights"]
    n_entities = len(_entity_index["names"])
    candidate_mask = payload.get("candidate_mask")
    if candidate_mask is None:
        candidate_mask = np.ones(n_entities, dtype=bool)
    else:
        candidate_mask = np.array(candidate_mask, dtype=bool)

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
    best_matching_domains = list(payload.get("best_matching_domains", []))
    best_matching_domain = str(best_matching_domains[best_idx] or "") if len(best_matching_domains) > best_idx else ""
    final_domain = str(
        payload.get("final_domain", "")
        or (urlparse(str(payload.get("final_landing_url", "") or "")).hostname or str(payload.get("domain", "") or ""))
    ).strip().lower()
    deceptive_host_embedding = _has_deceptive_host_embedding(final_domain, best_matching_domain)
    lexical_rule_hit = bool(payload["lexical_rule_hit"][best_idx])
    brand_token_hit = bool(payload["brand_token_hit"][best_idx])
    generic_token_only_match = bool(payload.get("generic_token_only_hit", np.zeros(n_entities, dtype=bool))[best_idx])
    typo_anchor = lexical_rule_hit and best_typo_similarity >= scoring_config["typo_min_score"]
    favicon_hit = bool(payload["favicon_hit"][best_idx])
    ssl_hash_hit = bool(payload["ssl_hash_hit"][best_idx])
    html_hash_hit = bool(payload["html_hash_hit"][best_idx])
    domain_hash_hit = bool(payload["domain_hash_hit"][best_idx])
    favicon_anchor = bool(payload.get("favicon_anchor", np.zeros(n_entities, dtype=bool))[best_idx])
    ssl_hash_anchor = bool(payload.get("ssl_hash_anchor", np.zeros(n_entities, dtype=bool))[best_idx])
    html_hash_anchor = bool(payload.get("html_hash_anchor", np.zeros(n_entities, dtype=bool))[best_idx])
    hash_hit_count = sum(
        int(flag)
        for flag in (favicon_hit, ssl_hash_hit, html_hash_hit, domain_hash_hit)
    )
    hash_anchor = bool(
        favicon_anchor
        or ssl_hash_anchor
        or html_hash_anchor
        or hash_hit_count >= 2
    )
    favicon_hash_similarity = float(payload.get("favicon_hash_similarity", np.zeros(n_entities, dtype="float64"))[best_idx])
    favicon_hash_distance = int(payload.get("favicon_hash_distance", np.full(n_entities, -1, dtype="int32"))[best_idx])
    ssl_hash_similarity = float(payload.get("ssl_hash_similarity", np.zeros(n_entities, dtype="float64"))[best_idx])
    ssl_hash_distance = int(payload.get("ssl_hash_distance", np.full(n_entities, -1, dtype="int32"))[best_idx])
    page_hash_similarity = float(payload.get("page_hash_similarity", np.zeros(n_entities, dtype="float64"))[best_idx])
    page_hash_distance = int(payload.get("page_hash_distance", np.full(n_entities, -1, dtype="int32"))[best_idx])
    domain_hash_similarity = float(payload.get("domain_hash_similarity", np.zeros(n_entities, dtype="float64"))[best_idx])
    domain_hash_distance = int(payload.get("domain_hash_distance", np.full(n_entities, -1, dtype="int32"))[best_idx])
    best_clip_similarity = 0.0
    direct_brand_evidence_count = _count_shortlist_aligned_page_brand_evidence(best_idx, payload)
    clip_corroborated = False
    clip_anchor = False
    old_fuzzy_hit = bool(payload.get("old_fuzzy_hit", False))
    old_fuzzy_cse = str(payload.get("old_fuzzy_cse", "") or "")
    hybrid_lexical_hit = bool(lexical_rule_hit or brand_token_hit)
    strict_lexical_hit = bool(payload.get("strict_lexical_hit", False) or old_fuzzy_hit or hybrid_lexical_hit)
    candidate_generation_reason = payload["candidate_reasons"][best_idx] or "fallback_top_k"
    fallback_rank_only = bool(
        payload.get("fallback_rank_only", False)
        or ("fallback_top_k" in candidate_generation_reason and not strict_lexical_hit)
    )
    lexical_score_pass = bool(
        payload.get("lexical_score_pass", False)
        or (best_lexical_score >= scoring_config["lexical_pass_min_score"] and not fallback_rank_only)
    )
    if generic_token_only_match:
        strict_lexical_hit = False
        lexical_score_pass = False
    content_spoof_strong = bool(
        strict_lexical_hit
        and deceptive_host_embedding
        and direct_brand_evidence_count >= DEFAULT_CONTENT_SPOOF_STRONG_DIRECT_BRAND_MIN
    )
    stage1_http_suspicious = any(
        (
            int(payload.get("brand_score", 0) or 0) > 0,
            int(payload.get("credential_score", 0) or 0) > 0,
            int(payload.get("infra_score", 0) or 0) > 0,
            int(payload.get("evasion_score", 0) or 0) > 0,
            bool(payload.get("hard_trigger_hit", False)),
        )
    )
    parked_sale_signal = bool(str(payload.get("parking_reason", "") or "").strip())
    weak_direct_evidence = bool(
        stage1_http_suspicious
        or direct_brand_evidence_count > 0
        or bool(payload["keyword_hit"][best_idx])
        or bool(payload["domain_hit"][best_idx])
        or favicon_hit
        or ssl_hash_hit
        or html_hash_hit
        or domain_hash_hit
        or deceptive_host_embedding
        or content_spoof_strong
    )
    evidence_tier = (
        "strong_evidence"
        if lexical_rule_hit and hash_anchor
        else "weak_evidence"
    )
    hash_contribution = float(
        (favicon_hash_similarity * resolved_weights["favicon"] if favicon_hit else 0.0)
        + (ssl_hash_similarity * resolved_weights["ssl_hash"] if ssl_hash_hit else 0.0)
        + (page_hash_similarity * resolved_weights["html_hash"] if html_hash_hit else 0.0)
        + (domain_hash_similarity * resolved_weights["domain_hash"] if domain_hash_hit else 0.0)
    )
    lexical_contribution = best_lexical_score * resolved_weights["domain"]
    dominant_signal_family = max(
        (
            ("lexical", lexical_contribution),
            ("hash", hash_contribution),
        ),
        key=lambda item: item[1],
    )[0]
    admission_decision = _classify_stage1_admission(
        best_score=best_score,
        threshold=threshold,
        strict_lexical_hit=strict_lexical_hit,
        lexical_score_pass=lexical_score_pass,
        hash_anchor=hash_anchor,
        clip_anchor=clip_anchor,
        weak_direct_evidence=weak_direct_evidence,
        network_corroborated=True,
        parked_sale_signal=parked_sale_signal,
    )
    admitted_to_holdout = bool(admission_decision["admitted_to_holdout"])
    kept_for_review_only = bool(admission_decision["kept_for_review_only"])
    admission_paths = list(admission_decision["admission_paths"])
    admission_reason = str(admission_decision["admission_reason"] or "")
    review_only_reason = str(admission_decision["review_only_reason"] or "")

    decision_rows.append(
        {
            "raw_url": payload["url"],
            "normalized_url": payload.get("normalized_url", payload["url"]),
            "hashed_at_utc": utc_now_iso(),
            "target_url_sha256": sha256_text(payload.get("normalized_url", payload["url"])) if payload.get("normalized_url", payload["url"]) else "",
            "hash_mode": _hash_mode_label(),
            "domain": payload.get("domain", ""),
            "final_domain": final_domain,
            "source_workbook": payload.get("source_workbook", ""),
            "fetch_status": payload.get("fetch_status", "fetched"),
            "visual_status": payload.get("visual_status", "not_attempted"),
            "fetch_error_type": payload.get("fetch_error_type", ""),
            "fetch_error_detail": payload.get("fetch_error_detail", ""),
            "final_landing_url": payload.get("final_landing_url", ""),
            "parking_provider": payload.get("parking_provider", ""),
            "parking_reason": payload.get("parking_reason", ""),
            "screenshot_path": payload.get("screenshot_path", ""),
            "placeholder_or_parking_reason": payload.get("parking_reason", ""),
            "admitted": admitted_to_holdout,
            "admitted_to_holdout": admitted_to_holdout,
            "kept_for_review_only": kept_for_review_only,
            "review_only_reason": review_only_reason,
            "old_fuzzy_hit": old_fuzzy_hit,
            "old_fuzzy_cse": old_fuzzy_cse,
            "hybrid_lexical_hit": hybrid_lexical_hit,
            "strict_lexical_hit": strict_lexical_hit,
            "lexical_score_pass": lexical_score_pass,
            "fallback_rank_only": fallback_rank_only,
            "admission_reason": admission_reason,
            "admission_path": "|".join(dict.fromkeys(admission_paths)),
            "candidate_generation_reason": candidate_generation_reason,
            "best_entity": best_entity,
            "best_matching_domain": best_matching_domain,
            "best_score": round(best_score, 4),
            "score_margin": round(score_margin, 4),
            "confidence_band": confidence_band,
            "lexical_score": round(best_lexical_score, 4),
            **{
                key: payload.get(key, _STAGE1_SIGNAL_FIELD_DEFAULTS[key])
                for key in _STAGE1_SIGNAL_FIELD_DEFAULTS
            },
            "clip_similarity": round(best_clip_similarity, 4),
            "typo_similarity": round(best_typo_similarity, 4),
            "generic_token_only_match": generic_token_only_match,
            "direct_brand_evidence_count": direct_brand_evidence_count,
            "deceptive_host_embedding": deceptive_host_embedding,
            "content_spoof_strong": content_spoof_strong,
            "favicon_hash_similarity": round(favicon_hash_similarity, 4),
            "favicon_hash_distance": favicon_hash_distance,
            "page_hash_similarity": round(page_hash_similarity, 4),
            "page_hash_distance": page_hash_distance,
            "domain_hash_similarity": round(domain_hash_similarity, 4),
            "domain_hash_distance": domain_hash_distance,
            "ssl_hash_similarity": round(ssl_hash_similarity, 4),
            "ssl_hash_distance": ssl_hash_distance,
            "signal_hit_favicon": bool(payload["favicon_hit"][best_idx]),
            "signal_hit_ssl_hash": bool(payload["ssl_hash_hit"][best_idx]),
            "signal_hit_html_hash": bool(payload["html_hash_hit"][best_idx]),
            "signal_hit_domain_hash": bool(payload["domain_hash_hit"][best_idx]),
            "hash_anchor": bool(hash_anchor),
            "favicon_hash_raw": _coerce_hash_export_text(payload.get("favicon_hash_raw", "")),
            "ssl_hash_raw": _coerce_hash_export_text(payload.get("ssl_hash_raw", "")),
            "html_hash_raw": _coerce_hash_export_text(payload.get("html_hash_raw", "")),
            "page_hash_raw": _coerce_hash_export_text(payload.get("page_hash_raw", "")),
            "domain_hash_raw": _coerce_hash_export_text(payload.get("domain_hash_raw", "")),
            "clip_corroborated": clip_corroborated,
            "stage1_passthrough": False,
            "survival_path": "|".join(dict.fromkeys(admission_paths)) if admitted_to_holdout else (review_only_reason if kept_for_review_only else ""),
            "drop_path": "" if (admitted_to_holdout or kept_for_review_only) else "not_admitted_after_lexical_and_hash_checks",
            "domain_component": round(lexical_contribution, 4),
            "clip_component": 0.0,
            "hash_component": round(hash_contribution, 4),
            "review_reason": review_only_reason,
        }
    )

    shortlist_record = {
        "url": payload["url"],
        "source_workbook": payload.get("source_workbook", ""),
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
        "stage1_passthrough": False,
        "survival_path": "|".join(dict.fromkeys(admission_paths)) if admitted_to_holdout else (review_only_reason if kept_for_review_only else ""),
        "drop_path": "" if admitted_to_holdout else ("not_admitted_after_lexical_and_hash_checks" if not kept_for_review_only else ""),
        "old_fuzzy_hit": old_fuzzy_hit,
        "old_fuzzy_cse": old_fuzzy_cse,
        "hybrid_lexical_hit": hybrid_lexical_hit,
        "strict_lexical_hit": strict_lexical_hit,
        "lexical_score_pass": lexical_score_pass,
        "fallback_rank_only": fallback_rank_only,
        "admission_reason": admission_reason,
        "admission_path": "|".join(dict.fromkeys(admission_paths)),
        "fetch_status": payload.get("fetch_status", "fetched"),
        "visual_status": payload.get("visual_status", "not_attempted"),
        "fetch_error_type": payload.get("fetch_error_type", ""),
        "fetch_error_detail": payload.get("fetch_error_detail", ""),
        "final_landing_url": payload.get("final_landing_url", ""),
        "parking_provider": payload.get("parking_provider", ""),
        "parking_reason": payload.get("parking_reason", ""),
        "placeholder_or_parking_reason": payload.get("parking_reason", ""),
        "domain_component": lexical_contribution,
        "clip_component": 0.0,
        "hash_component": hash_contribution,
        **{
            key: payload.get(key, _STAGE1_SIGNAL_FIELD_DEFAULTS[key])
            for key in _STAGE1_SIGNAL_FIELD_DEFAULTS
        },
        "typo_similarity": best_typo_similarity,
        "clip_similarity": best_clip_similarity,
        "typo_anchor": bool(typo_anchor),
        "hash_anchor": bool(hash_anchor),
        "clip_anchor": bool(clip_anchor),
        "signal_hit_screenshot": False,
        "signal_hit_typo": bool(typo_anchor),
        "signal_hit_domain": bool(payload["domain_hit"][best_idx]),
        "signal_hit_favicon": bool(payload["favicon_hit"][best_idx]),
        "signal_hit_ssl_hash": bool(payload["ssl_hash_hit"][best_idx]),
        "signal_hit_html_hash": bool(payload["html_hash_hit"][best_idx]),
        "signal_hit_domain_hash": bool(payload["domain_hash_hit"][best_idx]),
        "signal_hit_keywords": bool(payload["keyword_hit"][best_idx]),
        "generic_token_only_match": generic_token_only_match,
        "direct_brand_evidence_count": direct_brand_evidence_count,
        "deceptive_host_embedding": deceptive_host_embedding,
        "content_spoof_strong": content_spoof_strong,
        "favicon_hash_similarity": favicon_hash_similarity,
        "favicon_hash_distance": favicon_hash_distance,
        "page_hash_similarity": page_hash_similarity,
        "page_hash_distance": page_hash_distance,
        "domain_hash_similarity": domain_hash_similarity,
        "domain_hash_distance": domain_hash_distance,
        "ssl_hash_similarity": ssl_hash_similarity,
        "ssl_hash_distance": ssl_hash_distance,
        "clip_corroborated": clip_corroborated,
        "screenshot_path": payload.get("screenshot_path", ""),
        "html_title_text": payload.get("html_title_text", ""),
        "visible_text_excerpt": payload.get("visible_text_excerpt", ""),
    }

    if admitted_to_holdout:
        metrics["final_matches_above_threshold"] += 1
        results.append(shortlist_record)
    elif kept_for_review_only:
        review_record = dict(shortlist_record)
        review_record["review_reason"] = review_only_reason
        review_results.append(review_record)


async def _gpu_microbatch_scorer(gpu_queue, results, review_results, decision_rows, metrics, threshold, scoring_config, hash_progress=None):
    """
    Queue scorer for browser-fetched payloads.
    CLIP runtime scoring is disabled; payloads are finalized with hash/domain signals only.
    """
    batch = []
    deadline = None

    async def _flush():
        nonlocal batch, deadline
        if not batch:
            return
        current_batch = batch
        batch = []
        deadline = None
        n_entities = len(_entity_index["names"])
        metrics["gpu_batches_flushed"] += 1
        metrics["gpu_items_scored"] += len(current_batch)
        metrics["avg_gpu_batch_size"] = (
            metrics["gpu_items_scored"] / max(1, metrics["gpu_batches_flushed"])
        )

        for payload in current_batch:
            scores = payload["cpu_scores"].copy()
            denominators = payload["cpu_denominators"].copy()
            screenshot_hit = np.zeros(n_entities, dtype=bool)
            screenshot_similarity = np.zeros(n_entities, dtype="float64")
            _finalize_scored_hash_payload(
                payload=payload,
                scores=scores,
                denominators=denominators,
                screenshot_hit=screenshot_hit,
                screenshot_similarity=screenshot_similarity,
                metrics=metrics,
                results=results,
                review_results=review_results,
                decision_rows=decision_rows,
                threshold=threshold,
                scoring_config=scoring_config,
            )
            metrics["hashed_success"] += 1
            metrics["processed"] += 1
            metrics["finalized"] += 1
            if hash_progress is not None:
                hash_progress.mark_completed(final_status="hashed_success")

    while True:
        loop = asyncio.get_running_loop()
        now = loop.time()
        wait = None if deadline is None else max(0.001, deadline - now)
        try:
            payload = await asyncio.wait_for(gpu_queue.get(), timeout=wait)
            if payload is None:  # sentinel â€” flush and exit
                await _flush()
                gpu_queue.task_done()
                break
            batch.append(payload)
            if deadline is None:
                deadline = loop.time() + GPU_MAX_WAIT_MS / 1000
            if len(batch) >= GPU_MAX_BATCH_SIZE:
                await _flush()
            gpu_queue.task_done()
        except asyncio.TimeoutError:
            await _flush()


###############################################
# PROGRESS HELPERS
###############################################

def _build_progress_postfix(metrics):
    elapsed = max(float(metrics.get("stage_elapsed_s", 0.0)), 1e-6)
    if str(metrics.get("hash_execution_mode", "")).strip().lower() == "legacy_shards":
        return {
            "proc": metrics.get("processed", 0),
            "ok": metrics.get("hashed_success", 0),
            "fail": metrics.get("fetch_failed", 0),
            "tout": metrics.get("fetch_timed_out", 0),
            "match": metrics.get("final_matches_above_threshold", 0),
            "gpu_batches": metrics.get("gpu_batches_flushed", 0),
            "gpu_items": metrics.get("gpu_items_scored", 0),
            "gpu_queue": metrics.get("gpu_queue_depth", 0),
            "active_fetch": metrics.get("active_fetch_limit", 0),
            "urls_per_sec": round(metrics.get("processed", 0) / elapsed, 2),
        }
    return {
        "proc": metrics.get("processed", 0),
        "render": metrics.get("render_completed", 0),
        "aux": metrics.get("aux_completed", 0),
        "ok": metrics.get("hashed_success", 0),
        "fail": metrics.get("fetch_failed", 0),
        "tout": metrics.get("fetch_timed_out", 0),
        "match": metrics.get("final_matches_above_threshold", 0),
        "final_q": metrics.get("gpu_queue_depth", 0),
        "render_q": metrics.get("render_queue_depth", 0),
        "aux_q": metrics.get("aux_queue_depth", 0),
        "active": metrics.get("active_fetch_limit", 0),
        "live": metrics.get("live_page_workers", 0),
        "phase": metrics.get("phase", "running"),
        "urls_per_sec": round(metrics.get("processed", 0) / elapsed, 2),
    }


def _log_hashing_periodic_status(metrics, accepted_count):
    processed = int(metrics.get("processed", 0))
    if processed <= 0:
        return
    timeout_ratio = metrics.get("fetch_timed_out", 0) / max(1, processed)
    success_ratio = metrics.get("hashed_success", 0) / max(1, processed)
    if str(metrics.get("hash_execution_mode", "")).strip().lower() == "legacy_shards":
        _clip_logger.info(
            "Hashing progress | processed=%d/%d | ok=%d | fail=%d | tout=%d | match=%d | "
            "gpu_batches=%d | gpu_items=%d | gpu_queue=%d | active_fetch_limit=%d | avg_gpu_batch=%.2f | "
            "urls_per_sec=%.2f | success_ratio=%.3f | timeout_ratio=%.3f",
            processed,
            accepted_count,
            metrics.get("hashed_success", 0),
            metrics.get("fetch_failed", 0),
            metrics.get("fetch_timed_out", 0),
            metrics.get("final_matches_above_threshold", 0),
            metrics.get("gpu_batches_flushed", 0),
            metrics.get("gpu_items_scored", 0),
            metrics.get("gpu_queue_depth", 0),
            metrics.get("active_fetch_limit", 0),
            metrics.get("avg_gpu_batch_size", 0.0),
            processed / max(float(metrics.get("stage_elapsed_s", 0.0)), 1e-6),
            success_ratio,
            timeout_ratio,
        )
        return
    _clip_logger.info(
        "Hashing progress | phase=%s | processed=%d/%d | render=%d | aux=%d | ok=%d | fail=%d | tout=%d | match=%d | "
        "queues={render=%d,aux=%d,final=%d} | nodes_alive=%d | live_pages=%d | active_pages=%d | shutdown={expected=%d,drained=%d} | "
        "finalized=%d | avg_finalize_batch=%.2f | urls_per_sec=%.2f | success_ratio=%.3f | timeout_ratio=%.3f | fd=%d/%d | ram=%.1f%% | target=%.1f | limiting_lane=%s",
        metrics.get("phase", "running"),
        processed,
        accepted_count,
        metrics.get("render_completed", 0),
        metrics.get("aux_completed", 0),
        metrics.get("hashed_success", 0),
        metrics.get("fetch_failed", 0),
        metrics.get("fetch_timed_out", 0),
        metrics.get("final_matches_above_threshold", 0),
        metrics.get("render_queue_depth", 0),
        metrics.get("aux_queue_depth", 0),
        metrics.get("gpu_queue_depth", 0),
        metrics.get("worker_nodes_alive", 0),
        metrics.get("live_page_workers", 0),
        metrics.get("active_fetch_limit", 0),
        metrics.get("shutdown_sentinels_expected", 0),
        metrics.get("shutdown_sentinels_drained", 0),
        metrics.get("gpu_items_scored", 0),
        metrics.get("avg_gpu_batch_size", 0.0),
        processed / max(float(metrics.get("stage_elapsed_s", 0.0)), 1e-6),
        success_ratio,
        timeout_ratio,
        metrics.get("fd_count", 0),
        metrics.get("fd_limit", 0),
        metrics.get("ram_usage_ratio", 0.0) * 100.0,
        HASH_TARGET_URLS_PER_SEC,
        metrics.get("limiting_lane", "render"),
    )


def _log_hashing_metrics_summary(
    metrics,
    elapsed,
    threshold,
    shortlisted_results=None,
    typo_min_score=None,
):
    _clip_logger.info(
        "Hashing shortlist completed | processed=%d | "
        "hashed_success=%d | fetch_failed=%d | fetch_timed_out=%d | "
        "final_matches=%d | gpu_batches=%d | gpu_items=%d | avg_gpu_batch=%.1f | urls_per_sec=%.2f | "
        "threshold=%s | elapsed=%.1fs",
        metrics["processed"],
        metrics["hashed_success"],
        metrics["fetch_failed"],
        metrics["fetch_timed_out"],
        metrics["final_matches_above_threshold"],
        metrics["gpu_batches_flushed"],
        metrics.get("gpu_items_scored", 0),
        metrics["avg_gpu_batch_size"],
        metrics["processed"] / max(elapsed, 1e-6),
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


def _commit_terminal_hash_outcome(
    payload_outcome,
    *,
    metrics,
    decision_rows,
    prefetch_admitted_failures,
    hash_progress,
):
    if payload_outcome["decision_row"] is not None:
        decision_rows.append(payload_outcome["decision_row"])
    admitted_prefetch_match = payload_outcome["admitted_prefetch_match"]
    if admitted_prefetch_match is not None:
        metrics["final_matches_above_threshold"] += 1
        prefetch_admitted_failures.append(admitted_prefetch_match)
    metrics[payload_outcome["metric_key"]] += 1
    metrics["processed"] += 1
    metrics["finalized"] += 1
    hash_progress.mark_completed(final_status=payload_outcome["metric_key"])


def _commit_legacy_shard_fetch_outcome(
    payload_outcome,
    *,
    metrics,
    decision_rows,
    prefetch_admitted_failures,
):
    if payload_outcome["decision_row"] is not None:
        decision_rows.append(payload_outcome["decision_row"])
    admitted_prefetch_match = payload_outcome["admitted_prefetch_match"]
    if admitted_prefetch_match is not None:
        metrics["final_matches_above_threshold"] += 1
        prefetch_admitted_failures.append(admitted_prefetch_match)
    if payload_outcome["queue_payload"] is None:
        metrics[payload_outcome["metric_key"]] += 1
        metrics["processed"] += 1
        metrics["finalized"] += 1
    return payload_outcome["queue_payload"]


def _set_hash_worker_state(
    worker_states,
    worker_id,
    *,
    node_id,
    page_worker_id,
    phase,
    current_url="",
    consecutive_failures=0,
):
    worker_states[worker_id] = {
        "node_id": int(node_id),
        "page_worker_id": int(page_worker_id),
        "phase": str(phase or ""),
        "current_url": str(current_url or ""),
        "consecutive_failures": int(max(0, consecutive_failures)),
        "last_progress_monotonic": time.monotonic(),
    }


def _summarize_hash_worker_states(worker_states):
    phase_counts = Counter()
    stale_workers = {}
    now = time.monotonic()
    for worker_id, state in list(worker_states.items()):
        phase = str(state.get("phase", "") or "unknown")
        phase_counts[phase] += 1
        age = max(0.0, now - float(state.get("last_progress_monotonic", now) or now))
        if age >= 60.0:
            stale_workers[worker_id] = {
                "phase": phase,
                "url": str(state.get("current_url", "") or ""),
                "age_seconds": round(age, 1),
                "node_id": int(state.get("node_id", -1) or -1),
                "page_worker_id": int(state.get("page_worker_id", -1) or -1),
            }
    return {
        "live_page_workers": len(worker_states),
        "phase_counts": dict(phase_counts),
        "stale_workers": stale_workers,
    }


def _desired_hash_worker_nodes(active_page_limit: int) -> int:
    desired = int(math.ceil(max(1, active_page_limit) / max(1, HASH_PAGES_PER_NODE)))
    desired = max(HASH_WORKER_NODES_START, desired)
    return max(1, min(HASH_WORKER_NODES_MAX, desired))


def _drain_asyncio_queue_nowait(queue) -> int:
    drained = 0
    while True:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            break
        else:
            queue.task_done()
            drained += 1
    return drained


async def _queue_hash_lane_item(queue, item, *, lane_name, metrics, active_fetch_limiter):
    while True:
        try:
            await asyncio.wait_for(queue.put(item), timeout=2.0)
            return
        except asyncio.TimeoutError:
            metrics["limiting_lane"] = lane_name
            if active_fetch_limiter.limit > ACTIVE_FETCH_LIMIT_FLOOR:
                await active_fetch_limiter.set_limit(max(ACTIVE_FETCH_LIMIT_FLOOR, active_fetch_limiter.limit - ACTIVE_FETCH_DOWNSHIFT_STEP))
                metrics["active_fetch_limit"] = active_fetch_limiter.limit
            _clip_logger.warning(
                "Hash %s queue saturated | depth=%d | active_pages=%d",
                lane_name,
                queue.qsize(),
                active_fetch_limiter.limit,
            )


async def _reset_hash_page(page, browser_context, *, recycle: bool):
    if page is not None and not page.is_closed():
        if recycle:
            with suppress(Exception):
                await asyncio.wait_for(page.close(), timeout=3.0)
            page = None
        else:
            try:
                await asyncio.wait_for(
                    page.goto("about:blank", wait_until="domcontentloaded", timeout=3000),
                    timeout=3.0,
                )
            except Exception:
                with suppress(Exception):
                    await asyncio.wait_for(page.close(), timeout=3.0)
                page = None
    if page is None:
        page = await asyncio.wait_for(browser_context.new_page(), timeout=5.0)
    return page


async def _run_hash_browser_node(
    *,
    node_id,
    render_queue,
    aux_queue,
    metrics,
    decision_rows,
    prefetch_admitted_failures,
    prefetch_metrics_map,
    stage1_analysis_map,
    active_fetch_limiter,
    host_limiter,
    hash_progress,
    scoring_config,
    active_workers,
    worker_states,
    worker_tasks,
):
    p = None
    browser = None
    ctx = None
    try:
        p = await async_playwright().start()
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(ignore_https_errors=True, service_workers="block")
        await ctx.route("**/*", _route_nonessential_requests)
        ctx.set_default_navigation_timeout(SCRAPER_NAV_TIMEOUT_MS)
        ctx.set_default_timeout(SCRAPER_SCREENSHOT_TIMEOUT_MS)
    except Exception as exc:
        _clip_logger.warning(
            "Hash browser node %s startup failed: %s: %s",
            node_id,
            exc.__class__.__name__,
            _compact_exception_message(exc),
        )
        for cleanup in (ctx.close if ctx is not None else None, browser.close if browser is not None else None, p.stop if p is not None else None):
            if cleanup is None:
                continue
            with suppress(Exception):
                await asyncio.wait_for(cleanup(), timeout=10.0)
        return

    async def _page_worker(slot_id: int):
        worker_id = f"node-{node_id}:page-{slot_id}"
        worker_tasks[worker_id] = asyncio.current_task()
        _set_hash_worker_state(
            worker_states,
            worker_id,
            node_id=node_id,
            page_worker_id=slot_id,
            phase="starting",
        )
        page = None
        urls_since_recycle = 0
        consecutive_failures = 0
        try:
            page = await _reset_hash_page(None, ctx, recycle=False)
            _set_hash_worker_state(
                worker_states,
                worker_id,
                node_id=node_id,
                page_worker_id=slot_id,
                phase="idle",
                consecutive_failures=consecutive_failures,
            )
            while True:
                item_taken = False
                raw_url = ""
                normalized_url = ""
                prefetch_metrics = {}
                stage1_analysis = {}
                recycle_page = False
                cancel_requested = False
                cancel_error = None
                item = await render_queue.get()
                item_taken = True
                if item is None:
                    _set_hash_worker_state(
                        worker_states,
                        worker_id,
                        node_id=node_id,
                        page_worker_id=slot_id,
                        phase="shutdown",
                        consecutive_failures=consecutive_failures,
                    )
                    render_queue.task_done()
                    break
                raw_url = str(item.get("url", "") or "")
                normalized_url = str(item.get("normalized_url", "") or normalize_url(raw_url))
                prefetch_metrics = item.get("prefetch_metrics") or prefetch_metrics_map.get(normalized_url) or {}
                stage1_analysis = item.get("stage1_analysis") or stage1_analysis_map.get(normalized_url, {}) or {}
                active_workers[worker_id] = normalized_url
                _set_hash_worker_state(
                    worker_states,
                    worker_id,
                    node_id=node_id,
                    page_worker_id=slot_id,
                    phase="render",
                    current_url=normalized_url,
                    consecutive_failures=consecutive_failures,
                )
                try:
                    render_payload = await _render_hash_payload_on_page(
                        raw_url,
                        page,
                        active_fetch_limiter,
                        host_limiter,
                        prefetch_metrics=prefetch_metrics,
                        stage1_analysis=stage1_analysis,
                    )
                    metrics["render_completed"] += 1
                    if str(render_payload.get("fetch_status", "")).strip().lower() in {"fetched", "fetched_visual_missing"}:
                        await _queue_hash_lane_item(
                            aux_queue,
                            {
                                "render_payload": render_payload,
                                "prefetch_metrics": prefetch_metrics,
                                "stage1_analysis": stage1_analysis,
                            },
                            lane_name="aux",
                            metrics=metrics,
                            active_fetch_limiter=active_fetch_limiter,
                        )
                    else:
                        payload_outcome = _handle_stage1_fetch_payload(
                            payload=render_payload,
                            normalized_url=normalized_url,
                            prefetch_metrics=prefetch_metrics,
                            scoring_config=scoring_config,
                            stage1_analysis=stage1_analysis,
                        )
                        _commit_terminal_hash_outcome(
                            payload_outcome,
                            metrics=metrics,
                            decision_rows=decision_rows,
                            prefetch_admitted_failures=prefetch_admitted_failures,
                            hash_progress=hash_progress,
                        )
                        recycle_page = True
                    consecutive_failures = 0
                except asyncio.CancelledError as exc:
                    cancel_requested = True
                    cancel_error = exc
                    if normalized_url:
                        payload_outcome = _handle_stage1_fetch_payload(
                            payload={
                                "url": normalized_url or raw_url,
                                "normalized_url": normalized_url or raw_url,
                                "source_workbook": prefetch_metrics.get("source_workbook", ""),
                                "fetch_status": "failed",
                                "visual_status": "not_attempted",
                                "fetch_error_type": "worker_stall",
                                "fetch_error_detail": "hash render worker cancelled during stall recovery",
                                "final_landing_url": "",
                                "parking_provider": "",
                                "parking_reason": "",
                            },
                            normalized_url=normalized_url or raw_url,
                            prefetch_metrics=prefetch_metrics,
                            scoring_config=scoring_config,
                            stage1_analysis=stage1_analysis,
                        )
                        _commit_terminal_hash_outcome(
                            payload_outcome,
                            metrics=metrics,
                            decision_rows=decision_rows,
                            prefetch_admitted_failures=prefetch_admitted_failures,
                            hash_progress=hash_progress,
                        )
                    consecutive_failures += 1
                    raise
                except Exception as exc:
                    payload_outcome = _handle_stage1_fetch_payload(
                        payload={
                            "url": normalized_url or raw_url,
                            "normalized_url": normalized_url or raw_url,
                            "source_workbook": prefetch_metrics.get("source_workbook", ""),
                            "fetch_status": "failed",
                            "visual_status": "not_attempted",
                            "fetch_error_type": "render_worker_error",
                            "fetch_error_detail": _compact_exception_message(exc),
                            "final_landing_url": "",
                            "parking_provider": "",
                            "parking_reason": "",
                        },
                        normalized_url=normalized_url or raw_url,
                        prefetch_metrics=prefetch_metrics,
                        scoring_config=scoring_config,
                        stage1_analysis=stage1_analysis,
                    )
                    _commit_terminal_hash_outcome(
                        payload_outcome,
                        metrics=metrics,
                        decision_rows=decision_rows,
                        prefetch_admitted_failures=prefetch_admitted_failures,
                        hash_progress=hash_progress,
                    )
                    recycle_page = True
                    _clip_logger.warning(
                        "Hash render worker %s error on %s: %s: %s",
                        worker_id,
                        raw_url,
                        exc.__class__.__name__,
                        _compact_exception_message(exc),
                    )
                    consecutive_failures += 1
                finally:
                    active_workers.pop(worker_id, None)
                    if item_taken:
                        render_queue.task_done()
                    if not cancel_requested:
                        _set_hash_worker_state(
                            worker_states,
                            worker_id,
                            node_id=node_id,
                            page_worker_id=slot_id,
                            phase="reset",
                            consecutive_failures=consecutive_failures,
                        )
                        try:
                            urls_since_recycle += 1
                            page = await _reset_hash_page(
                                page,
                                ctx,
                                recycle=recycle_page or urls_since_recycle >= 50,
                            )
                            if recycle_page or urls_since_recycle >= 50:
                                urls_since_recycle = 0
                            _set_hash_worker_state(
                                worker_states,
                                worker_id,
                                node_id=node_id,
                                page_worker_id=slot_id,
                                phase="idle",
                                consecutive_failures=consecutive_failures,
                            )
                        except asyncio.CancelledError:
                            cancel_requested = True
                            if cancel_error is None:
                                cancel_error = asyncio.CancelledError()
                        except Exception as reset_exc:
                            metrics["stuck_reset_recoveries"] = metrics.get("stuck_reset_recoveries", 0) + 1
                            _clip_logger.warning(
                                "Hash render worker %s reset error after %s: %s: %s",
                                worker_id,
                                normalized_url or raw_url,
                                reset_exc.__class__.__name__,
                                _compact_exception_message(reset_exc),
                            )
                            with suppress(Exception):
                                if page is not None and not page.is_closed():
                                    await asyncio.wait_for(page.close(), timeout=3.0)
                            page = None
                            try:
                                page = await _reset_hash_page(None, ctx, recycle=False)
                                urls_since_recycle = 0
                                _set_hash_worker_state(
                                    worker_states,
                                    worker_id,
                                    node_id=node_id,
                                    page_worker_id=slot_id,
                                    phase="idle",
                                    consecutive_failures=consecutive_failures,
                                )
                            except Exception as restart_exc:
                                _clip_logger.warning(
                                    "Hash render worker %s page restart failed: %s: %s",
                                    worker_id,
                                    restart_exc.__class__.__name__,
                                    _compact_exception_message(restart_exc),
                                )
                                break
                if cancel_requested:
                    raise cancel_error if cancel_error is not None else asyncio.CancelledError()
        finally:
            worker_tasks.pop(worker_id, None)
            worker_states.pop(worker_id, None)
            active_workers.pop(worker_id, None)
            with suppress(Exception):
                if page is not None and not page.is_closed():
                    await asyncio.wait_for(page.close(), timeout=3.0)

    workers = [asyncio.create_task(_page_worker(slot_id)) for slot_id in range(HASH_PAGES_PER_NODE)]
    try:
        await asyncio.gather(*workers, return_exceptions=True)
    finally:
        for cleanup in (ctx.close, browser.close, p.stop):
            with suppress(Exception):
                await asyncio.wait_for(cleanup(), timeout=10.0)


async def _run_hash_aux_worker(
    *,
    worker_id,
    aux_queue,
    gpu_queue,
    metrics,
    decision_rows,
    prefetch_admitted_failures,
    active_fetch_limiter,
    aio_session,
    hash_progress,
    scoring_config,
    active_workers,
):
    while True:
        item = await aux_queue.get()
        if item is None:
            aux_queue.task_done()
            break
        render_payload = item.get("render_payload") or {}
        normalized_url = str(render_payload.get("normalized_url", render_payload.get("url", "")) or "")
        prefetch_metrics = item.get("prefetch_metrics") or {}
        stage1_analysis = item.get("stage1_analysis") or {}
        active_workers[worker_id] = normalized_url
        try:
            scored_payload = await _enrich_render_payload_for_hashing(
                render_payload,
                aio_session=aio_session,
                scoring_config=scoring_config,
                prefetch_metrics=prefetch_metrics,
                stage1_analysis=stage1_analysis,
            )
            metrics["aux_completed"] += 1
            await _queue_hash_lane_item(
                gpu_queue,
                scored_payload,
                lane_name="finalize",
                metrics=metrics,
                active_fetch_limiter=active_fetch_limiter,
            )
        except Exception as exc:
            payload_outcome = _handle_stage1_fetch_payload(
                payload={
                    "url": render_payload.get("url", normalized_url),
                    "normalized_url": normalized_url,
                    "source_workbook": prefetch_metrics.get("source_workbook", ""),
                    "fetch_status": "failed",
                    "visual_status": render_payload.get("visual_status", "not_attempted"),
                    "fetch_error_type": "aux_hash_error",
                    "fetch_error_detail": _compact_exception_message(exc),
                    "final_landing_url": render_payload.get("final_landing_url", ""),
                    "parking_provider": render_payload.get("parking_provider", ""),
                    "parking_reason": render_payload.get("parking_reason", ""),
                    "screenshot_path": render_payload.get("screenshot_path", ""),
                },
                normalized_url=normalized_url,
                prefetch_metrics=prefetch_metrics,
                scoring_config=scoring_config,
                stage1_analysis=stage1_analysis,
            )
            _commit_terminal_hash_outcome(
                payload_outcome,
                metrics=metrics,
                decision_rows=decision_rows,
                prefetch_admitted_failures=prefetch_admitted_failures,
                hash_progress=hash_progress,
            )
            _clip_logger.warning(
                "Hash aux worker %s error on %s: %s: %s",
                worker_id,
                normalized_url,
                exc.__class__.__name__,
                _compact_exception_message(exc),
            )
        finally:
            active_workers.pop(worker_id, None)
            aux_queue.task_done()


class _Stage1PerHostLimiter:
    def __init__(self, limit: int):
        self._limit = max(1, int(limit))
        self._lock = asyncio.Lock()
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    async def run(self, host: str, awaitable_factory):
        host_key = str(host or "").strip().lower()
        if not host_key:
            return await awaitable_factory()
        async with self._lock:
            semaphore = self._semaphores.get(host_key)
            if semaphore is None:
                semaphore = asyncio.Semaphore(self._limit)
                self._semaphores[host_key] = semaphore
        async with semaphore:
            return await awaitable_factory()


def _stage1_fd_usage() -> tuple[int | None, int | None, float | None]:
    count = None
    limit = None
    try:
        process = psutil.Process(os.getpid())
        if hasattr(process, "num_fds"):
            count = int(process.num_fds())
        elif hasattr(process, "num_handles"):
            count = int(process.num_handles())
    except Exception:
        count = None
    try:
        import resource  # type: ignore

        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if isinstance(soft_limit, int) and soft_limit > 0:
            limit = int(soft_limit)
    except Exception:
        limit = None
    ratio = (float(count) / float(limit)) if (count is not None and limit not in (None, 0)) else None
    return count, limit, ratio


def _stage1_timeout_flag_from_message(*messages: str) -> bool:
    surface = " ".join(str(message or "") for message in messages).lower()
    return "timeout" in surface


def _build_stage1_failed_result(
    raw_url: str,
    *,
    normalized_url: str,
    error_type: str,
    error_message: str,
    timeout_hit: bool,
    base_result: dict | None = None,
    reason: str = "stage1_fetch_failed",
) -> dict:
    analysis = _default_stage1_result(raw_url)
    if base_result:
        analysis.update(dict(base_result))
    analysis["url"] = normalized_url
    analysis["normalized_url"] = normalized_url
    analysis["fetch_status"] = "failed"
    analysis["fetch_error_type"] = str((base_result or {}).get("fetch_error_type") or error_type or "stage1_http_error")
    analysis["fetch_error_detail"] = str((base_result or {}).get("fetch_error_detail") or error_message or error_type)
    analysis["stage1_error_type"] = str(error_type or analysis.get("stage1_error_type") or "stage1_http_error")
    analysis["stage1_error_message"] = str(error_message or analysis.get("stage1_error_message") or error_type or "stage1_http_error")
    analysis["stage1_retry_count"] = 0
    analysis["stage1_timeout_hit"] = bool(timeout_hit)
    analysis["stage1_reasons"] = reason
    analysis["escalate_reason"] = reason
    analysis["escalate_to_hashing"] = False
    return analysis


async def _analyze_stage1_http_candidates(
    urls: list[str],
    stage1_http_config: dict | None = None,
    scoring_config: dict | None = None,
    run_context: RunContext | None = None,
    checkpoint_store: CheckpointStore | None = None,
    source_workbook_map: dict[str, str] | None = None,
    dns_prefetch_map: dict[str, dict] | None = None,
    prefetch_metrics_map: dict[str, dict] | None = None,
) -> dict[str, dict]:
    if not urls:
        return {}

    stage1_http_config = dict(stage1_http_config or STAGE1_HTTP_CONFIG)
    scoring_config = dict(scoring_config or _DEFAULT_SCORING_CONFIG)
    source_workbook_map = dict(source_workbook_map or {})
    dns_prefetch_map = dict(dns_prefetch_map or {})
    prefetch_metrics_map = dict(prefetch_metrics_map or {})
    fetch_concurrency = max(
        1,
        int(stage1_http_config.get("stage1_fetch_concurrency_start", stage1_http_config.get("concurrency", 24))),
    )
    fetch_concurrency_max = max(
        fetch_concurrency,
        int(stage1_http_config.get("stage1_fetch_concurrency_max", fetch_concurrency)),
    )
    stage1_http_config["http_concurrency"] = max(
        1,
        int(
            stage1_http_config.get(
                "stage1_http_connection_limit",
                stage1_http_config.get("http_concurrency", fetch_concurrency_max),
            )
        ),
    )
    stage1_http_config["dns_concurrency"] = max(
        1,
        int(stage1_http_config.get("stage1_enrich_dns_concurrency", stage1_http_config.get("dns_concurrency", fetch_concurrency))),
    )
    stage1_http_config["rdap_concurrency"] = max(
        1,
        int(stage1_http_config.get("stage1_enrich_rdap_concurrency", stage1_http_config.get("rdap_concurrency", 8))),
    )
    stage1_http_config["tls_concurrency"] = max(
        1,
        int(stage1_http_config.get("stage1_enrich_tls_concurrency", stage1_http_config.get("tls_concurrency", 32))),
    )
    entity_context, ordered_entities = get_stage1_entity_context()
    concurrency_controls = build_stage1_concurrency_controls(stage1_http_config)
    url_concurrency = max(1, fetch_concurrency)
    http_concurrency = max(1, int(stage1_http_config.get("http_concurrency", url_concurrency)))
    keepalive_concurrency = max(
        1,
        min(
            http_concurrency,
            int(stage1_http_config.get("stage1_http_keepalive_limit", min(http_concurrency, url_concurrency))),
        ),
    )
    limits = httpx.Limits(
        max_connections=http_concurrency,
        max_keepalive_connections=keepalive_concurrency,
    )
    timeout = httpx.Timeout(
        stage1_http_config["get_timeout"],
        connect=stage1_http_config["connect_timeout"],
    )
    results = {}
    progress = ProgressTracker(total=len(urls))
    progress_metrics = {
        "escalated": 0,
        "failed": 0,
        "head_only": 0,
        "fetched": 0,
        "fallback_dns": 0,
        "timeout": 0,
    }
    active_workers: dict[str, str] = {}
    fetch_limiter = _AdaptiveFetchLimiter(url_concurrency)
    per_host_limiter = _Stage1PerHostLimiter(
        max(1, int(stage1_http_config.get("stage1_per_host_limit", 4)))
    )
    telemetry = {
        "event_loop_lag_ms": 0.0,
        "fd_count": None,
        "fd_limit": None,
        "fd_ratio": None,
        "timeout_ratio": 0.0,
    }
    stage1_started_monotonic = time.perf_counter()
    last_progress_log_monotonic = stage1_started_monotonic
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    for raw_url in urls:
        await queue.put(raw_url)
    for _ in range(url_concurrency):
        await queue.put(None)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        limits=limits,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; stage1-router/1.0)"},
    ) as client:
        _clip_logger.info(
            "Stage1 fast-path runtime | urls=%d | fetch_concurrency=%d..%d | http_limit=%d | keepalive_limit=%d | per_host_limit=%d | dns_reuse=%s",
            len(urls),
            url_concurrency,
            fetch_concurrency_max,
            http_concurrency,
            keepalive_concurrency,
            int(stage1_http_config.get("stage1_per_host_limit", 4) or 4),
            True,
        )
        try:
            from tqdm import tqdm

            progress_bar = tqdm(
                total=len(urls),
                desc="Stage1 cheap HTTP",
                unit="url",
                leave=True,
                dynamic_ncols=True,
            )
        except ImportError:
            progress_bar = None

        async def _progress_monitor():
            nonlocal last_progress_log_monotonic
            last_completed = 0
            while True:
                before_sleep = time.perf_counter()
                await asyncio.sleep(0.5)
                telemetry["event_loop_lag_ms"] = max(
                    0.0,
                    (time.perf_counter() - before_sleep - 0.5) * 1000.0,
                )
                completed = progress.completed
                if progress_bar is not None and completed > last_completed:
                    progress_bar.update(completed - last_completed)
                last_completed = completed
                if progress_bar is not None:
                    progress_bar.set_postfix(
                        {
                            "act": len(active_workers),
                            "q": queue.qsize(),
                            "limit": fetch_limiter.limit,
                            "esc": progress_metrics["escalated"],
                            "fail": progress_metrics["failed"],
                            "failfb": progress_metrics["fallback_dns"],
                        },
                        refresh=False,
                    )
                now_monotonic = time.perf_counter()
                if (now_monotonic - last_progress_log_monotonic) >= float(
                    stage1_http_config.get("stage1_progress_log_interval_seconds", 10) or 10
                ):
                    elapsed_s = max(0.001, now_monotonic - stage1_started_monotonic)
                    rate = completed / elapsed_s
                    remaining = max(0, len(urls) - completed)
                    eta_s = (remaining / rate) if rate > 0 else 0.0
                    fd_count, fd_limit, fd_ratio = _stage1_fd_usage()
                    telemetry["fd_count"] = fd_count
                    telemetry["fd_limit"] = fd_limit
                    telemetry["fd_ratio"] = fd_ratio
                    _clip_logger.info(
                        "Stage1 cheap HTTP progress | processed=%d/%d | rate=%.1f url/s | elapsed=%.1fs | eta=%.1fs | active=%d | queue=%d | fetch_limit=%d | escalated=%d | failed=%d | failure_fallback=%d | fd=%s/%s | event_loop_lag_ms=%.1f | timeout_ratio=%.3f",
                        completed,
                        len(urls),
                        rate,
                        elapsed_s,
                        eta_s,
                        len(active_workers),
                        queue.qsize(),
                        fetch_limiter.limit,
                        progress_metrics["escalated"],
                        progress_metrics["failed"],
                        progress_metrics["fallback_dns"],
                        fd_count if fd_count is not None else "n/a",
                        fd_limit if fd_limit is not None else "n/a",
                        float(telemetry["event_loop_lag_ms"] or 0.0),
                        float(telemetry["timeout_ratio"] or 0.0),
                    )
                    last_progress_log_monotonic = now_monotonic
                if completed >= len(urls):
                    break

        async def _ramp_monitor():
            last_fetch_timeout = 0
            bad_windows = 0
            while True:
                await asyncio.sleep(15.0)
                if progress.completed >= len(urls):
                    break
                window_timeout = max(0, progress_metrics["timeout"] - last_fetch_timeout)
                last_fetch_timeout = progress_metrics["timeout"]
                telemetry["timeout_ratio"] = window_timeout / max(1, progress.completed)
                fd_count, fd_limit, fd_ratio = _stage1_fd_usage()
                telemetry["fd_count"] = fd_count
                telemetry["fd_limit"] = fd_limit
                telemetry["fd_ratio"] = fd_ratio
                healthy = (
                    float(telemetry["event_loop_lag_ms"] or 0.0) < 50.0
                    and (fd_ratio is None or fd_ratio < 0.70)
                    and float(telemetry["timeout_ratio"] or 0.0) < 0.25
                    and queue.qsize() < max(1, int(len(urls) * 0.90))
                )
                if healthy and fetch_limiter.limit < fetch_concurrency_max:
                    previous_limit = fetch_limiter.limit
                    await fetch_limiter.set_limit(min(fetch_concurrency_max, fetch_limiter.limit + 64))
                    _clip_logger.info(
                        "Stage1 fetch ramp up | limit %d -> %d | timeout_ratio=%.3f | fd_ratio=%s",
                        previous_limit,
                        fetch_limiter.limit,
                        float(telemetry["timeout_ratio"] or 0.0),
                        "n/a" if fd_ratio is None else f"{fd_ratio:.3f}",
                    )
                    bad_windows = 0
                elif not healthy:
                    bad_windows += 1
                    if bad_windows >= 2 and fetch_limiter.limit > url_concurrency:
                        previous_limit = fetch_limiter.limit
                        await fetch_limiter.set_limit(max(url_concurrency, fetch_limiter.limit - 64))
                        _clip_logger.info(
                            "Stage1 fetch downshift | limit %d -> %d | timeout_ratio=%.3f | fd_ratio=%s",
                            previous_limit,
                            fetch_limiter.limit,
                            float(telemetry["timeout_ratio"] or 0.0),
                            "n/a" if fd_ratio is None else f"{fd_ratio:.3f}",
                        )
                        bad_windows = 0

        monitor_task = asyncio.create_task(_progress_monitor())
        ramp_task = asyncio.create_task(_ramp_monitor())

        async def _worker(worker_index: int):
            worker_id = f"stage1-{worker_index}"
            while True:
                raw_url = await queue.get()
                if raw_url is None:
                    queue.task_done()
                    break
                normalized_url = normalize_url(raw_url)
                source_workbook = source_workbook_map.get(normalized_url, "")
                stage_started_at = utc_now_iso()
                started_monotonic = time.perf_counter()
                record_key = make_record_key(normalized_url, source_workbook)
                active_workers[worker_id] = normalized_url
                if checkpoint_store is not None and run_context is not None:
                    checkpoint_store.ensure_url_result(
                        raw_url=raw_url,
                        normalized_url=normalized_url,
                        source_workbook=source_workbook,
                    )
                    checkpoint_store.update_worker_heartbeat(
                        stage_name="stage1",
                        worker_id=worker_id,
                        record_key=record_key,
                        state="running",
                        details={"url": normalized_url},
                    )
                try:
                    try:
                        async with concurrency_controls.url_semaphore:
                            analysis, retry_count, timeout_hit = await async_with_timeout_and_retry(
                                lambda: analyze_stage1_url(
                                    raw_url,
                                    client,
                                    entity_context=entity_context,
                                    ordered_entities=ordered_entities,
                                    config=stage1_http_config,
                                    concurrency_controls=concurrency_controls,
                                    dns_prefetch=dns_prefetch_map.get(normalized_url, {}),
                                    fetch_limiter=fetch_limiter,
                                    per_host_limiter=per_host_limiter,
                                ),
                                timeout=18.0,
                                max_retries=0,
                            )
                    except Exception as exc:
                        error = normalize_exception(exc)
                        timeout_hit = _stage1_timeout_flag_from_message(error["error_message"])
                        retry_count = 0
                        analysis = _build_stage1_failed_result(
                            raw_url,
                            normalized_url=normalized_url,
                            error_type=error["error_type"],
                            error_message=error["error_message"],
                            timeout_hit=timeout_hit,
                        )
                    analysis["stage1_timeout_hit"] = bool(
                        analysis.get("stage1_timeout_hit", False)
                        or timeout_hit
                        or _stage1_timeout_flag_from_message(
                            analysis.get("stage1_error_message", ""),
                            analysis.get("fetch_error_detail", ""),
                        )
                    )
                    fallback_taken = ""
                    prefetch_metrics = prefetch_metrics_map.get(normalized_url, {})
                    if (
                        str(analysis.get("fetch_status", "")).strip().lower() == "failed"
                        and run_context is not None
                        and run_context.stage1_failure_policy == "route_to_dns"
                        and _should_rescue_stage1_failure_to_hashing(
                            prefetch_metrics,
                            analysis,
                            scoring_config=scoring_config,
                        )
                    ):
                        fallback_taken = "targeted_stage1_failure_rescue"
                        analysis["fallback_taken"] = fallback_taken
                        analysis["escalate_to_hashing"] = True
                        analysis["escalate_reason"] = fallback_taken
                    fetch_status = str(analysis.get("fetch_status", "")).strip().lower()
                    if bool(analysis.get("escalate_to_hashing")):
                        progress_metrics["escalated"] += 1
                    if fetch_status == "failed":
                        progress_metrics["failed"] += 1
                    elif fetch_status == "head_only":
                        progress_metrics["head_only"] += 1
                    elif fetch_status in {"fetched", "fetched_visual_missing"}:
                        progress_metrics["fetched"] += 1
                    if bool(analysis.get("stage1_timeout_hit", False)):
                        progress_metrics["timeout"] += 1
                    if fallback_taken:
                        progress_metrics["fallback_dns"] += 1
                    results[normalized_url] = analysis
                    _upsert_shortlist_checkpoint(
                        run_context=run_context,
                        checkpoint_store=checkpoint_store,
                        raw_url=raw_url,
                        normalized_url=normalized_url,
                        source_workbook=source_workbook,
                        stage_name="stage1",
                        stage_status=(
                            "escalated"
                            if bool(analysis.get("escalate_to_hashing"))
                            else str(analysis.get("fetch_status", "failed") or "failed")
                        ),
                        current_stage="stage1",
                        retry_count=int(analysis.get("stage1_retry_count", 0) or 0),
                        timeout_hit=bool(analysis.get("stage1_timeout_hit", False)),
                        fallback_taken=fallback_taken,
                        worker_id=worker_id,
                        error_type=str(analysis.get("stage1_error_type", "") or analysis.get("fetch_error_type", "")),
                        error_message=str(analysis.get("stage1_error_message", "") or analysis.get("fetch_error_detail", "")),
                        final_pipeline_status=(
                            None
                            if bool(analysis.get("escalate_to_hashing")) or fallback_taken
                            else "filtered_lexical_miss"
                        ),
                        failure_reason=str(analysis.get("stage1_reasons", "") or analysis.get("fetch_error_detail", "")),
                    )
                    _append_shortlist_stage_event(
                        run_context=run_context,
                        checkpoint_store=checkpoint_store,
                        raw_url=raw_url,
                        normalized_url=normalized_url,
                        source_workbook=source_workbook,
                        stage_name="stage1",
                        worker_id=worker_id,
                        started_at=stage_started_at,
                        started_monotonic=started_monotonic,
                        status=(
                            "escalated"
                            if bool(analysis.get("escalate_to_hashing"))
                            else str(analysis.get("fetch_status", "failed") or "failed")
                        ),
                        retry_count=int(analysis.get("stage1_retry_count", 0) or 0),
                        timeout_flag=bool(analysis.get("stage1_timeout_hit", False)),
                        error_type=str(analysis.get("stage1_error_type", "") or analysis.get("fetch_error_type", "")),
                        error_message=str(analysis.get("stage1_error_message", "") or analysis.get("fetch_error_detail", "")),
                        fallback_taken=fallback_taken,
                    )
                    progress.mark_completed(
                        final_status="stage1_failed" if str(analysis.get("fetch_status", "")).strip().lower() == "failed" else "stage1_completed"
                    )
                finally:
                    active_workers.pop(worker_id, None)
                    if checkpoint_store is not None:
                        checkpoint_store.clear_worker_heartbeat(stage_name="stage1", worker_id=worker_id)
                    queue.task_done()

        watchdog = StageWatchdog(
            stage_name="stage1",
            progress_tracker=progress,
            checkpoint_store=checkpoint_store,
            warn_after_seconds=run_context.watchdog_warning_seconds if run_context is not None else 60,
            stall_after_seconds=run_context.stall_threshold_seconds if run_context is not None else 180,
            queue_size_getter=queue.qsize,
            active_summary_getter=lambda: {
                "workers": url_concurrency,
                "results": len(results),
                "active_workers": dict(active_workers),
                "fetch_limit": fetch_limiter.limit,
                "telemetry": dict(telemetry),
            },
            logger_instance=_clip_logger,
        )
        workers = [asyncio.create_task(_worker(index)) for index in range(url_concurrency)]
        watchdog.start()
        try:
            await queue.join()
            await asyncio.gather(*workers)
        finally:
            if monitor_task is not None:
                monitor_task.cancel()
                await asyncio.gather(monitor_task, return_exceptions=True)
            if ramp_task is not None:
                ramp_task.cancel()
                await asyncio.gather(ramp_task, return_exceptions=True)
            if progress_bar is not None:
                completed = progress.completed
                if completed > progress_bar.n:
                    progress_bar.update(completed - progress_bar.n)
                progress_bar.set_postfix(
                    {
                        "act": len(active_workers),
                        "q": queue.qsize(),
                        "limit": fetch_limiter.limit,
                        "esc": progress_metrics["escalated"],
                        "fail": progress_metrics["failed"],
                        "failfb": progress_metrics["fallback_dns"],
                    },
                    refresh=False,
                )
                progress_bar.close()
            await watchdog.stop()

    elapsed_s = max(0.001, time.perf_counter() - stage1_started_monotonic)
    _clip_logger.info(
        "Stage1 cheap HTTP completed | processed=%d/%d | rate=%.1f url/s | elapsed=%.1fs | escalated=%d | failed=%d | failure_fallback=%d | final_fetch_limit=%d",
        progress.completed,
        len(urls),
        progress.completed / elapsed_s,
        elapsed_s,
        progress_metrics["escalated"],
        progress_metrics["failed"],
        progress_metrics["fallback_dns"],
        fetch_limiter.limit,
    )

    return results


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
    lexical_pass_min_score=DEFAULT_LEXICAL_PASS_MIN_SCORE,
    clip_margin_min=DEFAULT_CLIP_MARGIN_MIN,
    weights=None,
    shortlist_debug_csv: str | None = DEFAULT_STAGE1_DEBUG_CSV,
    url_sources: dict | None = None,
    keep_stage1_suspected: bool = False,
    keep_fetch_failed_strict_lexical: bool = False,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
    run_context: RunContext | None = None,
    checkpoint_store: CheckpointStore | None = None,
    resume: bool = False,
    force_reprocess: bool = False,
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
        lexical_pass_min_score=lexical_pass_min_score,
        clip_margin_min=clip_margin_min,
        keep_stage1_suspected=keep_stage1_suspected,
        keep_fetch_failed_strict_lexical=keep_fetch_failed_strict_lexical,
        stage1_escalate_total_threshold=stage1_escalate_total_threshold,
        stage1_brand_min=stage1_brand_min,
        stage1_credential_min=stage1_credential_min,
        stage1_low_band_min=stage1_low_band_min,
        stage1_hard_trigger_brand_min=stage1_hard_trigger_brand_min,
    )
    resolved_weights = scoring_config["weights"]
    stage1_http_config = dict(scoring_config["stage1_http_config"])
    source_workbook_map = _resolve_source_workbook_map(url_sources)
    from .rdap_utils import get_rdap_metrics_snapshot, reset_rdap_state

    input_urls = list(url_list)
    completed_record_keys = (
        checkpoint_store.get_completed_record_keys()
        if checkpoint_store is not None and resume and not force_reprocess
        else set()
    )
    log_path = _configure_hashing_log()
    reset_rdap_state()
    original_count = len(input_urls)
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
        "active_fetch_limit": ACTIVE_FETCH_LIMIT_INITIAL,
        "worker_nodes_alive": 0,
        "node_restarts": 0,
        "live_page_workers": 0,
        "shutdown_sentinels_expected": 0,
        "shutdown_sentinels_drained": 0,
        "stuck_reset_recoveries": 0,
        "phase": "running",
        "fd_count": 0,
        "fd_limit": 0,
        "fd_usage_ratio": 0.0,
        "ram_usage_ratio": 0.0,
        "limiting_lane": "render",
    }
    decision_rows = []
    prefetch_metrics_map = {}
    stage1_analysis_map = {}
    lexical_candidate_urls = []
    lexical_miss_urls = []
    lexical_reject_urls = set()
    stage0_hits = 0
    stage0_misses = 0
    stage0_skipped = 0
    stage0_processed = 0
    stage0_started_monotonic = time.perf_counter()
    last_stage0_log_monotonic = stage0_started_monotonic
    stage1_http_eligible_miss_urls = []

    _clip_logger.info(
        "Hashing shortlist (streaming) started | urls=%d | threshold=%s | "
        "domain_similarity_threshold=%.3f | high_confidence_threshold=%.2f | "
        "medium_confidence_threshold=%.2f | typo_top_k=%d | typo_min_score=%.3f | "
        "lexical_pass_min_score=%.3f | clip_margin_min=%.3f",
        original_count,
        threshold,
        scoring_config["domain_similarity_threshold"],
        scoring_config["high_confidence_threshold"],
        scoring_config["medium_confidence_threshold"],
        scoring_config["typo_top_k"],
        scoring_config["typo_min_score"],
        scoring_config["lexical_pass_min_score"],
        scoring_config["clip_margin_min"],
    )
    _clip_logger.info(
        "Scoring weights | %s",
        _format_weights_for_logging(resolved_weights),
    )
    _clip_logger.info(
        "Hash stage topology | pages=%d | page_workers_per_shard=%d | shards=%d | "
        "http_limit=%d | nav_timeout_ms=%d | screenshot_timeout_ms=%d | fetch_timeout_s=%.1f | "
        "gpu_queue=%d | gpu_batch=%d | active_fetch_limit=%d | active_fetch_floor=%d | "
        "aux_net_limit=%d | adaptive_downshift_enabled=%s",
        MAX_CONCURRENT_PAGES,
        SCRAPER_PAGE_CONCURRENCY,
        BROWSER_SHARDS,
        _AIOHTTP_CONNECTOR_LIMIT,
        SCRAPER_NAV_TIMEOUT_MS,
        SCRAPER_SCREENSHOT_TIMEOUT_MS,
        SCRAPER_FETCH_TIMEOUT_S,
        GPU_QUEUE_MAXSIZE,
        GPU_MAX_BATCH_SIZE,
        ACTIVE_FETCH_LIMIT_INITIAL,
        ACTIVE_FETCH_LIMIT_FLOOR,
        AUX_NET_CONCURRENCY_LIMIT,
        ADAPTIVE_FETCH_DOWNSHIFT_ENABLED,
    )
    _clip_logger.info(
        "Stage1 note | OCR/Screenshots/ImgProc/RDAP/WHOIS limits from phishing_pipeline.utils are not the active hashing-stage browser worker counts."
    )
    _clip_logger.info(
        "Stage1 runtime thresholds | escalate_total=%d | brand_min=%d | credential_min=%d | low_band_min=%d | hard_trigger_brand_min=%d | policies={stage1_suspected_passthrough=%s,fetch_failed_strict_lexical_passthrough=%s}",
        int(stage1_http_config.get("escalate_total_threshold", 0) or 0),
        int(stage1_http_config.get("brand_min", 0) or 0),
        int(stage1_http_config.get("credential_min", 0) or 0),
        int(stage1_http_config.get("low_band_min", 0) or 0),
        int(stage1_http_config.get("hard_trigger_brand_min", 0) or 0),
        scoring_config["keep_stage1_suspected"],
        scoring_config["keep_fetch_failed_strict_lexical"],
    )
    _clip_logger.info("Hashing log file: %s", log_path)
    print(f"Hashing log: {log_path}")

    try:
        from tqdm import tqdm as tqdm_sync

        stage0_progress_bar = tqdm_sync(
            total=original_count,
            desc="Stage0 lexical gate",
            unit="url",
            leave=True,
            dynamic_ncols=True,
        )
    except Exception:
        stage0_progress_bar = None

    for raw_url in input_urls:
        normalized_url = normalize_url(raw_url)
        source_workbook = source_workbook_map.get(normalized_url, "")
        if checkpoint_store is not None and run_context is not None and normalized_url:
            if make_record_key(normalized_url, source_workbook) in completed_record_keys:
                stage0_skipped += 1
                stage0_processed += 1
                if stage0_progress_bar is not None:
                    stage0_progress_bar.update(1)
                continue
        if normalized_url and normalized_url not in prefetch_metrics_map:
            prefetch_metrics_map[normalized_url] = _compute_prefetch_lexical_state(raw_url, scoring_config)
            prefetch_metrics_map[normalized_url]["source_workbook"] = source_workbook
        prefetch_metrics = prefetch_metrics_map.get(normalized_url, {})
        prefetch_metrics["source_workbook"] = source_workbook_map.get(normalized_url, prefetch_metrics.get("source_workbook", ""))
        if _passes_lexical_gate(prefetch_metrics):
            stage0_hits += 1
            stage1_analysis_map[normalized_url] = _build_lexical_stage1_state(prefetch_metrics)
            lexical_candidate_urls.append(raw_url)
            _upsert_shortlist_checkpoint(
                run_context=run_context,
                checkpoint_store=checkpoint_store,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="stage0",
                stage_status="lexical_hit",
                current_stage="stage0",
            )
        else:
            lexical_miss_urls.append(raw_url)
            stage0_misses += 1
            stage1_http_eligible_miss_urls.append(raw_url)
            _upsert_shortlist_checkpoint(
                run_context=run_context,
                checkpoint_store=checkpoint_store,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="stage0",
                stage_status="filtered_lexical_miss",
                current_stage="stage0",
            )
        stage0_processed += 1
        if stage0_progress_bar is not None:
            stage0_progress_bar.update(1)
            stage0_progress_bar.set_postfix(
                {
                    "hits": stage0_hits,
                    "miss": stage0_misses,
                    "skip": stage0_skipped,
                    "w": 1,
                },
                refresh=False,
            )
        now_monotonic = time.perf_counter()
        log_interval = float(getattr(run_context, "stage0_progress_log_interval_seconds", 10) if run_context is not None else 10)
        if (now_monotonic - last_stage0_log_monotonic) >= log_interval:
            elapsed_s = max(0.001, now_monotonic - stage0_started_monotonic)
            rate = stage0_processed / elapsed_s
            remaining = max(0, original_count - stage0_processed)
            eta_s = (remaining / rate) if rate > 0 else 0.0
            _clip_logger.info(
                "Stage0 lexical gate progress | processed=%d/%d | rate=%.1f url/s | elapsed=%.1fs | eta=%.1fs | hits=%d | misses=%d | skipped=%d | workers=1",
                stage0_processed,
                original_count,
                rate,
                elapsed_s,
                eta_s,
                stage0_hits,
                stage0_misses,
                stage0_skipped,
            )
            last_stage0_log_monotonic = now_monotonic

    if stage0_progress_bar is not None:
        stage0_progress_bar.close()
    stage0_elapsed_s = max(0.001, time.perf_counter() - stage0_started_monotonic)
    _clip_logger.info(
        "Stage0 lexical gate completed | processed=%d/%d | rate=%.1f url/s | elapsed=%.1fs | hits=%d | misses=%d | skipped=%d | workers=1",
        stage0_processed,
        original_count,
        stage0_processed / stage0_elapsed_s,
        stage0_elapsed_s,
        stage0_hits,
        stage0_misses,
        stage0_skipped,
    )

    if completed_record_keys:
        skipped_count = max(0, original_count - len(lexical_candidate_urls) - len(lexical_miss_urls))
        if skipped_count:
            _clip_logger.info(
                "Hash shortlist resume | skipped %d URL records already terminal in checkpoint store",
                skipped_count,
            )

    if stage1_http_eligible_miss_urls:
        analyzed_lexical_misses = await _analyze_stage1_http_candidates(
            stage1_http_eligible_miss_urls,
            stage1_http_config=stage1_http_config,
            scoring_config=scoring_config,
            run_context=run_context,
            checkpoint_store=checkpoint_store,
            source_workbook_map=source_workbook_map,
            prefetch_metrics_map=prefetch_metrics_map,
        )
        for raw_url in stage1_http_eligible_miss_urls:
            normalized_url = normalize_url(raw_url)
            analysis = dict(analyzed_lexical_misses.get(normalized_url, {}) or {})
            stage1_analysis_map[normalized_url] = {
                **_stage1_signal_defaults(),
                **analysis,
            }
            if bool(stage1_analysis_map[normalized_url].get("escalate_to_hashing")):
                lexical_candidate_urls.append(raw_url)

    rdap_metrics = get_rdap_metrics_snapshot()
    stage1_rescued_miss_count = max(0, len(lexical_candidate_urls) - stage0_hits)

    _clip_logger.info(
        "Stage1 routing kept %d/%d URLs before hashing | stage0_lexical_hits=%d | stage1_http_rescued=%d | lexical_misses=%d | stage1_http_eligible=%d | non_escalated=%d",
        len(lexical_candidate_urls),
        max(original_count, 1),
        stage0_hits,
        stage1_rescued_miss_count,
        stage0_misses,
        len(stage1_http_eligible_miss_urls),
        sum(
            1
            for normalized_url, row in stage1_analysis_map.items()
            if not bool(row.get("escalate_to_hashing", False))
        ),
    )
    _clip_logger.info(
        "Stage1 RDAP summary | success=%d | 429=%d | retry_success=%d | retry_exhausted=%d | exception=%d | cache_hit=%d | inflight_wait=%d | cooldown_hit=%d",
        int(rdap_metrics.get("success", 0) or 0),
        int(rdap_metrics.get("429", 0) or 0),
        int(rdap_metrics.get("retry_success", 0) or 0),
        int(rdap_metrics.get("retry_exhausted", 0) or 0),
        int(rdap_metrics.get("exception", 0) or 0),
        int(rdap_metrics.get("cache_hit", 0) or 0),
        int(rdap_metrics.get("inflight_wait", 0) or 0),
        int(rdap_metrics.get("cooldown_hit", 0) or 0),
    )
    print(
        f"Stage1 routing kept {len(lexical_candidate_urls)}/{original_count} URLs before hashing "
        f"({stage0_hits} Stage0 lexical hits + {stage1_rescued_miss_count} Stage1 rescues)"
    )

    if not lexical_candidate_urls:
        stage1_rows = _build_stage1_debug_rows(
            input_urls,
            audit_rows,
            decision_rows=[],
            prefetch_metrics_map=prefetch_metrics_map,
            lexical_reject_urls=lexical_reject_urls,
            stage1_analysis_map=stage1_analysis_map,
            scoring_config=scoring_config,
            source_workbook_map=source_workbook_map,
        )
        methods_path, deep_analysis_path = _write_stage1_method_artifacts(stage1_rows)
        passthrough_rows = [
            row
            for row in (
                _build_stage1_passthrough_holdout_row(stage1_row, scoring_config)
                for stage1_row in stage1_rows
            )
            if row
        ]
        stage1_review_rows = _build_stage1_review_queue_rows(stage1_rows, scoring_config=scoring_config)
        os.makedirs(os.path.dirname(STAGE1_REVIEW_QUEUE_PATH), exist_ok=True)
        pd.DataFrame(stage1_review_rows).to_csv(STAGE1_REVIEW_QUEUE_PATH, index=False, encoding="utf-8")
        if shortlist_debug_csv:
            debug_path = _write_stage1_debug_csv(stage1_rows, output_path=shortlist_debug_csv)
            _clip_logger.info("Stage1 debug CSV written to %s with %d rows", debug_path, len(stage1_rows))
        excluded_rows = _build_excluded_url_rows(stage1_rows)
        excluded_path = _write_excluded_urls_audit(excluded_rows)
        _write_stage1_subset_csv(
            stage1_rows,
            FETCH_FAILED_LEXICAL_HITS_PATH,
            lambda row: str(row.get("fetch_status", "")).strip().lower() in {"failed", "timeout"} and bool(row.get("strict_lexical_hit")),
        )
        _clip_logger.info(
            "Excluded URL audit written to %s with %d rows",
            excluded_path,
            len(excluded_rows),
        )
        _clip_logger.info("Stage1 routing summary | review_queue_rows=%d", len(stage1_review_rows))
        _clip_logger.info(
            "Stage1 review queue written to %s with %d rows",
            STAGE1_REVIEW_QUEUE_PATH,
            len(stage1_review_rows),
        )
        print(f"Excluded URLs: {excluded_path} ({len(excluded_rows)} rows)")
        print(f"Stage1 methods: {methods_path}")
        print(f"Stage1 deep-analysis candidates: {deep_analysis_path}")
        _clip_logger.info("No URLs escalated past Stage1 routing; skipping hashing.")
        _close_hashing_log()
        if not passthrough_rows:
            return _empty_shortlist_df()
        return pd.DataFrame(passthrough_rows)

    shortlisted_urls = list(lexical_candidate_urls)

    try:
        t0 = time.perf_counter()
        url_queue = asyncio.Queue()
        gpu_queue = asyncio.Queue(maxsize=GPU_QUEUE_MAXSIZE)
        active_fetch_limiter = _AdaptiveFetchLimiter(ACTIVE_FETCH_LIMIT_INITIAL)
        results = []
        review_results = []
        prefetch_admitted_failures = []
        hash_progress = ProgressTracker(total=len(shortlisted_urls))
        last_progress_log = t0
        last_processed = 0
        last_window_processed = 0
        last_window_failed = 0
        last_window_timed_out = 0
        consecutive_pressure_windows = 0
        metrics["hash_execution_mode"] = "legacy_shards"

        for raw_url in shortlisted_urls:
            await url_queue.put(raw_url)
        for _ in range(BROWSER_SHARDS * SCRAPER_PAGE_CONCURRENCY):
            await url_queue.put(None)

        connector = aiohttp.TCPConnector(limit=_AIOHTTP_CONNECTOR_LIMIT, ttl_dns_cache=300) if _has_aiohttp else None
        aio_session = aiohttp.ClientSession(connector=connector) if _has_aiohttp else None
        progress_bar = None
        hash_watchdog = None

        try:
            from tqdm import tqdm

            progress_bar = tqdm(
                total=len(shortlisted_urls),
                desc="Hashing shortlist",
                unit="url",
                leave=True,
            )
        except Exception:
            pass

        try:
            loop = asyncio.get_running_loop()
            _install_asyncio_exception_logging(loop)
            shard_tasks = [
                asyncio.create_task(
                    _run_browser_shard(
                        i,
                        url_queue,
                        gpu_queue,
                        metrics,
                        decision_rows,
                        prefetch_metrics_map,
                        stage1_analysis_map,
                        prefetch_admitted_failures,
                        active_fetch_limiter,
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
                    review_results,
                    decision_rows,
                    metrics,
                    threshold,
                    scoring_config,
                    None,
                )
            )
            hash_watchdog = StageWatchdog(
                stage_name="hash",
                progress_tracker=hash_progress,
                checkpoint_store=checkpoint_store,
                warn_after_seconds=run_context.watchdog_warning_seconds if run_context is not None else 60,
                stall_after_seconds=run_context.stall_threshold_seconds if run_context is not None else 180,
                queue_size_getter=url_queue.qsize,
                active_summary_getter=lambda: {
                    "processed": metrics.get("processed", 0),
                    "gpu_queue_depth": gpu_queue.qsize(),
                    "active_fetch_limit": active_fetch_limiter.limit,
                    "shards_done": sum(1 for task in shard_tasks if task.done()),
                    "shards_total": len(shard_tasks),
                },
                logger_instance=_clip_logger,
            )
            hash_watchdog.start()

            while not all(task.done() for task in shard_tasks):
                await asyncio.sleep(0.5)
                now = time.perf_counter()
                metrics["gpu_queue_depth"] = gpu_queue.qsize()
                metrics["active_fetch_limit"] = active_fetch_limiter.limit
                metrics["stage_elapsed_s"] = now - t0
                current = metrics["processed"]
                if progress_bar is not None and current > last_processed:
                    progress_bar.update(current - last_processed)
                    progress_bar.set_postfix(_build_progress_postfix(metrics), refresh=False)
                    last_processed = current
                    for _ in range(current - hash_progress.completed):
                        hash_progress.mark_completed(final_status="hash_processed")
                if (
                    run_context is not None
                    and hash_progress.seconds_since_progress() >= run_context.stall_threshold_seconds
                ):
                    for task in shard_tasks:
                        task.cancel()
                    scorer_task.cancel()
                    await asyncio.gather(*shard_tasks, return_exceptions=True)
                    await asyncio.gather(scorer_task, return_exceptions=True)
                    raise RuntimeError(
                        f"Hashing browser shard pool stalled for >= {run_context.stall_threshold_seconds}s without progress"
                    )
                if now - last_progress_log >= HASH_RAMP_INTERVAL_SECONDS:
                    window_processed = current - last_window_processed
                    window_failed = metrics["fetch_failed"] - last_window_failed
                    window_timed_out = metrics["fetch_timed_out"] - last_window_timed_out
                    if ADAPTIVE_FETCH_DOWNSHIFT_ENABLED:
                        downshift = _compute_stage1_downshift(
                            current_limit=active_fetch_limiter.limit,
                            floor_limit=ACTIVE_FETCH_LIMIT_FLOOR,
                            step=ACTIVE_FETCH_DOWNSHIFT_STEP,
                            processed_total=current,
                            window_processed=window_processed,
                            window_failed=window_failed,
                            window_timed_out=window_timed_out,
                            gpu_queue_depth=metrics["gpu_queue_depth"],
                            gpu_backlog_threshold=GPU_QUEUE_BACKLOG_THRESHOLD,
                            consecutive_pressure_windows=consecutive_pressure_windows,
                        )
                        consecutive_pressure_windows = downshift["next_consecutive_pressure_windows"]
                        if downshift["should_downshift"] and downshift["next_limit"] < active_fetch_limiter.limit:
                            previous_limit = active_fetch_limiter.limit
                            await active_fetch_limiter.set_limit(downshift["next_limit"])
                            metrics["active_fetch_limit"] = active_fetch_limiter.limit
                            _clip_logger.info(
                                "Hash adaptive downshift | active_fetch_limit %d -> %d | timeout_ratio=%.3f | success_ratio=%.3f",
                                previous_limit,
                                active_fetch_limiter.limit,
                                downshift["timeout_ratio"],
                                metrics["hashed_success"] / max(1, current),
                            )
                    _log_hashing_periodic_status(metrics, len(shortlisted_urls))
                    last_window_processed = current
                    last_window_failed = metrics["fetch_failed"]
                    last_window_timed_out = metrics["fetch_timed_out"]
                    last_progress_log = now

            await asyncio.gather(*shard_tasks)
            current = metrics["processed"]
            metrics["stage_elapsed_s"] = time.perf_counter() - t0
            metrics["gpu_queue_depth"] = gpu_queue.qsize()
            metrics["active_fetch_limit"] = active_fetch_limiter.limit
            if progress_bar is not None and current > last_processed:
                progress_bar.update(current - last_processed)
                progress_bar.set_postfix(_build_progress_postfix(metrics), refresh=False)
                last_processed = current
                for _ in range(current - hash_progress.completed):
                    hash_progress.mark_completed(final_status="hash_processed")
            await gpu_queue.put(None)
            await scorer_task
            current = metrics["processed"]
            metrics["stage_elapsed_s"] = time.perf_counter() - t0
            metrics["gpu_queue_depth"] = 0
            metrics["active_fetch_limit"] = active_fetch_limiter.limit
            if progress_bar is not None and current > last_processed:
                progress_bar.update(current - last_processed)
                progress_bar.set_postfix(_build_progress_postfix(metrics), refresh=False)
                last_processed = current
                for _ in range(current - hash_progress.completed):
                    hash_progress.mark_completed(final_status="hash_processed")
            if prefetch_admitted_failures:
                results.extend(prefetch_admitted_failures)
        finally:
            if hash_watchdog is not None:
                with suppress(Exception):
                    await hash_watchdog.stop()
            if progress_bar is not None:
                progress_bar.close()
            if aio_session is not None:
                await aio_session.close()

        return _finish_hashing_shortlist_output(
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
            checkpoint_store=checkpoint_store,
        )
    except Exception:
        with suppress(Exception):
            written_paths = _write_stage2_hash_exports(decision_rows, run_context=run_context)
            if written_paths:
                _clip_logger.info(
                    "Stage2 hash exports partially written to %s (%d files) after fatal error",
                    os.path.join(getattr(run_context, "output_dir", "") or os.path.dirname(HASH_EXPORT_DIR), "hash_folder"),
                    len(written_paths),
                )
        _clip_logger.exception("Hashing shortlist (streaming) crashed.")
        raise
    finally:
        _close_hashing_log()


def _finish_hashing_shortlist_output(
    *,
    t0,
    metrics,
    threshold,
    results,
    review_results,
    input_urls,
    audit_rows,
    decision_rows,
    prefetch_metrics_map,
    lexical_reject_urls,
    stage1_analysis_map,
    scoring_config,
    source_workbook_map,
    shortlist_debug_csv,
    run_context,
    checkpoint_store,
):
    import pandas as pd

    elapsed = time.perf_counter() - t0
    metrics["stage_elapsed_s"] = elapsed
    metrics["gpu_queue_depth"] = 0
    metrics["render_queue_depth"] = 0
    metrics["aux_queue_depth"] = 0
    print(
        f"\nHashing shortlist completed in {elapsed:.1f}s "
        f"({metrics['processed']} processed, "
        f"{metrics['final_matches_above_threshold']} matched)"
    )
    print(
        "Hashing metrics: "
        f"processed={metrics['processed']} "
        + (
            ""
            if str(metrics.get("hash_execution_mode", "")).strip().lower() == "legacy_shards"
            else f"render={metrics.get('render_completed', 0)} aux={metrics.get('aux_completed', 0)} "
        )
        + f"hashed_success={metrics['hashed_success']} "
        f"fetch_failed={metrics['fetch_failed']} "
        f"fetch_timed_out={metrics['fetch_timed_out']} "
        f"gpu_batches_flushed={metrics['gpu_batches_flushed']} "
        f"gpu_items_scored={metrics['gpu_items_scored']} "
        f"avg_gpu_batch_size={metrics['avg_gpu_batch_size']:.1f} "
        f"urls_per_sec={metrics['processed'] / max(elapsed, 1e-6):.2f} "
        f"final_matches={metrics['final_matches_above_threshold']}"
    )
    _log_hashing_metrics_summary(
        metrics,
        elapsed,
        threshold,
        shortlisted_results=results,
        typo_min_score=scoring_config["typo_min_score"],
    )
    hash_export_paths = _write_stage2_hash_exports(decision_rows, run_context=run_context)
    if hash_export_paths:
        _clip_logger.info(
            "Stage2 hash exports written to %s (%d files)",
            os.path.join(getattr(run_context, "output_dir", "") or os.path.dirname(HASH_EXPORT_DIR), "hash_folder"),
            len(hash_export_paths),
        )

    rows = [
        (
            dict(match)
            if "Cooresponding CSE" in match and "Identified Phishing/Suspected Domain Name" in match
            else _build_shortlist_output_row(match, scoring_config)
        )
        for match in results
    ]
    review_rows = []
    for match in review_results:
        review_row = _build_shortlist_output_row(match, scoring_config)
        review_row["review_reason"] = match.get("review_reason", "stage1_review_only")
        review_rows.append(review_row)

    stage1_rows = _build_stage1_debug_rows(
        input_urls,
        audit_rows,
        decision_rows=decision_rows,
        prefetch_metrics_map=prefetch_metrics_map,
        lexical_reject_urls=lexical_reject_urls,
        stage1_analysis_map=stage1_analysis_map,
        scoring_config=scoring_config,
        source_workbook_map=source_workbook_map,
    )
    methods_path, deep_analysis_path = _write_stage1_method_artifacts(stage1_rows)
    passthrough_rows = [
        row
        for row in (
            _build_stage1_passthrough_holdout_row(stage1_row, scoring_config)
            for stage1_row in stage1_rows
        )
        if row
    ]
    rows.extend(passthrough_rows)
    if rows:
        deduped_rows = []
        seen_row_keys = set()
        for row in rows:
            row_key = (
                str(row.get("Identified Phishing/Suspected Domain Name", "") or ""),
                str(row.get("Cooresponding CSE", "") or ""),
                str(row.get("Legitimate Domains", "") or ""),
            )
            if row_key in seen_row_keys:
                continue
            seen_row_keys.add(row_key)
            deduped_rows.append(row)
        rows = deduped_rows
    review_rows.extend(_build_stage1_review_queue_rows(stage1_rows, scoring_config=scoring_config))
    review_df = pd.DataFrame(review_rows)
    if not review_df.empty:
        dedupe_columns = [
            column
            for column in [
                "Identified Phishing/Suspected Domain Name",
                "Cooresponding CSE",
                "Legitimate Domains",
                "review_reason",
            ]
            if column in review_df.columns
        ]
        if dedupe_columns:
            review_df = review_df.drop_duplicates(subset=dedupe_columns, keep="last")
    os.makedirs(os.path.dirname(STAGE1_REVIEW_QUEUE_PATH), exist_ok=True)
    review_df.to_csv(STAGE1_REVIEW_QUEUE_PATH, index=False, encoding="utf-8")
    _clip_logger.info(
        "Stage1 review queue written to %s with %d rows",
        STAGE1_REVIEW_QUEUE_PATH,
        len(review_df),
    )
    if shortlist_debug_csv:
        debug_path = _write_stage1_debug_csv(stage1_rows, output_path=shortlist_debug_csv)
        _clip_logger.info("Stage1 debug CSV written to %s with %d rows", debug_path, len(stage1_rows))
        print(f"Stage1 debug: {debug_path} ({len(stage1_rows)} rows)")
    _write_stage1_subset_csv(
        stage1_rows,
        FETCH_FAILED_LEXICAL_HITS_PATH,
        lambda row: str(row.get("fetch_status", "")).strip().lower() in {"failed", "timeout"} and bool(row.get("strict_lexical_hit")),
    )
    excluded_rows = _build_excluded_url_rows(stage1_rows)
    excluded_path = _write_excluded_urls_audit(excluded_rows)
    _clip_logger.info(
        "Excluded URL audit written to %s with %d rows",
        excluded_path,
        len(excluded_rows),
    )
    _clip_logger.info("Stage1 routing summary | review_queue_rows=%d", len(review_df))
    if checkpoint_store is not None and run_context is not None:
        for stage1_row in stage1_rows:
            raw_url = str(stage1_row.get("input_url", "") or "")
            normalized_url = str(stage1_row.get("normalized_url", "") or "")
            source_workbook = str(stage1_row.get("source_workbook", "") or "")
            final_status, hash_status, failure_reason = _resolve_stage1_terminal_checkpoint_outcome(stage1_row)
            _upsert_shortlist_checkpoint(
                run_context=run_context,
                checkpoint_store=checkpoint_store,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="hash",
                stage_status=hash_status,
                current_stage="hash",
                final_pipeline_status=final_status,
                failure_reason=failure_reason,
            )
    print(f"Excluded URLs: {excluded_path} ({len(excluded_rows)} rows)")
    print(f"Stage1 methods: {methods_path}")
    print(f"Stage1 deep-analysis candidates: {deep_analysis_path}")

    if not rows:
        return _empty_shortlist_df()
    output_df = pd.DataFrame(rows)
    dedupe_columns = [
        column
        for column in [
            "Identified Phishing/Suspected Domain Name",
            "Cooresponding CSE",
            "Legitimate Domains",
        ]
        if column in output_df.columns
    ]
    if dedupe_columns:
        output_df = output_df.drop_duplicates(subset=dedupe_columns, keep="first")
    return output_df


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
    lexical_pass_min_score=DEFAULT_LEXICAL_PASS_MIN_SCORE,
    clip_margin_min=DEFAULT_CLIP_MARGIN_MIN,
    weights=None,
    shortlist_debug_csv: str | None = DEFAULT_STAGE1_DEBUG_CSV,
    url_sources: dict | None = None,
    keep_stage1_suspected: bool = False,
    keep_fetch_failed_strict_lexical: bool = False,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
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
            lexical_pass_min_score=lexical_pass_min_score,
            clip_margin_min=clip_margin_min,
            weights=weights,
            shortlist_debug_csv=shortlist_debug_csv,
            url_sources=url_sources,
            keep_stage1_suspected=keep_stage1_suspected,
            keep_fetch_failed_strict_lexical=keep_fetch_failed_strict_lexical,
            stage1_escalate_total_threshold=stage1_escalate_total_threshold,
            stage1_brand_min=stage1_brand_min,
            stage1_credential_min=stage1_credential_min,
            stage1_low_band_min=stage1_low_band_min,
            stage1_hard_trigger_brand_min=stage1_hard_trigger_brand_min,
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
    lexical_pass_min_score=DEFAULT_LEXICAL_PASS_MIN_SCORE,
    clip_margin_min=DEFAULT_CLIP_MARGIN_MIN,
    weights=None,
    shortlist_debug_csv: str | None = DEFAULT_STAGE1_DEBUG_CSV,
    url_sources: dict | None = None,
    keep_stage1_suspected: bool = False,
    keep_fetch_failed_strict_lexical: bool = False,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
    run_context: RunContext | None = None,
    checkpoint_store: CheckpointStore | None = None,
    resume: bool = False,
    force_reprocess: bool = False,
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
        lexical_pass_min_score=lexical_pass_min_score,
        clip_margin_min=clip_margin_min,
        weights=weights,
        shortlist_debug_csv=shortlist_debug_csv,
        url_sources=url_sources,
        keep_stage1_suspected=keep_stage1_suspected,
        keep_fetch_failed_strict_lexical=keep_fetch_failed_strict_lexical,
        stage1_escalate_total_threshold=stage1_escalate_total_threshold,
        stage1_brand_min=stage1_brand_min,
        stage1_credential_min=stage1_credential_min,
        stage1_low_band_min=stage1_low_band_min,
        stage1_hard_trigger_brand_min=stage1_hard_trigger_brand_min,
        run_context=run_context,
        checkpoint_store=checkpoint_store,
        resume=resume,
        force_reprocess=force_reprocess,
    )


if __name__ == "__main__":
    test_urls = [
        "https://www.onlinesbi.sbi/",
        "http://airtel.in",
        "http://myjio.login.com",
    ]
    df = run_hashing_shortlist(test_urls)
    print(df)
