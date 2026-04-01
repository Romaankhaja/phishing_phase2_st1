import json
import hashlib
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import asyncio
from playwright.async_api import async_playwright
from rapidfuzz.fuzz import ratio
import numpy as np
import csv
import os
import time
import torch
import logging as _logging
import warnings as _warnings

try:
    import aiohttp
    _has_aiohttp = True
except ImportError:
    import requests
    _has_aiohttp = False

_clip_logger = _logging.getLogger(__name__)

# ── Parallelism tuning (auto-tuned from system resources) ──
import multiprocessing as _mp
_CPU_COUNT = _mp.cpu_count() or 4

# Scale concurrency to available CPU cores:
#   ≥48 cores (server)  → 120 pages, 16 per shard
#   ≥16 cores           →  48 pages,  8 per shard
#    <16 cores          →  16 pages,  4 per shard
if _CPU_COUNT >= 48:
    MAX_CONCURRENT_PAGES     = 120
    SCRAPER_PAGE_CONCURRENCY = 16
elif _CPU_COUNT >= 16:
    MAX_CONCURRENT_PAGES     = 48
    SCRAPER_PAGE_CONCURRENCY = 8
else:
    MAX_CONCURRENT_PAGES     = 16
    SCRAPER_PAGE_CONCURRENCY = 4

BROWSER_SHARDS = max(1, MAX_CONCURRENT_PAGES // SCRAPER_PAGE_CONCURRENCY)
SCRAPER_NAV_TIMEOUT_MS        = 8000   # domcontentloaded hard cap
SCRAPER_SCREENSHOT_TIMEOUT_MS = 3000   # viewport-only screenshot
SCRAPER_FETCH_TIMEOUT_S       = 10.0   # outer per-URL fence
GPU_QUEUE_MAXSIZE  = BROWSER_SHARDS * SCRAPER_PAGE_CONCURRENCY * 2
GPU_MAX_WAIT_MS    = 50
_AIOHTTP_CONNECTOR_LIMIT = min(256, MAX_CONCURRENT_PAGES * 2)

def _probe_gpu_batch_size() -> int:
    if not torch.cuda.is_available():
        return 16
    try:
        free_bytes, _ = torch.cuda.mem_get_info()
        vram_gb = free_bytes / 1024**3
        if vram_gb >= 80:
            return 256
        if vram_gb >= 40:
            return 128
        if vram_gb >= 16:
            return 64
        return 16
    except Exception:
        return 16

GPU_MAX_BATCH_SIZE = _probe_gpu_batch_size()

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

# ── Lazy-loaded singletons (initialized on first use) ──
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
        _clip_logger.info("🚀 Loading CLIP model (%s) on %s...", _MODEL_NAME, device)
        m = CLIPModel.from_pretrained(_MODEL_NAME, use_safetensors=True)
        # FP16 on CUDA for massive throughput
        if device == "cuda":
            m = m.half()
        m = m.to(device).eval()
        p = CLIPProcessor.from_pretrained(_MODEL_NAME, use_fast=True)
        _model, _processor = m, p
        _clip_logger.info("✅ CLIP model ready (dtype=%s)", next(m.parameters()).dtype)
        return _model, _processor
    except Exception as e:
        _has_clip = False
        _model = None
        _processor = None
        _clip_logger.debug("Failed to init CLIP model, using fallback embeddings: %s", e)
        return None, None

# Backward-compat aliases used by external code that references the globals
model = None      # legacy — use _get_model() instead
processor = None  # legacy — use _get_model() instead

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


# ✅ CSV LOADER (NEW)
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

# Only load test URLs if running standalone; do not crash module import.
# url_list = load_domains(URLS_PATH)

WEIGHTS = {
    "domain": 20,
    "screenshot": 60,
    "favicon": 5,
    "keywords": 15
}
_TOTAL_WEIGHT = sum(WEIGHTS.values())

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
        ]
    )


# Block all resource types not needed for HTML text + screenshot extraction.
# Dropping images/fonts/media/stylesheets cuts per-page network time significantly.
_BLOCKED_RESOURCE_TYPES = {"font", "media", "image", "stylesheet", "other", "eventsource", "websocket"}

async def _route_nonessential_requests(route):
    request = route.request
    if request.resource_type in _BLOCKED_RESOURCE_TYPES:
        await route.abort()
        return
    await route.continue_()


# ── Async favicon fetching (non-blocking) ──
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
        # Sync fallback — run in thread so we don't block the loop
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


def domain_similarity(d1, d2):
    if isinstance(d1, list): d1 = d1[0] if d1 else ""
    if isinstance(d2, list): d2 = d2[0] if d2 else ""
    e1 = tldextract.extract(str(d1))
    e2 = tldextract.extract(str(d2))

    if e1.domain == e2.domain:
        return 1.0

    return ratio(e1.domain, e2.domain) / 100


###############################################
# PRE-COMPUTED ENTITY INDEX (vectorised scoring)
###############################################

def _build_entity_index(entity_db):
    """
    Pre-compute numpy arrays from entity_db for vectorised scoring.
    Called once at module load — avoids repeated dict traversal.
    """
    entity_names = list(entity_db.keys())

    # Build a matrix of ALL screenshot CLIP vectors across ALL entities
    # plus a mapping so we know which rows belong to which entity.
    clip_vecs = []
    clip_entity_idx = []  # index into entity_names for each row

    entity_domains = []      # list of domain-lists, aligned with entity_names
    entity_fav_sets = []     # list of favicon-hash-sets
    entity_kw_sets = []      # list of keyword-sets

    for idx, name in enumerate(entity_names):
        data = entity_db[name]

        entity_domains.append(data.get("domains", []))
        entity_fav_sets.append(set(data.get("favicon_hashes", [])) - {None})
        entity_kw_sets.append(set(data.get("keywords", [])))

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
        "kw_sets": entity_kw_sets,
    }


_entity_index = _build_entity_index(entity_db)

_gpu_clip_matrix = None
if _entity_index["clip_matrix"].shape[0] > 0 and device == "cuda":
    # Push precomputed numpy matrices permanently into H100 VRAM for instant access
    _gpu_clip_matrix = torch.tensor(_entity_index["clip_matrix"], dtype=torch.float32, device=device)

# ── Top-level helper for ProcessPoolExecutor (must be picklable) ──

def _domain_sim_for_entity(args):
    """Compute max domain similarity for one entity. Runs in child process."""
    target_domain, entity_domains = args
    if not entity_domains:
        return 0.0
    return max(domain_similarity(target_domain, d) for d in entity_domains)


###############################################
# VECTORISED SCORING
###############################################

def score_all_entities(screenshot_vec, target_domain, fav_hash, words, pool):
    """
    Score target against ALL entities using vectorised numpy ops + process pool.
    Returns dict { entity_name: score (0-100) }.
    """
    idx = _entity_index
    n_entities = len(idx["names"])
    scores = np.zeros(n_entities, dtype="float64")

    # ─── SCREENSHOT (vectorised GPU/CPU cosine similarity) ───
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
                scores[i] += float(all_sims[mask].max()) * WEIGHTS["screenshot"]

    # ─── DOMAIN (process pool for CPU-bound tldextract + rapidfuzz) ───
    args_list = [(target_domain, idx["domains"][i]) for i in range(n_entities)]
    domain_sims = list(pool.map(_domain_sim_for_entity, args_list))
    for i, sim in enumerate(domain_sims):
        scores[i] += sim * WEIGHTS["domain"]

    # ─── FAVICON (set lookup – O(1) per entity) ───
    if fav_hash:
        for i in range(n_entities):
            if fav_hash in idx["fav_sets"][i]:
                scores[i] += WEIGHTS["favicon"]

    # ─── KEYWORDS (set intersection) ───
    for i in range(n_entities):
        kw = idx["kw_sets"][i]
        if kw:
            overlap = len(words & kw)
            scores[i] += min(overlap / 5, 1.0) * WEIGHTS["keywords"]

    # ─── NORMALISE ───
    scores = (scores / _TOTAL_WEIGHT) * 100

    return {idx["names"][i]: float(scores[i]) for i in range(n_entities)}


###############################################
# STREAMING FETCH PIPELINE
###############################################

async def _fetch_url_payload(url, browser_context, semaphore, aio_session):
    """
    Fetch one URL: navigate, screenshot, parse HTML, compute CPU-side scores.
    Returns payload dict for GPU queue, or None on timeout/crash.
    Retries once on TargetClosedError (browser crash).
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

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

    fav_hash = await favicon_hash_async(domain, session=aio_session)

    n_entities = len(_entity_index["names"])
    cpu_scores = np.zeros(n_entities, dtype="float64")
    for i in range(n_entities):
        entity_domains = _entity_index["domains"][i]
        if entity_domains:
            cpu_scores[i] += max(
                domain_similarity(domain, d) for d in entity_domains
            ) * WEIGHTS["domain"]
        if fav_hash and fav_hash in _entity_index["fav_sets"][i]:
            cpu_scores[i] += WEIGHTS["favicon"]
        if _entity_index["kw_sets"][i]:
            overlap = len(words & _entity_index["kw_sets"][i])
            cpu_scores[i] += min(overlap / 5, 1.0) * WEIGHTS["keywords"]

    return {
        "url": url,
        "domain": domain,
        "screenshot_bytes": screenshot_bytes,
        "cpu_scores": cpu_scores,
    }


###############################################
# BROWSER SHARDS
###############################################

async def _run_browser_shard(shard_id, url_queue, gpu_queue, metrics, aio_session):
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
                payload = await _fetch_url_payload(url, ctx, semaphore, aio_session)
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

async def _gpu_microbatch_scorer(gpu_queue, results, metrics, threshold):
    """
    Single GPU scorer. Flushes on GPU_MAX_BATCH_SIZE or GPU_MAX_WAIT_MS.
    """
    loop = asyncio.get_running_loop()
    batch = []
    deadline = None

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
            sims_b = all_sims[:, b] if all_sims.ndim > 1 else all_sims

            for i in range(n_entities):
                mask = eidx == i
                if mask.any():
                    if isinstance(sims_b, torch.Tensor):
                        entity_sims = sims_b[torch.tensor(mask, device=sims_b.device)]
                        scores[i] += float(entity_sims.max().item()) * WEIGHTS["screenshot"]
                    else:
                        scores[i] += float(sims_b[mask].max()) * WEIGHTS["screenshot"]

            scores = (scores / _TOTAL_WEIGHT) * 100
            best_idx = int(np.argmax(scores))
            best_score = float(scores[best_idx])
            best_entity = _entity_index["names"][best_idx]

            if best_score > threshold:
                metrics["final_matches_above_threshold"] += 1
                results.append((payload["url"], best_entity, best_score))

        metrics["gpu_items_scored"] += len(valid_payloads)
        metrics["avg_gpu_batch_size"] = (
            metrics["gpu_items_scored"] / max(1, metrics["gpu_batches_flushed"])
        )

    while True:
        now = loop.time()
        wait = None if deadline is None else max(0.001, deadline - now)
        try:
            payload = await asyncio.wait_for(gpu_queue.get(), timeout=wait)
            if payload is None:  # sentinel — flush and exit
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


def _log_hashing_metrics_summary(metrics, elapsed, threshold):
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


###############################################
# STREAMING ENGINE
###############################################

async def run_hashing_shortlist_streaming(url_list, threshold=65):
    """
    Streaming hashing shortlist engine. Uses long-lived browser shards
    feeding a bounded GPU queue. No Ray dependency.
    """
    import pandas as pd

    log_path = _configure_hashing_log()
    original_count = len(url_list)
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

    _clip_logger.info(
        "Hashing shortlist (streaming) started | urls=%d | threshold=%s",
        original_count, threshold,
    )

    try:
        from .dns_gate import (
            DEFAULT_DNS_TIMEOUT,
            _gate_urls_for_hashing_async,
            write_dns_gate_audit,
        )

        shortlisted_urls, audit_rows = await _gate_urls_for_hashing_async(
            list(url_list),
            timeout=DEFAULT_DNS_TIMEOUT,
            max_workers=None,
        )
        write_dns_gate_audit(audit_rows)
        accepted_count = len(shortlisted_urls)
        metrics["passed_dns_gate"] = accepted_count
        _clip_logger.info(
            "DNS gate kept %d/%d URLs at %.1fs timeout",
            accepted_count, original_count, DEFAULT_DNS_TIMEOUT,
        )
        print(
            f"DNS gate kept {accepted_count}/{original_count} URLs "
            f"(timeout={DEFAULT_DNS_TIMEOUT:.1f}s)"
        )
        _clip_logger.info("Hashing log file: %s", log_path)
        print(f"Hashing log: {log_path}")

        if not shortlisted_urls:
            _clip_logger.info("No URLs passed DNS gate; skipping hashing.")
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
                    _run_browser_shard(i, url_queue, gpu_queue, metrics, aio_session)
                )
                for i in range(BROWSER_SHARDS)
            ]
            scorer_task = asyncio.create_task(
                _gpu_microbatch_scorer(gpu_queue, results, metrics, threshold)
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
        _log_hashing_metrics_summary(metrics, elapsed, threshold)

        rows = []
        for target_url, best_entity, best_score in results:
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
            })

        if not rows:
            return _empty_shortlist_df()
        return pd.DataFrame(rows)

    except Exception:
        _clip_logger.exception("Hashing shortlist (streaming) crashed.")
        raise
    finally:
        _close_hashing_log()


###############################################
# PUBLIC API (unchanged signatures)
###############################################

def run_hashing_shortlist(url_list, threshold=65):
    """Synchronous entry point for hashing shortlist."""
    return asyncio.run(run_hashing_shortlist_streaming(url_list, threshold=threshold))


async def run_hashing_shortlist_async(url_list, threshold=65):
    """Async entry point for hashing shortlist."""
    return await run_hashing_shortlist_streaming(url_list, threshold=threshold)


if __name__ == "__main__":
    test_urls = [
        "https://www.onlinesbi.sbi/",
        "http://airtel.in",
        "http://myjio.login.com",
    ]
    df = run_hashing_shortlist(test_urls)
    print(df)
