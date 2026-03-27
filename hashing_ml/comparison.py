import json
import hashlib
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import asyncio
from concurrent.futures import ProcessPoolExecutor
from playwright.async_api import async_playwright
from rapidfuzz.fuzz import ratio
import numpy as np
import csv
import os
import time
import torch
import logging as _logging

try:
    import aiohttp
    _has_aiohttp = True
except ImportError:
    import requests
    _has_aiohttp = False

_clip_logger = _logging.getLogger(__name__)

# ── Parallelism tuning (AMD EPYC 9654 – 48 cores) ──
MAX_CONCURRENT_PAGES = 24       # Playwright pages open at the same time
DOMAIN_SIM_WORKERS   = 32       # ProcessPoolExecutor workers for CPU-bound scoring
CLIP_BATCH_SIZE      = 64       # H100 has 95 GB VRAM – use bigger batches

# transformers and CLIP are optional; use fallback for environments without these deps.
try:
    from transformers import CLIPProcessor, CLIPModel
    _has_clip = True
except Exception as e:
    _has_clip = False
    CLIPProcessor = None
    CLIPModel = None
    print(f"⚠ transformers/CLIP import failed, using fallback embeddings: {e}")

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
        m = CLIPModel.from_pretrained(_MODEL_NAME)
        # FP16 on CUDA for ~2× throughput with negligible accuracy loss
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
        print(f"⚠ Failed to init CLIP model, using fallback embeddings: {e}")
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


def get_clip_embeddings_batch(images: list, batch_size: int = CLIP_BATCH_SIZE) -> list:
    """
    Process multiple PIL images through CLIP in batched forward passes.
    Returns a list of normalized numpy arrays (float32, shape 512).

    batch_size default = 64 to leverage H100's 95 GB VRAM.
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
                features = m.get_image_features(**inputs)

            # L2 normalize
            features = features / features.norm(dim=-1, keepdim=True).clamp(min=1e-8)
            batch_np = features.cpu().float().numpy().astype("float32")
            all_embeddings.extend(batch_np)
        except Exception as e:
            _clip_logger.warning("⚠ CLIP batch embedding failed: %s", e)
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

with open(os.path.join(BASE_DIR, "entity_hash_db.json")) as f:
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
URLS_PATH = os.path.join(BASE_DIR, "urls.csv")

url_list = load_domains(URLS_PATH)

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
    e1 = tldextract.extract(d1)
    e2 = tldextract.extract(d2)

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

    # ─── SCREENSHOT (vectorised cosine similarity) ───
    if idx["clip_matrix"].shape[0] > 0 and screenshot_vec is not None:
        sv = np.array(screenshot_vec, dtype="float32").reshape(1, -1)
        sv_norm = np.linalg.norm(sv).clip(min=1e-8)
        sv = sv / sv_norm
        # dot product with all entity vecs at once → (N,) similarity scores
        all_sims = idx["clip_matrix"] @ sv.T  # shape (N, 1)
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
# PARALLEL DETECTION
###############################################

async def detect_entity(target_url, browser, semaphore, aio_session, pool):
    """
    Process a single URL: browse → extract features → score entities.
    Semaphore limits concurrent Playwright pages.
    """
    target_url = normalize_url(target_url)
    parsed = urlparse(target_url)
    target_domain = parsed.netloc.lower()

    async with semaphore:
        try:
            page = await browser.new_page()

            await page.goto(target_url, timeout=40000)
            await page.wait_for_load_state("networkidle")
            await page.wait_for_timeout(2000)

            html = await page.content()
            screenshot = await page.screenshot()

            await page.close()

        except Exception:
            print(f"⚠ Failed loading {target_url}")
            return target_url, None, 0.0

    ###############################################
    # FEATURES (collected in parallel where possible)
    ###############################################

    # CLIP embedding (GPU-bound — runs on caller thread)
    screenshot_vec = get_clip_embedding(Image.open(BytesIO(screenshot)))

    # HTML parsing (CPU-bound but fast)
    soup = BeautifulSoup(html, "html.parser")
    visible_text = " ".join(
        [p.get_text() for p in soup.find_all(["p", "h1", "h2", "h3", "title"])]
    ).lower()
    words = set(visible_text.split())

    # Favicon (async I/O)
    fav_hash = await favicon_hash_async(target_domain, session=aio_session)

    ###############################################
    # SCORING (vectorised + process pool)
    ###############################################

    scores = score_all_entities(screenshot_vec, target_domain, fav_hash, words, pool)

    ###############################################
    # RESULT
    ###############################################

    best_entity = max(scores, key=scores.get)
    best_score = scores[best_entity]

    print(f"\n🔎 {target_url}")

    if best_score > 65:
        print(f"✅ Related to: {best_entity} ({best_score:.1f}%)")
        return target_url, best_entity, best_score
    else:
        print(f"❌ Not related to any known CSE (best: {best_entity} {best_score:.1f}%)")
        return target_url, None, best_score


###############################################
# RUN (parallel)
###############################################

async def run_hashing_shortlist_async(url_list, threshold=65):
    import pandas as pd
    t0 = time.perf_counter()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PAGES)

    # Create a shared aiohttp session (connection pooling)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_PAGES * 2) if _has_aiohttp else None
    aio_session = aiohttp.ClientSession(connector=connector) if _has_aiohttp else None

    # Process pool for CPU-bound domain similarity
    pool = ProcessPoolExecutor(max_workers=DOMAIN_SIM_WORKERS)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        print(f"🚀 Processing {len(url_list)} URLs with up to {MAX_CONCURRENT_PAGES} concurrent pages...")

        tasks = [
            detect_entity(url, browser, semaphore, aio_session, pool)
            for url in url_list
        ]
        results = await asyncio.gather(*tasks)

        await browser.close()

    pool.shutdown(wait=False)

    if aio_session:
        await aio_session.close()

    elapsed = time.perf_counter() - t0
    print(f"\n⏱ Done in {elapsed:.1f}s ({len(url_list)} URLs)")

    rows = []
    for target_url, best_entity, best_score in results:
        if best_entity is not None and best_score >= threshold:
            rows.append({
                "Cooresponding CSE": best_entity,
                "Identified Phishing/Suspected Domain Name": target_url
            })
    
    return pd.DataFrame(rows)

def run_hashing_shortlist(url_list, threshold=65):
    """Synchronous wrapper for the hashing shortlisting process."""
    return asyncio.run(run_hashing_shortlist_async(url_list, threshold))

if __name__ == "__main__":
    # For testing standalone
    test_urls = [
        "https://www.onlinesbi.sbi/",
        "http://airtel.in",
        "http://myjio.login.com",
    ]
    df = run_hashing_shortlist(test_urls)
    print(df)