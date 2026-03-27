import json
import ray
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

# ── Parallelism tuning (AMD EPYC 9654 + NVIDIA H100) ──
MAX_CONCURRENT_PAGES =  120# Scale up Playwright pages for AMD EPYC
DOMAIN_SIM_WORKERS   = 40       # More ProcessPoolExecutor workers for CPU-bound scoring
CLIP_BATCH_SIZE      = 3000  # Massive VRAM allows huge batch pass

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
# PARALLEL DETECTION
###############################################

async def fetch_features(target_url, browser, semaphore, aio_session):
    """
    Playwright Scraping ONLY - decoupled from GPU Inference.
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
            return target_url, target_domain, None, None, None

    # HTML parsing (CPU-bound but fast)
    soup = BeautifulSoup(html, "html.parser")
    visible_text = " ".join(
        [p.get_text() for p in soup.find_all(["p", "h1", "h2", "h3", "title"])]
    ).lower()
    words = set(visible_text.split())

    # Favicon (async I/O)
    fav_hash = await favicon_hash_async(target_domain, session=aio_session)

    return target_url, target_domain, screenshot, words, fav_hash


###############################################
# RUN (parallel)
###############################################

###############################################
# RAY DISTRIBUTED DETECTION
###############################################

@ray.remote(num_gpus=1)
class GPUInferenceActor:
    def __init__(self, clip_matrix_np):
        import torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.gpu_clip_matrix = torch.tensor(clip_matrix_np, dtype=torch.float32, device=self.device)

    def score_batch(self, images, cpu_scores_batch):
        import torch
        import numpy as np
        if not images:
            return []
        
        clip_embeddings = get_clip_embeddings_batch(images, batch_size=len(images))
        sv = torch.tensor(clip_embeddings, dtype=torch.float32, device=self.device)
        sv = sv / sv.norm(dim=1, keepdim=True).clamp(min=1e-8)
        
        all_sims = torch.mm(self.gpu_clip_matrix, sv.T).cpu().numpy()
        
        n_entities = len(_entity_index["names"])
        results = []
        for b in range(len(images)):
            scores = cpu_scores_batch[b].copy()
            
            # all_sims is shape (M, B)
            if all_sims.ndim > 1:
                all_sims_b = all_sims[:, b]
            else:
                all_sims_b = all_sims
            
            for i in range(n_entities):
                mask = _entity_index["clip_entity_idx"] == i
                if mask.any():
                    scores[i] += float(all_sims_b[mask].max()) * WEIGHTS["screenshot"]
            
            scores = (scores / _TOTAL_WEIGHT) * 100
            best_idx = int(np.argmax(scores))
            results.append({
                "entity": _entity_index["names"][best_idx], 
                "score": float(scores[best_idx])
            })
        return results

@ray.remote(num_cpus=1)
def process_url_chunk_ray(chunk_urls, gpu_actor_handle):
    import asyncio
    return asyncio.run(_async_process_chunk(chunk_urls, gpu_actor_handle))

async def _async_process_chunk(chunk_urls, gpu_actor_handle):
    import asyncio
    import aiohttp
    from playwright.async_api import async_playwright
    from PIL import Image
    from io import BytesIO
    import numpy as np

    semaphore = asyncio.Semaphore(16)
    connector = aiohttp.TCPConnector(limit=32) if _has_aiohttp else None
    aio_session = aiohttp.ClientSession(connector=connector) if _has_aiohttp else None
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        tasks = [fetch_features(u, browser, semaphore, aio_session) for u in chunk_urls]
        chunk_features = await asyncio.gather(*tasks)
        await browser.close()
    if aio_session:
        await aio_session.close()

    images = []
    cpu_scores_list = []
    final_urls = []
    
    n_entities = len(_entity_index["names"])
    
    for url, domain, screenshot, words, fav_hash in chunk_features:
        if screenshot is None:
            continue
        images.append(Image.open(BytesIO(screenshot)))
        final_urls.append(url)
        
        scores = np.zeros(n_entities, dtype="float64")
        for i in range(n_entities):
            entity_domains = _entity_index["domains"][i]
            if entity_domains:
                d_sim = max(domain_similarity(domain, d) for d in entity_domains)
            else:
                d_sim = 0.0
            scores[i] += d_sim * WEIGHTS["domain"]
            if fav_hash and fav_hash in _entity_index["fav_sets"][i]:
                scores[i] += WEIGHTS["favicon"]
            if _entity_index["kw_sets"][i]:
                overlap = len(words & _entity_index["kw_sets"][i])
                scores[i] += min(overlap / 5, 1.0) * WEIGHTS["keywords"]
        cpu_scores_list.append(scores)
        
    if not images:
        return []
        
    cpu_scores_batch = np.array(cpu_scores_list, dtype="float32")
    # RPC to the hot VRAM Actor!
    gpu_results = await gpu_actor_handle.score_batch.remote(images, cpu_scores_batch)
    
    out = []
    for url, res in zip(final_urls, gpu_results):
        out.append((url, res["entity"], res["score"]))
    return out

def run_hashing_shortlist_ray(url_list, threshold=65):
    import pandas as pd
    import time
    t0 = time.perf_counter()
    
    # Pre-init Ray using EPYC's 48 CPUs and H100 GPU
    if not ray.is_initialized():
        ray.init(ignore_reinit_error=True)
        
    chunk_size = 128
    print(f"🚀 Submitting {len(url_list)} URLs to Ray Cluster across CPUs and 1 GPU...")
    
    gpu_actor = GPUInferenceActor.remote(_entity_index["clip_matrix"])
    
    futures = []
    # Send chunks rapidly as asynchronous Ray RPC Tasks
    for i in range(0, len(url_list), chunk_size):
        chunk = url_list[i : i+chunk_size]
        futures.append(process_url_chunk_ray.remote(chunk, gpu_actor))
        
    results = []
    while futures:
        ready, futures = ray.wait(futures, num_returns=1, timeout=0.1)
        for f in ready:
            res_list = ray.get(f)
            for url, best_entity, best_score in res_list:
                if best_score > threshold:
                    print(f"✅ {url} -> {best_entity} ({best_score:.1f}%)")
                    results.append((url, best_entity, best_score))
                else:
                    print(f"❌ {url} -> None (best: {best_entity} {best_score:.1f}%)")
                
    elapsed = time.perf_counter() - t0
    print(f"\n⏱ Ray Processing done in {elapsed:.1f}s ({len(url_list)} URLs)")
    
    # Optional cleanup for long running instances
    ray.shutdown()
    
    rows = []
    for target_url, best_entity, best_score in results:
        rows.append({
            "Cooresponding CSE": best_entity,
            "Identified Phishing/Suspected Domain Name": target_url
        })
    return pd.DataFrame(rows)

def run_hashing_shortlist(url_list, threshold=65):
    return run_hashing_shortlist_ray(url_list, threshold)

# Alias for backward compatibility with main_controller.py
run_hashing_shortlist_async = run_hashing_shortlist_ray

if __name__ == "__main__":
    test_urls = [
        "https://www.onlinesbi.sbi/",
        "http://airtel.in",
        "http://myjio.login.com",
    ]
    df = run_hashing_shortlist_ray(test_urls)
    print(df)
