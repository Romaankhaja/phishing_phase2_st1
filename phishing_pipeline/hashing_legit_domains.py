import pandas as pd
import json
import hashlib
import asyncio
import ssl
import os
import time
import multiprocessing as mp
import numpy as np
import psutil
import torch
from io import BytesIO
from playwright.async_api import async_playwright
from PIL import Image
from bs4 import BeautifulSoup
from urllib.parse import urlparse

try:
    import aiohttp
    _has_aiohttp = True
except ImportError:
    import requests as _requests_fallback
    _has_aiohttp = False

# Use the shared, optimized CLIP from comparison.py (lazy-loaded, FP16, batched)
from .comparison import get_clip_embeddings_batch


def _read_env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _runtime_parallelism() -> tuple[int, int]:
    cpu_count = mp.cpu_count() or 4
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    vram_gb = 0.0
    if torch.cuda.is_available():
        try:
            vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        except Exception:
            vram_gb = 0.0

    if cpu_count >= 32 and ram_gb >= 96:
        max_pages = min(64, max(32, cpu_count))
    elif cpu_count >= 16:
        max_pages = 32
    else:
        max_pages = 16

    if vram_gb >= 80:
        clip_batch = 512
    elif vram_gb >= 40:
        clip_batch = 256
    elif vram_gb >= 16:
        clip_batch = 128
    else:
        clip_batch = 64

    return (
        _read_env_int("PHISHING_LEGIT_HASH_PAGES", max_pages),
        _read_env_int("PHISHING_LEGIT_CLIP_BATCH", clip_batch),
    )


MAX_CONCURRENT_PAGES, CLIP_BATCH_SIZE = _runtime_parallelism()

###############################################
# HELPERS
###############################################

def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# â”€â”€ Async favicon fetching â”€â”€
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
                    return sha256_bytes(data)
        except Exception:
            pass
        return None
    else:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _favicon_hash_sync, domain)


def _favicon_hash_sync(domain):
    """Sync fallback for favicon fetch."""
    try:
        import requests
        r = requests.get(f"https://{domain}/favicon.ico", timeout=5)
        if r.status_code == 200:
            return sha256_bytes(r.content)
    except Exception:
        pass
    return None


# Keep old sync version for backward compat
def favicon_hash(domain):
    return _favicon_hash_sync(domain)


# â”€â”€ Async SSL cert hash â”€â”€
async def get_ssl_hash_async(domain):
    """Non-blocking SSL certificate hash fetch."""
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx),
            timeout=5,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert_der = ssl_obj.getpeercert(binary_form=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if cert_der:
                return sha256_bytes(cert_der)
        writer.close()
    except Exception:
        pass
    return None


# Keep old sync version for backward compat
def get_ssl_hash(domain):
    try:
        ctx = ssl.create_default_context()
        import socket
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return sha256_bytes(ssock.getpeercert(binary_form=True))
    except Exception:
        return None


###############################################
# LOAD EXCEL
###############################################

BASE_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(BASE_DIR)
EXCEL_PATH = os.path.join(ROOT_DIR, "data", "Stage_2_Legitimate_Domains.xlsx")

df = pd.read_excel(EXCEL_PATH)
df["CSE Name"] = df["CSE Name"].ffill()


def clean_domain(url):
    if pd.isna(url):
        return None

    url = str(url).strip()

    if not url.startswith("http"):
        url = "https://" + url

    return urlparse(url).netloc.lower()


df["domain"] = df["Legitimate Domains/URLs"].apply(clean_domain)
df = df.dropna(subset=["domain"])


###############################################
# MAIN (parallel)
###############################################

entity_db = {}


async def _scan_domain(domain, entity, context, semaphore, aio_session, lock,
                        pending_clips):
    """
    Scan a single domain concurrently.
    Semaphore limits parallel Playwright pages.
    Lock protects entity_db writes.
    """
    async with semaphore:
        print(f"  â†³ Scanning: {domain}")
        page = await context.new_page()
        try:
            url = "https://" + domain

            await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            await page.wait_for_timeout(3000)

            html = await page.content()
            screenshot = await page.screenshot()

            ###################################
            # COLLECT FEATURES IN PARALLEL
            ###################################

            # Favicon + SSL fetched concurrently (async I/O)
            fav_task = favicon_hash_async(domain, session=aio_session)
            ssl_task = get_ssl_hash_async(domain)
            fav_result, ssl_result = await asyncio.gather(fav_task, ssl_task)

            ###################################
            # STORE DATA (non-CLIP) â€” protected by lock
            ###################################

            img = Image.open(BytesIO(screenshot)).convert("RGB")
            img = img.resize((224, 224))  # pre-resize for speed

            async with lock:
                entity_db[entity]["domains"].append(domain)
                entity_db[entity]["domain_hashes"].append(sha256_text(domain))
                entity_db[entity]["html_hashes"].append(sha256_text(html))
                entity_db[entity]["favicon_hashes"].append(fav_result)
                entity_db[entity]["ssl_hashes"].append(ssl_result)
                pending_clips[entity].append(img)

        except Exception as e:
            print(f"  âš  Error: {domain} â€” {e}")

        await page.close()


async def generate_hashes():
    t0 = time.perf_counter()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PAGES)
    lock = asyncio.Lock()

    # aiohttp session for non-blocking favicon fetches
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_PAGES * 2) if _has_aiohttp else None
    aio_session = aiohttp.ClientSession(connector=connector) if _has_aiohttp else None

    # pending_clips[entity] = list of PIL images (collected during browsing)
    pending_clips = {}

    async with async_playwright() as p:

        browser = await p.chromium.launch(headless=True)

        context = await browser.new_context(
            user_agent="Mozilla/5.0",
            viewport={"width": 1366, "height": 768}
        )

        # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # PHASE 1: Browse & collect screenshots (PARALLEL)
        # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        all_tasks = []

        for entity, group in df.groupby("CSE Name"):

            entity_db[entity] = {
                "domains": [],
                "domain_hashes": [],
                "html_hashes": [],
                "screenshot_clip": [],   # will be filled in Phase 2
                "favicon_hashes": [],
                "ssl_hashes": [],
                "keywords": []
            }

            pending_clips[entity] = []

            for domain in group["domain"]:
                all_tasks.append(
                    _scan_domain(domain, entity, context, semaphore, aio_session,
                                 lock, pending_clips)
                )

        total = len(all_tasks)
        print(f"ðŸš€ Scanning {total} domains with up to {MAX_CONCURRENT_PAGES} concurrent pages...")

        await asyncio.gather(*all_tasks)

        await browser.close()

    if aio_session:
        await aio_session.close()

    browse_elapsed = time.perf_counter() - t0
    print(f"â± Phase 1 (browsing) done in {browse_elapsed:.1f}s")

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # PHASE 2: Batch CLIP embedding (GPU-bound)
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Collect ALL images across all entities into one flat list for maximum batching
    all_images = []
    image_map = []  # (entity, index_within_entity)

    for entity, images in pending_clips.items():
        for i, img in enumerate(images):
            all_images.append(img)
            image_map.append((entity, i))

    if all_images:
        print(f"ðŸ§  Batch-embedding {len(all_images)} screenshots through CLIP (batch_size={CLIP_BATCH_SIZE})...")
        embeddings = get_clip_embeddings_batch(all_images, batch_size=CLIP_BATCH_SIZE)

        for (entity, _), emb in zip(image_map, embeddings):
            entity_db[entity]["screenshot_clip"].append(emb.tolist())

        print("âœ… Batch CLIP embedding complete.")

    total_elapsed = time.perf_counter() - t0
    print(f"â± Total generation time: {total_elapsed:.1f}s")


###############################################
# RUN
###############################################

asyncio.run(generate_hashes())


###############################################
# SAVE
###############################################

with open(os.path.join(os.path.dirname(BASE_DIR), "data", "entity_hash_db.json"), "w") as f:
    json.dump(entity_db, f, indent=4)


print("âœ… DB GENERATED WITH CLIP")

