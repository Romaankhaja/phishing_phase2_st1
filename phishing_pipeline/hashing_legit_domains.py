import pandas as pd
import json
import asyncio
import ssl
import os
import time
import multiprocessing as mp
import psutil
from playwright.async_api import async_playwright
from urllib.parse import urlparse
from .similarity_hashing import (
    compute_domain_simhash,
    compute_image_phash,
    compute_ssl_simhash,
)

try:
    import aiohttp
    _has_aiohttp = True
except ImportError:
    _has_aiohttp = False

def _read_env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _runtime_parallelism() -> int:
    cpu_count = mp.cpu_count() or 4
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)

    if cpu_count >= 32 and ram_gb >= 96:
        max_pages = min(64, max(32, cpu_count))
    elif cpu_count >= 16:
        max_pages = 32
    else:
        max_pages = 16

    return _read_env_int("PHISHING_LEGIT_HASH_PAGES", max_pages)


MAX_CONCURRENT_PAGES = _runtime_parallelism()

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
                    return compute_image_phash(data)
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
            return compute_image_phash(r.content)
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
            cert_info = ssl_obj.getpeercert()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if cert_info:
                return compute_ssl_simhash(cert_info)
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
                return compute_ssl_simhash(ssock.getpeercert())
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


async def _scan_domain(domain, entity, context, semaphore, aio_session, lock):
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
            # STORE DATA â€” protected by lock
            ###################################

            async with lock:
                entity_db[entity]["domains"].append(domain)
                entity_db[entity]["domain_simhashes"].append(compute_domain_simhash(domain))
                entity_db[entity]["page_phashes"].append(compute_image_phash(screenshot))
                entity_db[entity]["favicon_phashes"].append(fav_result)
                entity_db[entity]["ssl_simhashes"].append(ssl_result)

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
                "domain_simhashes": [],
                "page_phashes": [],
                "favicon_phashes": [],
                "ssl_simhashes": [],
                "keywords": []
            }

            for domain in group["domain"]:
                all_tasks.append(
                    _scan_domain(domain, entity, context, semaphore, aio_session, lock)
                )

        total = len(all_tasks)
        print(f"ðŸš€ Scanning {total} domains with up to {MAX_CONCURRENT_PAGES} concurrent pages...")

        await asyncio.gather(*all_tasks)

        await browser.close()

    if aio_session:
        await aio_session.close()

    browse_elapsed = time.perf_counter() - t0
    print(f"â± Phase 1 (browsing) done in {browse_elapsed:.1f}s")

    total_elapsed = time.perf_counter() - t0
    print(f"â± Total generation time: {total_elapsed:.1f}s")


###############################################
# RUN
###############################################

asyncio.run(generate_hashes())


###############################################
# SAVE
###############################################

output_payload = {
    "_meta": {
        "hash_schema_version": 2,
    },
    **entity_db,
}

with open(os.path.join(os.path.dirname(BASE_DIR), "data", "entity_hash_db.json"), "w", encoding="utf-8") as f:
    json.dump(output_payload, f, indent=4)


print("âœ… DB GENERATED WITH SIMILARITY HASHES (schema v2)")

