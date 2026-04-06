import sys, asyncio, re, os, socket, whois, dns.resolver, logging, time
import httpx

# Suppress noisy httpx request logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class _WhoisSocketNoiseFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        return "Error trying to connect to socket: closing socket" not in message


logging.getLogger("whois.whois").addFilter(_WhoisSocketNoiseFilter())
import pandas as pd
import tldextract
from tqdm.asyncio import tqdm
from datetime import datetime
from dateutil import parser
import warnings
from urllib.parse import urlparse
from fpdf import FPDF

# Suppress noisy sklearn warnings that clutter progress bars
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
try:
    from sklearn.exceptions import ConvergenceWarning
    warnings.filterwarnings("ignore", category=ConvergenceWarning)
except ImportError:
    pass

# NEW: visual analysis imports
import cv2, imagehash
import numpy as np
from PIL import Image
# We have REMOVED pytesseract, as it's no longer used.
# EasyOCR in visual_features.py handles all text extraction now.

from .config import (
    FEATURES_CSV, FEATURES_ENRICH, FINAL_OUTPUT, CHECKPOINT_CSV,
    ASN_DB_PATH, CITY_DB_PATH, SCREENS_DIR,
    EVIDENCE_DIR, APPLICATION_ID
)
from .utils import extract_all_features_async
from .visual_features import close_browser
from .geoip_utils import enrich_with_geoip
from .model_utils import load_models_and_preproc
from .comparison import detect_parked_page_signals
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
# from .shortlisting import generate_shortlisted_csv # REMOVED: Using hashing_ml instead
from .rate_limiter import RateLimiter
from .utils import (
    MAX_CONCURRENT_RDAP, MAX_CONCURRENT_WHOIS, MAX_CONCURRENT_DNS_PREFILTER,
    _get_rdap_semaphore, _get_whois_semaphore, _get_dns_prefilter_semaphore,
    _get_ocr_semaphore,
    CHUNK_SIZE,
    MAX_CONCURRENT_OCR, MAX_CONCURRENT_SCREENSHOTS,
    NETWORK_SEMAPHORE_LIMIT,
    _get_screenshot_semaphore,
    wait_for_vram,
    extract_network_features_async,
    _create_dummy_image,

)

# ------------------------------------------------------------------
# Direct RDAP URLs (bypass rdap.org bootstrap to avoid 10/10s limit)
# ------------------------------------------------------------------
RDAP_DIRECT_URLS = {
    # Verisign
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    # Identity Digital (Donuts/Afilias) — .biz, .info, .io, .mobi, .pro, etc.
    "biz":  "https://rdap.identitydigital.services/rdap/domain/",
    "info": "https://rdap.identitydigital.services/rdap/domain/",
    "io":   "https://rdap.identitydigital.services/rdap/domain/",
    "mobi": "https://rdap.identitydigital.services/rdap/domain/",
    "pro":  "https://rdap.identitydigital.services/rdap/domain/",
    # CentralNic — .xyz, .top, .lat, .online, .site, .shop, .store, .vip
    "xyz":    "https://rdap.centralnic.com/xyz/domain/",
    "top":    "https://rdap.centralnic.com/top/domain/",
    "lat":    "https://rdap.centralnic.com/lat/domain/",
    "online": "https://rdap.centralnic.com/online/domain/",
    "site":   "https://rdap.centralnic.com/site/domain/",
    "shop":   "https://rdap.centralnic.com/shop/domain/",
    "store":  "https://rdap.centralnic.com/store/domain/",
    "vip":    "https://rdap.centralnic.com/vip/domain/",
    # PIR (.org)
    "org": "https://rdap.org/domain/",
    # NIXI (.in)
    "in":  "https://rdap.registry.in/domain/",
}
RDAP_FALLBACK_URL = "https://rdap.org/domain/"  # For TLDs not in the map

# ------------------------------------------------------------------
# RDAP lookup (fast, async, structured JSON)
# ------------------------------------------------------------------
async def rdap_lookup(domain: str, timeout: float = 10.0) -> dict | None:
    """
    Query the RDAP bootstrap service for domain registration data.
    Returns a dict with: reg_date, registrar, registrant_name, registrant_country, name_servers.
    Returns None on any failure (timeout, 404, parse error).
    """
    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()

        result = {}

        # --- Registration date ---
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                result["reg_date"] = event.get("eventDate", "NA")
                break
        if "reg_date" not in result:
            result["reg_date"] = "NA"

        # --- Registrar ---
        result["registrar"] = "NA"
        result["registrant_name"] = "NA"
        result["registrant_country"] = "NA"
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [None, []])
            vcard_items = vcard[1] if len(vcard) > 1 else []

            # Extract "fn" (full name) from vCard
            fn = "NA"
            for item in vcard_items:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    fn = item[3]
                    break

            if "registrar" in roles and fn != "NA":
                result["registrar"] = fn
            if "registrant" in roles:
                if fn != "NA":
                    result["registrant_name"] = fn
                # Try to extract country from adr vCard field
                for item in vcard_items:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
                        adr_val = item[3]
                        if isinstance(adr_val, dict):
                            result["registrant_country"] = adr_val.get("country-name", "NA")
                        elif isinstance(adr_val, list) and len(adr_val) >= 7:
                            result["registrant_country"] = adr_val[6] if adr_val[6] else "NA"
                        break

            # Check nested entities (registrar often has registrant inside)
            for sub_entity in entity.get("entities", []):
                sub_roles = sub_entity.get("roles", [])
                sub_vcard = sub_entity.get("vcardArray", [None, []])
                sub_items = sub_vcard[1] if len(sub_vcard) > 1 else []
                sub_fn = "NA"
                for item in sub_items:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        sub_fn = item[3]
                        break
                if "registrant" in sub_roles and sub_fn != "NA":
                    result["registrant_name"] = sub_fn

        # --- Name servers ---
        ns_list = []
        for ns in data.get("nameservers", []):
            ldh = ns.get("ldhName", "")
            if ldh:
                ns_list.append(ldh)
        result["name_servers"] = ";".join(ns_list) if ns_list else "NA"

        return result

    except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError):
        return None
    except Exception:
        return None


def _parse_rdap_to_fields(data: dict) -> dict:
    """
    Parse raw RDAP JSON response into standardized reg-data fields.
    Used by the 3-pass parallel RDAP batch in Phase 2.
    Returns: {reg_date, registrar, registrant_name, registrant_country, name_servers}
    """
    result = {
        "reg_date": "NA",
        "registrar": "NA",
        "registrant_name": "NA",
        "registrant_country": "NA",
        "name_servers": "NA",
    }

    # Registration date
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            result["reg_date"] = event.get("eventDate", "NA")
            break

    # Registrar & Registrant
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])
        vcard_items = vcard[1] if len(vcard) > 1 else []

        fn = "NA"
        for item in vcard_items:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                fn = item[3]
                break

        if "registrar" in roles and fn != "NA":
            result["registrar"] = fn
        if "registrant" in roles:
            if fn != "NA":
                result["registrant_name"] = fn
            for item in vcard_items:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
                    adr_val = item[3]
                    if isinstance(adr_val, dict):
                        result["registrant_country"] = adr_val.get("country-name", "NA")
                    elif isinstance(adr_val, list) and len(adr_val) >= 7:
                        result["registrant_country"] = adr_val[6] if adr_val[6] else "NA"
                    break

        # Nested entities (registrant inside registrar)
        for sub_entity in entity.get("entities", []):
            sub_roles = sub_entity.get("roles", [])
            sub_vcard = sub_entity.get("vcardArray", [None, []])
            sub_items = sub_vcard[1] if len(sub_vcard) > 1 else []
            sub_fn = "NA"
            for item in sub_items:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    sub_fn = item[3]
                    break
            if "registrant" in sub_roles and sub_fn != "NA":
                result["registrant_name"] = sub_fn

    # Name servers
    ns_list = []
    for ns in data.get("nameservers", []):
        ldh = ns.get("ldhName", "")
        if ldh:
            ns_list.append(ldh)
    result["name_servers"] = ";".join(ns_list) if ns_list else "NA"

    return result

# ---
# --- FIX 1: Define ROOT_DIR at the top so all functions can use it.
# ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
HASH_REVIEW_QUEUE_PATH = os.path.join(ROOT_DIR, "output", "hash_review_queue.csv")
STAGE2_MODEL_DEBUG_PATH = os.path.join(ROOT_DIR, "output", "stage2_model_debug.csv")
STAGE3_CLASSIFICATION_DEBUG_PATH = os.path.join(ROOT_DIR, "output", "stage3_classification_debug.csv")
# --- (End of Fix 1) ---

_STAGE1_DEBUG_COMPAT_FIELDS = (
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
)


def _stage1_debug_compat_payload(row: dict) -> dict:
    defaults = {
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
    return {
        field: row.get(field, defaults[field])
        for field in _STAGE1_DEBUG_COMPAT_FIELDS
    }

warnings.filterwarnings("ignore", message=".*pin_memory.*")

# ------------------------------------------------------------------
# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("phishing_pipeline")
logger.propagate = False

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ------------------------------------------------------------------
# Source mapping & brand config
# ------------------------------------------------------------------
SOURCE_MAPPING = {
    "sbi": "Banking/Financial", "icici": "Banking/Financial", "hdfc": "Banking/Financial",
    "pnb": "Banking/Financial", "bankof": "Banking/Financial", "bob": "Banking/Financial",
    "canara": "Banking/Financial", "axis": "Banking/Financial", "kotak": "Banking/Financial",
    "yesbank": "Banking/Financial", "unionbank": "Banking/Financial", "idbi": "Banking/Financial",
    "indus": "Banking/Financial", "sbicard": "Banking/Financial", "card": "Banking/Financial",
    "pay": "Banking/Financial",
    "life": "Insurance", "lombard": "Insurance", "prulife": "Insurance",
    "ergo": "Insurance", "insurance": "Insurance", "lic": "Insurance",
    "gov": "Government", "nic": "Government", "mgovcloud": "Government",
    "crsorgi": "Government", "kavach": "Government",
    "irctc": "Transport", "rail": "Transport", "railway": "Transport",
    "airtel": "Telecom", "vodafone": "Telecom", "reliance": "Telecom",
    "iocl": "Oil & Gas", "hpcl": "Oil & Gas", "bpcl": "Oil & Gas",
    "ongc": "Oil & Gas", "oil": "Oil & Gas", "petrol": "Oil & Gas",
    "accounts": "Services", "email": "Services",
    "facebook": "Social Media", "fb": "Social Media",
    "instagram": "Social Media", "insta": "Social Media",
    "twitter": "Social Media", "x": "Social Media",
    "linkedin": "Social Media", "lnkd": "Social Media",
    "reddit": "Social Media", "rdt": "Social Media",
    "youtube": "Social Media", "yt": "Social Media",
    "tiktok": "Social Media", "tk": "Social Media",
    "telegram": "Social Media", "whatsapp": "Social Media"
}

HIGH_PRIORITY_TOKENS = {"irctc", "nic", "iocl", "sbi", "icici", "hdfc", "airtel"}

# Brand visual palettes (extendable)
# NOTE: This is no longer used by reclassify_label but kept for future reference
BRAND_COLORS = {
    "sbi": [(10, 60, 105)],    # SBI blue
    "airtel": [(228, 0, 43)], # Airtel red
    "irctc": [(0, 85, 150)],  # IRCTC blue
    "nic": [(0, 51, 153)],    # NIC blue
    "iocl": [(255, 102, 0)],  # IOC orange
}

BRAND_KEYWORDS = {"sbi", "airtel", "irctc", "nic", "iocl", "baroda"}

TRUSTED_REGISTRARS = {"godaddy", "gmo internet", "markmonitor", "verisign"}
SUSPICIOUS_REGISTRARS = {
    "namecheap", "freenom", "dynadot", "pdr ltd",
    "hostinger", "internet domain service bs corp", "regru", "west263", "enom", "tucows",
    "nicenic", "shinjiru", "orange website", "flokinet", "njalla"
}

TRUSTED_HOSTS = {"amazon", "akamai", "cloudflare", "microsoft", "google"}
SUSPICIOUS_HOSTS = {
    "hostinger", "ovh", "contabo", "digitalocean",
    "colocrossing", "frantech", "hetzner", "linode", "vultr",
    "namesilo", "public domain registry"
}

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def normalize_text(s):
    if s is None:
        return ""
    return re.sub(r"[^a-z0-9]", " ", str(s).lower()).strip()

def domain_tokens_from_url(url):
    try:
        ext = tldextract.extract(url)
        tokens = []
        if ext.subdomain: tokens += [p for p in ext.subdomain.split(".") if p]
        if ext.domain: tokens.append(ext.domain)
        if ext.suffix: tokens.append(ext.suffix.replace(".", ""))
        return [t.lower() for t in tokens if t]
    except Exception:
        return [t for t in re.split(r"[\W_]+", str(url).lower()) if t]

def adjust_source(org_name, whitelisted_domain, ml_source="Unknown"):
    org_norm = normalize_text(org_name)
    dom_tokens = domain_tokens_from_url(whitelisted_domain)
    for tok in HIGH_PRIORITY_TOKENS:
        if tok in org_norm or tok in dom_tokens:
            return SOURCE_MAPPING.get(tok, ml_source)
    for tok in dom_tokens:
        if tok in SOURCE_MAPPING:
            return SOURCE_MAPPING[tok]
    for key, mapped in SOURCE_MAPPING.items():
        if key in org_norm or key in whitelisted_domain.lower():
            return mapped
    return ml_source

# ------------------------------------------------------------------
# Checkpoint helper — survives Kaggle kills
# ------------------------------------------------------------------
def _append_record_to_checkpoint(record: dict, checkpoint_path: str):
    """Append a single record as one CSV row. Write header if file is new."""
    import csv as _csv
    file_exists = os.path.exists(checkpoint_path) and os.path.getsize(checkpoint_path) > 0
    with open(checkpoint_path, mode="a", newline="", encoding="utf-8") as f:
        writer = _csv.DictWriter(f, fieldnames=record.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)

# ------------------------------------------------------------------
# Feature extraction (Chunked Processing for GPU Safety)
# ------------------------------------------------------------------
# CHUNK_SIZE is imported from .utils (calculated dynamically)

async def process_urls(input_csv, output_csv=FEATURES_CSV, network_semaphore=None,
                       phase2_queue=None, screenshot_pbar=None, ocr_pbar=None):
    """
    Three-Stage Producer-Consumer Feature Extraction Pipeline.

    Stage 1 — Screenshot Workers  (parallelism = MAX_CONCURRENT_SCREENSHOTS)
        - Runs network features + browser screenshot in parallel
        - Pushes (net_feats, screenshot_path, row_meta) into Queue-1

    Stage 2 — OCR Workers         (parallelism = MAX_CONCURRENT_OCR, VRAM-gated)
        - Pulls from Queue-1, runs OCR/branding/laplacian
        - Pushes merged feature dict into phase2_queue (Queue-2)

    Progress bars (screenshot_pbar, ocr_pbar) are managed by the caller
    (run_pipeline) and shared across this function.
    """
    import csv
    import gc
    import torch
    from .utils import (
        _safe_extract_ocr, _safe_extract_branding, _safe_extract_laplacian,
    )
    from .visual_features import get_favicon_features_async

    df = pd.read_csv(input_csv)
    total_domains = len(df)
    logger.info(
        "⚙️  Starting 3-Stage Pipeline for %d domains "
        "(Stage1=%d, OCR=%d, Phase2=%d)...",
        total_domains, MAX_CONCURRENT_SCREENSHOTS, MAX_CONCURRENT_OCR, MAX_CONCURRENT_RDAP
    )

    if df.empty:
        with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
            pass
        return

    if network_semaphore is None:
        network_semaphore = asyncio.Semaphore(NETWORK_SEMAPHORE_LIMIT)

    rows = df.to_dict('records')
    all_results = []
    results_lock = asyncio.Lock()  # Protects concurrent appends to all_results

    # -----------------------------------------------------------------------
    # Shared queue between Stage 1 and Stage 2.
    # max size = OCR_workers * 2  so Stage 1 doesn't race far ahead and eat RAM.
    # -----------------------------------------------------------------------
    OCR_QUEUE_DEPTH = max(MAX_CONCURRENT_OCR * 4, MAX_CONCURRENT_SCREENSHOTS)
    queue: asyncio.Queue = asyncio.Queue(maxsize=OCR_QUEUE_DEPTH)
    DONE_SENTINEL = None  # Tells OCR workers to stop

    screenshot_sem = _get_screenshot_semaphore()

    # -----------------------------------------------------------------------
    # Stage 1 Worker — one per domain (gated by screenshot_sem)
    # -----------------------------------------------------------------------
    async def stage1_worker(row, pbar):
        """Network features + screenshot, then enqueue for Stage 2."""
        domain = row.get("Identified Phishing/Suspected Domain Name", "")

        # --- Network features (fast, CPU-bound, async I/O) ---
        try:
            net_feats = await extract_network_features_async(domain, network_semaphore)
        except Exception as e:
            logger.error("[Stage1] Network failed for %s: %s", domain, e)
            net_feats = {}

        # --- Screenshot (gated by screenshot_sem) ---
        ext = tldextract.extract(domain)
        domain_full = ".".join(p for p in [ext.domain, ext.suffix] if p) or domain
        screenshot_path = os.path.join(SCREENS_DIR, f"{domain_full}.png")

        from .visual_features import capture_screenshot_async
        async with screenshot_sem:
            try:
                target_url, capture_ok = await capture_screenshot_async(domain, screenshot_path)
            except Exception as e:
                logger.error("[Stage1] Screenshot failed for %s: %s", domain, e)
                target_url, capture_ok = domain, False

        if not capture_ok:
            # Write a placeholder so Stage 2 still has a file to process
            await asyncio.to_thread(_create_dummy_image, domain, screenshot_path)
            target_url = domain

        row_meta = {
            "Cooresponding CSE": row.get("Cooresponding CSE", ""),
            "Legitimate Domains": row.get("Legitimate Domains", ""),
        }

        # Put into OCR queue (will block if queue is full — natural backpressure)
        await queue.put((net_feats, screenshot_path, target_url, row_meta))
        if screenshot_pbar:
            screenshot_pbar.update(1)

    # -----------------------------------------------------------------------
    # Stage 2 Worker — OCR-gated consumer (MAX_CONCURRENT_OCR instances)
    # -----------------------------------------------------------------------
    async def stage2_worker(queue2):
        """OCR + branding + laplacian, one domain at a time per worker.
        
        Pushes the fully-merged feature dict into queue2 so Phase 2
        (WHOIS/RDAP/DNS/classify) can stream it immediately.
        """
        from .utils import (
            _safe_preprocess_image, _safe_run_ocr,
            _safe_extract_branding, _safe_extract_laplacian,
            extract_tvc_features,
        )
        from .visual_features import extract_spatial_ocr_features
        loop = asyncio.get_running_loop()
        while True:
            item = await queue.get()
            if item is DONE_SENTINEL:
                queue.task_done()
                break

            net_feats, screenshot_path, target_url, row_meta = item
            try:
                # ── Phase A: CPU preprocess + branding + laplacian in PARALLEL ──
                img_np, branding_feats, lap_var = await asyncio.gather(
                    loop.run_in_executor(None, _safe_preprocess_image, screenshot_path),
                    loop.run_in_executor(None, _safe_extract_branding, screenshot_path),
                    loop.run_in_executor(None, _safe_extract_laplacian, screenshot_path),
                )

                # ── Phase B: GPU inference ──────────────────────────────────
                await wait_for_vram(min_free_gb=1.5)
                ocr_text, ocr_raw = await loop.run_in_executor(None, _safe_run_ocr, img_np)

                # ── Phase B+: Spatial OCR zones + TVC (CPU-only, ~7ms) ────────
                spatial_feats = extract_spatial_ocr_features(img_np, ocr_raw)
                tvc_feats = extract_tvc_features(
                    target_url,
                    spatial_feats.get("ocr_header_text", ""),
                    spatial_feats.get("ocr_footer_text", ""),
                )

                # ── Favicon (async network, runs after GPU is free) ──────────
                try:
                    fav_feats = await get_favicon_features_async(target_url)
                    if fav_feats:
                        fav_feats.pop("favicon_path", None)
                    else:
                        fav_feats = {}
                except Exception:
                    fav_feats = {}

                merged = {
                    **row_meta,
                    **net_feats,
                    "url": target_url,
                    "ocr_text": ocr_text or "",
                    **spatial_feats,
                    **tvc_feats,
                    "laplacian_variance": lap_var,
                    **(branding_feats or {}),
                    **fav_feats,
                }

                # Push into Phase 2 queue for immediate WHOIS/RDAP processing
                await queue2.put(merged)
                if ocr_pbar:
                    ocr_pbar.update(1)

            except Exception as e:
                logger.error("[Stage2] Unexpected error for %s: %s", target_url, e)
            finally:
                queue.task_done()
                try:
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                    gc.collect()
                except Exception:
                    pass

    # -----------------------------------------------------------------------
    # Orchestrate: launch all 3 stages concurrently
    #   Stage 1  → queue  → Stage 2 (OCR)  → phase2_queue  → Phase 2 (WHOIS/RDAP)
    # phase2_queue is passed in by run_pipeline, which also manages Phase 2 workers.
    # Progress bars are passed in from run_pipeline.
    # -----------------------------------------------------------------------
    # Launch Stage 2 OCR workers first (they wait on queue; push into phase2_queue)
    stage2_tasks = [
        asyncio.create_task(stage2_worker(phase2_queue))
        for _ in range(MAX_CONCURRENT_OCR)
    ]

    # Launch Stage 1: all domains (backpressure from bounded OCR queue)
    stage1_coros = [stage1_worker(row, None) for row in rows]  # pbar=None, using screenshot_pbar directly
    await asyncio.gather(*stage1_coros, return_exceptions=True)

    # Signal Stage 2 (OCR) workers to stop
    for _ in range(MAX_CONCURRENT_OCR):
        await queue.put(DONE_SENTINEL)

    logger.info("⏳ Screenshots done. Waiting for %d OCR workers to flush → Phase 2...", MAX_CONCURRENT_OCR)
    await asyncio.gather(*stage2_tasks, return_exceptions=True)

    # Final GPU cleanup after all OCR is done
    try:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()
        logger.debug("🧹 Final GPU cleanup complete")
    except Exception:
        pass

    logger.info("✅ Phase 1 complete: %d domains through OCR. Phase 2 may still be running.", total_domains)

# ------------------------------------------------------------------
# Visual feature extraction (REMOVED)
# ---
# --- All visual feature extraction (pytesseract) is removed from here.
# --- It is now 100% handled by visual_features.py (EasyOCR)
# --- and utils.py, which saves features to the CSV.
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# Evidence handling
# ------------------------------------------------------------------
def format_evidence_filename(org_name: str, domain: str, serial_no: int, application_id: str = APPLICATION_ID):
    import re, tldextract
    org_tag = re.findall(r"\((.*?)\)", org_name)
    org_tag = org_tag[0] if org_tag else org_name.split()[0]
    ext = tldextract.extract(domain)
    two_level = ".".join(part for part in [ext.domain, ext.suffix] if part)
    filename = f"{org_tag}_{two_level}_{serial_no}.pdf"
    folder = EVIDENCE_DIR
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename), os.path.join(os.path.basename(folder), filename)

def move_screenshot_to_evidence(domain_url, pdf_path):
    try:
        ext = tldextract.extract(domain_url)
        # --- FIX: Re-create the domain part correctly ---
        domain_part = ext.domain or ""
        suffix_part = ext.suffix or ""
        if not domain_part: # Handle cases like 'http://1.2.3.4'
             domain_full = domain_url.replace("https://","").replace("http://","").split("/")[0]
        else:
            domain_full = ".".join(part for part in [domain_part, suffix_part] if part)
        
        screenshot_path = os.path.join(SCREENS_DIR, f"{domain_full}.png")
        if not os.path.exists(screenshot_path):
            logger.warning("⚠️ Screenshot file not found: %s", screenshot_path)
            return False
        
        pdf = FPDF()
        pdf.add_page()
        
        # Add image, handling different sizes
        try:
            with Image.open(screenshot_path) as img:
                w, h = img.width, img.height
                # A4 page is 210mm wide, 190mm usable (10mm margin)
                img_w = 190
                img_h = (h * img_w) / w # Calculate proportional height
                pdf.image(screenshot_path, x=10, y=10, w=img_w, h=img_h)
        except Exception as img_e:
            logger.error("Error processing image for PDF: %s", img_e)
            pdf.set_font("Arial", "B", 12)
            pdf.text(10, 10, "Error: Could not embed screenshot.")

        pdf.output(pdf_path, "F")
        return True
    except Exception as e:
        logger.error("❌ Failed to move screenshot to evidence PDF: %s", e)
        return False

# ------------------------------------------------------------------
# Classification (infra + visual)
# ------------------------------------------------------------------
def reclassify_label(domain, registrar, host, dns, ocr_text_from_csv, tvc_brand_spoofed=False):
    """
    Re-classifies the label using heuristics.
    NOTE: This function NO LONGER uses pytesseract. It uses the
    'ocr_text_from_csv' which was generated by EasyOCR.

    NEW: tvc_brand_spoofed — if True, the page visually claims to be a known
    brand but the domain doesn't match. This is a strong phishing signal.
    """
    reg = str(registrar).lower()
    hst = str(host).lower()
    dns_str = str(dns).lower()
    dom = str(domain).lower()
    ocr_text = str(ocr_text_from_csv).lower() # Use the text from the CSV
    
    ssl_present = "ssl" in dns_str or "tls" in dns_str

    # ── TVC override: brand visually spoofed ──
    if tvc_brand_spoofed:
        if any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in hst for h in SUSPICIOUS_HOSTS):
            return "Phishing"
        # Brand spoofed but registrar unknown → still highly suspicious
        return "Suspected"
    
    # Check if domain or OCR text contains a brand keyword
    brand_hit_domain = any(b in dom for b in BRAND_KEYWORDS)
    brand_hit_ocr = any(b in ocr_text for b in BRAND_KEYWORDS)
    brand_hit = brand_hit_domain or brand_hit_ocr

    if brand_hit:
        if any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in hst for h in SUSPICIOUS_HOSTS):
            return "Phishing"
        if (any(r in reg for r in TRUSTED_REGISTRARS) or any(h in hst for h in TRUSTED_HOSTS)) and ssl_present:
            return "Legitimate"
        # If a brand is hit (e.g., "sbi" in URL) but infra is not clearly trusted,
        # it's safer to call it suspected.
        return "Suspected"
        
    if any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in hst for h in SUSPICIOUS_HOSTS):
        return "Suspected"
        
    # --- CRITICAL FIX: Fail-Safe Classification ---
    # If the scraped data is "na" (WHOIS/DNS failed), we strictly CANNOT trust it.
    # Defaulting to "Legitimate" logic requires POSITIVE confirmation of a trusted entity.
    # If data is missing, we must default to "Suspected" or higher.
    if reg == "na" and hst == "na":
        return "Suspected"

    # Default to Legitimate ONLY if valid data exists and no red flags found
    return "Legitimate"


# Override the legacy helper above with the current precision-first policy.
def reclassify_label(domain, registrar, host, dns, ocr_text_from_csv, tvc_brand_spoofed=False):
    """
    Precision-first reclassification used by the current pipeline.
    TVC spoofing is suspicious supporting evidence, not a direct phishing
    override. Final phishing escalation is handled by the Stage 3 hybrid gate.
    """
    reg = str(registrar or "").lower()
    hst = str(host or "").lower()
    dns_str = str(dns or "").lower()
    dom = str(domain or "").lower()
    ocr_text = str(ocr_text_from_csv or "").lower()

    ssl_present = "ssl" in dns_str or "tls" in dns_str

    if tvc_brand_spoofed:
        return "Suspected"

    brand_hit_domain = any(b in dom for b in BRAND_KEYWORDS)
    brand_hit_ocr = any(b in ocr_text for b in BRAND_KEYWORDS)
    brand_hit = brand_hit_domain or brand_hit_ocr

    if brand_hit:
        if (any(r in reg for r in TRUSTED_REGISTRARS) or any(h in hst for h in TRUSTED_HOSTS)) and ssl_present:
            return "Legitimate"
        return "Suspected"

    if any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in hst for h in SUSPICIOUS_HOSTS):
        return "Suspected"

    if reg == "na" and hst == "na":
        return "Suspected"

    return "Legitimate"


def _detect_stored_parked_page(row: dict) -> dict:
    domain_url = _normalize_replayed_text(row.get("Identified Phishing/Suspected Domain Name", ""))
    final_landing_url = _normalize_replayed_text(row.get("final_landing_url", ""))
    stored_provider = _normalize_replayed_text(row.get("parking_provider", ""))
    stored_reason = _normalize_replayed_text(row.get("parking_reason", ""))
    placeholder_reason = _normalize_replayed_text(row.get("placeholder_or_parking_reason", ""))
    effective_reason = stored_reason or placeholder_reason
    if stored_provider or effective_reason:
        return {
            "is_parked": True,
            "parking_provider": stored_provider or "GenericParking",
            "parking_reason": effective_reason or "stored_parking_signal",
            "final_landing_url": final_landing_url or domain_url,
            "matched_signals": [],
        }
    return detect_parked_page_signals(
        original_url=domain_url,
        final_landing_url=final_landing_url,
        title_text=str(row.get("html_title_text", "") or ""),
        visible_text=str(row.get("visible_text_excerpt", "") or ""),
    )


def _submission_record_columns() -> list[str]:
    return [
        "Application_ID",
        "Source of detection",
        "Identified Phishing/Suspected Domain Name",
        "Corresponding CSE Domain Name",
        "Critical Sector Entity Name",
        "Phishing/Suspected Domains (i.e. Class Label)",
        "Domain Registration Date",
        "Registrar Name",
        "Registrant Name or Registrant Organisation",
        "Registrant Country",
        "Name Servers",
        "Hosting IP",
        "Hosting ISP",
        "Hosting Country",
        "DNS Records (if any)",
        "Evidence file name",
        "Date of detection (DD-MM-YYYY)",
        "Time of detection (HH-MM-SS)",
        "Date of Post (If detection is from Source: social media)",
        "Remarks",
    ]


def _confidence_band_from_score(score, high_confidence_threshold, medium_confidence_threshold):
    try:
        score_value = float(score)
    except (TypeError, ValueError):
        score_value = 0.0
    if score_value >= high_confidence_threshold:
        return "High"
    if score_value >= medium_confidence_threshold:
        return "Medium"
    return "Low"


def _normalize_confidence_band(raw_band, score, high_confidence_threshold, medium_confidence_threshold):
    band_text = str(raw_band or "").strip().lower()
    if band_text == "high":
        return "High"
    if band_text == "medium":
        return "Medium"
    if band_text == "low":
        return "Low"
    return _confidence_band_from_score(score, high_confidence_threshold, medium_confidence_threshold)


def _normalize_evidence_tier(row: dict) -> str:
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        text = str(value or "").strip().lower()
        return text in {"1", "true", "yes", "y"}

    raw = str(row.get("evidence_tier", "") or "").strip().lower()
    if raw in {"strong", "strong_evidence"}:
        return "strong_evidence"
    if raw in {"weak", "weak_evidence"}:
        return "weak_evidence"

    lexical_hit = _as_bool(row.get("lexical_rule_hit")) or _as_bool(row.get("typo_anchor"))
    hash_hit = _as_bool(row.get("hash_anchor"))
    visual_hit = _as_bool(row.get("clip_anchor"))
    if lexical_hit and (hash_hit or visual_hit):
        return "strong_evidence"
    return "weak_evidence"


def _is_suspicious_infra(registrar, hosting_isp):
    reg = str(registrar or "").lower()
    isp = str(hosting_isp or "").lower()
    return any(r in reg for r in SUSPICIOUS_REGISTRARS) or any(h in isp for h in SUSPICIOUS_HOSTS)


def _is_trusted_infra(registrar, hosting_isp):
    reg = str(registrar or "").lower()
    isp = str(hosting_isp or "").lower()
    return any(r in reg for r in TRUSTED_REGISTRARS) or any(h in isp for h in TRUSTED_HOSTS)


def _as_bool_flag(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


_REPLAY_EMPTY_TEXT_VALUES = {"", "nan", "none", "null", "na"}


def _normalize_replayed_text(value) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    text = str(value).strip()
    if text.lower() in _REPLAY_EMPTY_TEXT_VALUES:
        return ""
    return text


def _normalize_replayed_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    for column in columns:
        if column in df.columns:
            df[column] = df[column].map(_normalize_replayed_text)
    return df


_REVIEW_QUEUE_KEY_COLUMNS = [
    "Identified Phishing/Suspected Domain Name",
    "Cooresponding CSE",
    "Legitimate Domains",
]


def _read_existing_review_queue(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


def _merge_review_queue_frames(*frames: pd.DataFrame) -> pd.DataFrame:
    usable_frames = [frame.copy() for frame in frames if isinstance(frame, pd.DataFrame) and not frame.empty]
    if not usable_frames:
        return pd.DataFrame()
    merged = pd.concat(usable_frames, ignore_index=True, sort=False)
    if "review_reason" not in merged.columns:
        merged["review_reason"] = ""
    dedupe_columns = [column for column in _REVIEW_QUEUE_KEY_COLUMNS if column in merged.columns]
    if dedupe_columns:
        merged = merged.drop_duplicates(subset=dedupe_columns, keep="last")
    return merged


def _write_hash_review_queue(review_df: pd.DataFrame) -> pd.DataFrame:
    os.makedirs(os.path.dirname(HASH_REVIEW_QUEUE_PATH), exist_ok=True)
    output_df = review_df.copy() if isinstance(review_df, pd.DataFrame) else pd.DataFrame()
    output_df.to_csv(HASH_REVIEW_QUEUE_PATH, index=False, encoding="utf-8")
    logger.info("Hash review queue written to %s (%d rows)", HASH_REVIEW_QUEUE_PATH, len(output_df))
    return output_df


def _safe_predict_top1(model, x_sc, classes) -> tuple[str, float]:
    if model is None or x_sc is None:
        return "NA", 0.0
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(x_sc)[0]
            idx = int(np.argmax(probs))
            labels = list(classes)
            return str(labels[idx]), float(probs[idx])
        pred = model.predict(x_sc)[0]
        labels = list(classes)
        if isinstance(pred, (int, np.integer)) and 0 <= int(pred) < len(labels):
            return str(labels[int(pred)]), 1.0
        return str(pred), 1.0
    except Exception:
        return "NA", 0.0


def _coerce_numeric_feature(value, default=0.0) -> float:
    if value is None:
        return float(default)
    if isinstance(value, bool):
        return float(int(value))
    try:
        if pd.isna(value):
            return float(default)
    except Exception:
        pass
    try:
        return float(value)
    except Exception:
        return float(default)


def _build_hash_only_model_frame(row: dict, network_feats: dict, geo_dict: dict, imputer) -> pd.DataFrame:
    feature_names = list(getattr(imputer, "feature_names_in_", []))
    if not feature_names:
        raise ValueError("imputer is missing feature_names_in_")

    model_row = {name: 0.0 for name in feature_names}
    source_values = {}
    if isinstance(network_feats, dict):
        source_values.update(network_feats)

    source_values["favicon_detected"] = int(
        _as_bool_flag(source_values.get("favicon_detected"))
        or _as_bool_flag(row.get("signal_hit_favicon"))
    )
    if isinstance(geo_dict, dict):
        asn_value = geo_dict.get("asn")
        if asn_value not in (None, "", "NA"):
            source_values["asn"] = asn_value

    for feature_name in feature_names:
        if feature_name.startswith("ssl_issuer_"):
            continue
        model_row[feature_name] = _coerce_numeric_feature(source_values.get(feature_name), default=0.0)

    ssl_issuer = str(source_values.get("ssl_issuer") or "").strip()
    issuer_column = f"ssl_issuer_{ssl_issuer}"
    if issuer_column in model_row:
        model_row[issuer_column] = 1.0

    return pd.DataFrame([model_row], columns=feature_names)


def _write_debug_csv(records: list[dict], output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df_debug = pd.DataFrame(records)
    df_debug.to_csv(output_path, index=False, encoding="utf-8")


async def _extract_hash_only_ocr_tvc(
    domain_url: str,
    screenshot_path: str,
    shortlisted_cse: str = "",
    shortlisted_domain: str = "",
    html_text: str = "",
) -> dict:
    if not screenshot_path or not os.path.exists(screenshot_path):
        return {
            "ocr_text": "",
            "ocr_header_text": "",
            "ocr_footer_text": "",
            "tvc_brand_detected": False,
            "tvc_detected_brand": "none",
            "tvc_domain_match": False,
            "tvc_fuzzy_score": 0.0,
            "tvc_brand_spoofed": False,
            "tvc_match_surface": "none",
            "tvc_matched_alias": "",
            "tvc_spoof_strong": False,
        }

    from .utils import _safe_preprocess_image, _safe_run_ocr, extract_tvc_features
    from .visual_features import extract_spatial_ocr_features

    loop = asyncio.get_running_loop()
    ocr_sem = _get_ocr_semaphore()
    async with ocr_sem:
        try:
            img_np = await loop.run_in_executor(None, _safe_preprocess_image, screenshot_path)
            if img_np is None:
                raise ValueError("image preprocessing returned None")
            await wait_for_vram(min_free_gb=1.5)
            ocr_text, ocr_raw = await loop.run_in_executor(None, _safe_run_ocr, img_np)
            spatial_feats = extract_spatial_ocr_features(img_np, ocr_raw)
            tvc_feats = extract_tvc_features(
                domain_url,
                spatial_feats.get("ocr_header_text", ""),
                spatial_feats.get("ocr_footer_text", ""),
                ocr_text or "",
                html_text or "",
                shortlisted_cse,
                shortlisted_domain,
            )
            return {
                "ocr_text": ocr_text or "",
                "ocr_header_text": spatial_feats.get("ocr_header_text", ""),
                "ocr_footer_text": spatial_feats.get("ocr_footer_text", ""),
                **tvc_feats,
            }
        except Exception as exc:
            logger.warning("Second-pass OCR/TVC failed for %s: %s", domain_url, exc)
            return {
                "ocr_text": "",
                "ocr_header_text": "",
                "ocr_footer_text": "",
                "tvc_brand_detected": False,
                "tvc_detected_brand": "none",
                "tvc_domain_match": False,
                "tvc_fuzzy_score": 0.0,
                "tvc_brand_spoofed": False,
                "tvc_match_surface": "none",
                "tvc_matched_alias": "",
                "tvc_spoof_strong": False,
            }


def _hybrid_hash_decision(
    row: dict,
    registrar,
    hosting_isp,
    dns_records,
    ocr_text_from_csv="",
    tvc_brand_spoofed=False,
    tvc_brand_spoof_strong=False,
    brand_model_agrees: bool = False,
    domain_model_agrees: bool = False,
    brand_model_confidence: float = 0.0,
    domain_model_confidence: float = 0.0,
    failed_fetch_suspected_min: float | None = None,
    failed_fetch_review_min: float | None = None,
):
    lexical_rule_hit = _as_bool_flag(row.get("lexical_rule_hit"))
    brand_token_hit = _as_bool_flag(row.get("brand_token_hit"))
    old_fuzzy_hit = _as_bool_flag(row.get("old_fuzzy_hit"))
    hybrid_lexical_hit = _as_bool_flag(row.get("hybrid_lexical_hit"))
    strict_lexical_hit = _as_bool_flag(row.get("strict_lexical_hit")) or lexical_rule_hit or brand_token_hit or old_fuzzy_hit or hybrid_lexical_hit
    lexical_score_pass = _as_bool_flag(row.get("lexical_score_pass"))
    fallback_rank_only = _as_bool_flag(row.get("fallback_rank_only"))
    stage1_passthrough = _as_bool_flag(row.get("stage1_passthrough")) or "stage1_suspected_passthrough" in str(row.get("admission_path", "") or "")
    fetch_status = str(row.get("fetch_status", "fetched") or "fetched").strip().lower()
    fetched = fetch_status in {"fetched", "fetched_visual_missing"}
    parking_reason = _normalize_replayed_text(
        row.get("placeholder_or_parking_reason")
        or row.get("parking_reason")
        or ""
    )

    decision = {
        "classification": "Legitimate",
        "emit_output": False,
        "classification_gate_reason": "",
        "review_only_reason": "",
        "non_lexical_corroboration_count": 0,
    }

    if parking_reason:
        decision["classification"] = "SKIPPED_PARKING_OR_PLACEHOLDER"
        decision["classification_gate_reason"] = "parking_or_placeholder_excluded"
        decision["review_only_reason"] = parking_reason
        return decision

    if fallback_rank_only and not strict_lexical_hit and not stage1_passthrough:
        decision["classification_gate_reason"] = "fallback_rank_only_without_strict_lexical"
        return decision

    lexical_survivor = bool(strict_lexical_hit or lexical_score_pass or stage1_passthrough)
    if not lexical_survivor:
        decision["classification_gate_reason"] = "no_lexical_gate"
        return decision

    if not fetched:
        lexical_score = _coerce_numeric_feature(row.get("lexical_score"), default=0.0)
        if strict_lexical_hit and not fallback_rank_only:
            if failed_fetch_suspected_min is not None and lexical_score >= float(failed_fetch_suspected_min):
                decision["classification"] = "Suspected"
                decision["emit_output"] = True
                decision["classification_gate_reason"] = "failed_fetch_strict_lexical_rescue"
                return decision
            if failed_fetch_review_min is not None and lexical_score >= float(failed_fetch_review_min):
                decision["classification"] = "REVIEW_ONLY"
                decision["classification_gate_reason"] = "failed_fetch_strict_lexical_review"
                decision["review_only_reason"] = "failed_fetch_strict_lexical_review"
                return decision
        decision["classification_gate_reason"] = "invalid_fetch_state_without_direct_evidence"
        return decision

    hash_anchor = _as_bool_flag(row.get("hash_anchor"))
    clip_anchor = _as_bool_flag(row.get("clip_anchor"))
    clip_corroborated = bool(_as_bool_flag(row.get("clip_corroborated")) and clip_anchor)
    keyword_hit = _as_bool_flag(row.get("signal_hit_keywords"))
    try:
        direct_brand_evidence_count = int(row.get("direct_brand_evidence_count", 0) or 0)
    except (TypeError, ValueError):
        direct_brand_evidence_count = 0
    tvc_spoof_strong = bool(_as_bool_flag(row.get("tvc_brand_spoof_strong")) or tvc_brand_spoof_strong)
    weak_tvc_spoof = bool(tvc_brand_spoofed) and not tvc_spoof_strong
    strong_direct_evidence = bool(hash_anchor or tvc_spoof_strong or clip_corroborated)
    weak_direct_evidence = bool(
        strong_direct_evidence
        or weak_tvc_spoof
        or direct_brand_evidence_count > 0
        or keyword_hit
    )
    non_lexical_corroborators = [
        hash_anchor,
        clip_corroborated,
        tvc_spoof_strong,
        weak_tvc_spoof,
        direct_brand_evidence_count > 0,
        keyword_hit,
    ]
    non_lexical_corroboration_count = sum(1 for flag in non_lexical_corroborators if flag)
    decision["non_lexical_corroboration_count"] = non_lexical_corroboration_count

    if strict_lexical_hit and strong_direct_evidence:
        decision["classification"] = "Phishing"
        decision["emit_output"] = True
        decision["classification_gate_reason"] = "strict_lexical_plus_direct_evidence"
        return decision

    if lexical_survivor and weak_direct_evidence:
        decision["classification"] = "Suspected"
        decision["emit_output"] = True
        decision["classification_gate_reason"] = "lexical_gate_plus_weak_direct_evidence"
        return decision

    decision["classification"] = "Legitimate"
    decision["emit_output"] = True
    decision["classification_gate_reason"] = "lexical_without_direct_evidence"
    return decision


def _hybrid_hash_classification(
    row: dict,
    registrar,
    hosting_isp,
    dns_records,
    ocr_text_from_csv="",
    tvc_brand_spoofed=False,
    tvc_brand_spoof_strong=False,
    brand_model_agrees: bool = False,
    domain_model_agrees: bool = False,
    brand_model_confidence: float = 0.0,
    domain_model_confidence: float = 0.0,
):
    decision = _hybrid_hash_decision(
        row,
        registrar=registrar,
        hosting_isp=hosting_isp,
        dns_records=dns_records,
        ocr_text_from_csv=ocr_text_from_csv,
        tvc_brand_spoofed=tvc_brand_spoofed,
        tvc_brand_spoof_strong=tvc_brand_spoof_strong,
        brand_model_agrees=brand_model_agrees,
        domain_model_agrees=domain_model_agrees,
        brand_model_confidence=brand_model_confidence,
        domain_model_confidence=domain_model_confidence,
    )
    classification = str(decision.get("classification", "Legitimate"))
    if classification in {"REVIEW_ONLY", "SKIPPED_PARKING_OR_PLACEHOLDER"}:
        return "Legitimate"
    return classification


async def _run_hash_only_pipeline(
    df_filtered: pd.DataFrame,
    whois_rate_limiter: RateLimiter,
    high_confidence_threshold: float,
    medium_confidence_threshold: float,
    failed_fetch_suspected_min: float | None = None,
    failed_fetch_review_min: float | None = None,
    run_context: RunContext | None = None,
    checkpoint_store: CheckpointStore | None = None,
    resume: bool = False,
    force_reprocess: bool = False,
):
    df_filtered = df_filtered.copy()
    df_filtered = _normalize_replayed_columns(
        df_filtered,
        ["parking_provider", "parking_reason", "placeholder_or_parking_reason", "final_landing_url"],
    )
    filtered_output_path = FINAL_OUTPUT.replace(".csv", "_filtered.csv")
    existing_review_df = _read_existing_review_queue(HASH_REVIEW_QUEUE_PATH)
    eligible_fetch_statuses = {"fetched", "fetched_visual_missing"}
    logger.info("Hash-only input after whitelist filtering: %d shortlisted rows", len(df_filtered))
    if "hash_score" not in df_filtered.columns:
        df_filtered["hash_score"] = 0.0
    df_filtered["hash_score"] = pd.to_numeric(df_filtered["hash_score"], errors="coerce").fillna(0.0)
    if "confidence_band" in df_filtered.columns:
        confidence_series = df_filtered["confidence_band"]
    else:
        confidence_series = pd.Series([""] * len(df_filtered), index=df_filtered.index)
    df_filtered["confidence_band"] = [
        _normalize_confidence_band(raw_band, score, high_confidence_threshold, medium_confidence_threshold)
        for raw_band, score in zip(confidence_series, df_filtered["hash_score"])
    ]
    df_filtered["evidence_tier"] = [
        _normalize_evidence_tier(row)
        for row in df_filtered.to_dict("records")
    ]
    df_filtered["review_reason"] = [
        "fetch_failed_lexical_hit"
        if str(row.get("fetch_status", "")).strip().lower() in {"failed", "timeout"} and _as_bool_flag(row.get("strict_lexical_hit"))
        else "low_confidence_hash_bypass"
        if _as_bool_flag(row.get("hash_anchor"))
        else "low_confidence_clip_anchor"
        if _as_bool_flag(row.get("clip_anchor"))
        else "low_confidence_strict_lexical"
        if _as_bool_flag(row.get("strict_lexical_hit"))
        else "low_confidence_lexical_score_pass"
        if _as_bool_flag(row.get("lexical_score_pass"))
        else "low_confidence_admitted"
        for row in df_filtered.to_dict("records")
    ]

    low_conf_df = df_filtered[df_filtered["confidence_band"] == "Low"].copy()

    classified_df = df_filtered.copy()
    completed_record_keys = (
        checkpoint_store.get_completed_record_keys()
        if checkpoint_store is not None and resume and not force_reprocess
        else set()
    )
    if checkpoint_store is not None and run_context is not None:
        pending_rows = []
        skipped_existing = 0
        for row in classified_df.to_dict("records"):
            domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
            normalized_url = domain_url.strip().lower()
            source_workbook = str(row.get("source_workbook", "") or "")
            checkpoint_store.ensure_url_result(
                raw_url=domain_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
            )
            if make_record_key(normalized_url, source_workbook) in completed_record_keys:
                skipped_existing += 1
                continue
            pending_rows.append(row)
        if skipped_existing:
            logger.info("Hash-only resume | skipped %d already-completed shortlisted rows", skipped_existing)
        classified_df = pd.DataFrame(pending_rows)
    non_fetched_count = int(
        (~classified_df.get(
            "fetch_status",
            pd.Series(["fetched"] * len(classified_df), index=classified_df.index),
        ).astype(str).str.strip().str.lower().isin(eligible_fetch_statuses)).sum()
    )
    total_domains = len(classified_df)
    logger.info(
        "Hash-only mode will classify %d shortlisted rows (%d non-fetched candidates included for possible rescue)",
        total_domains,
        non_fetched_count,
    )

    if classified_df.empty:
        existing_records = checkpoint_store.get_terminal_submission_records() if checkpoint_store is not None else []
        empty_df = pd.DataFrame(existing_records, columns=_submission_record_columns()) if existing_records else pd.DataFrame(columns=_submission_record_columns())
        empty_df.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
        empty_df.to_csv(filtered_output_path, index=False, encoding="utf-8")
        _write_debug_csv([], STAGE2_MODEL_DEBUG_PATH)
        _write_debug_csv([], STAGE3_CLASSIFICATION_DEBUG_PATH)
        _write_hash_review_queue(_merge_review_queue_frames(existing_review_df, low_conf_df))
        logger.info("No shortlisted rows to classify. Final output written as empty schema CSV.")
        return empty_df

    try:
        brand_model, domain_model, brand_label_encoder, source_classes, feature_cols, scaler, imputer = load_models_and_preproc()
        brand_classes = list(getattr(brand_label_encoder, "classes_", []))
        logger.info("Loaded supporting models for hash-only validation: brand/CSE model + target-domain model")
    except Exception as exc:
        brand_model = None
        domain_model = None
        brand_classes = []
        source_classes = []
        feature_cols = []
        scaler = None
        imputer = None
        logger.warning("Supporting models unavailable for hash-only validation: %s", exc)

    records = []
    review_queue_records = []
    stage2_model_debug_records = []
    stage3_classification_debug_records = []
    records_lock = asyncio.Lock()
    serial_counter = [0]
    rdap_sem = _get_rdap_semaphore()
    whois_sem = _get_whois_semaphore()
    dns_sem = _get_dns_prefilter_semaphore()
    classify_progress = ProgressTracker(total=len(classified_df))
    classify_metrics = {
        "outputs": 0,
        "review": 0,
        "failed": 0,
        "parked": 0,
        "legitimate": 0,
        "suspected": 0,
        "phishing": 0,
    }
    active_workers: dict[str, str] = {}

    def _upsert_classify_checkpoint(
        *,
        row: dict,
        stage_status: str,
        final_pipeline_status: str | None = None,
        final_decision: str | None = None,
        failure_reason: str | None = None,
        retry_count: int = 0,
        timeout_hit: bool = False,
        worker_id: str = "",
        error_type: str = "",
        error_message: str = "",
        submission_record: dict | None = None,
    ) -> None:
        if checkpoint_store is None or run_context is None:
            return
        domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
        normalized_url = domain_url.strip().lower()
        source_workbook = str(row.get("source_workbook", "") or "")
        checkpoint_store.upsert_url_result(
            stage_result_patch(
                run_id=run_context.run_id,
                raw_url=domain_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
                stage_name="classify",
                stage_status=stage_status,
                current_stage="classify",
                retry_count=retry_count,
                timeout_hit=timeout_hit,
                worker_id=worker_id,
                error_type=error_type,
                error_message=error_message,
                final_pipeline_status=final_pipeline_status,
                final_decision=final_decision,
                failure_reason=failure_reason,
                submission_record=submission_record,
            )
        )

    def _append_classify_stage_event(
        *,
        row: dict,
        worker_id: str,
        started_at: str,
        started_monotonic: float,
        status: str,
        retry_count: int = 0,
        timeout_flag: bool = False,
        error_type: str = "",
        error_message: str = "",
    ) -> None:
        if checkpoint_store is None or run_context is None:
            return
        domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
        normalized_url = domain_url.strip().lower()
        source_workbook = str(row.get("source_workbook", "") or "")
        checkpoint_store.append_stage_event(
            {
                "run_id": run_context.run_id,
                "record_key": make_record_key(normalized_url, source_workbook),
                "source_workbook": source_workbook,
                "normalized_url": normalized_url,
                "stage_name": "classify",
                "attempt_index": max(1, int(retry_count) + 1),
                "worker_id": worker_id,
                "started_at": started_at,
                "finished_at": utc_now_iso(),
                "duration_ms": int(max(0.0, (time.perf_counter() - started_monotonic) * 1000.0)),
                "status": status,
                "error_type": error_type,
                "error_message": error_message,
                "retry_count": retry_count,
                "timeout_flag": int(bool(timeout_flag)),
                "fallback_taken": "",
            }
        )

    def _get_rdap_url(host):
        ext = tldextract.extract(host)
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""
        return RDAP_DIRECT_URLS.get(tld, RDAP_FALLBACK_URL)

    async def _process_hash_row(row: dict, client: httpx.AsyncClient, worker_id: str = ""):
        domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
        stage_started_at = utc_now_iso()
        stage_started_monotonic = time.perf_counter()
        host = urlparse(domain_url).hostname or domain_url
        host = host.split(":")[0]
        screenshot_path = str(row.get("screenshot_path", "") or "").strip()
        fetch_status = str(row.get("fetch_status", "fetched") or "fetched").strip().lower()
        source_workbook = str(row.get("source_workbook", "") or "")
        confidence_band = row.get("confidence_band", "Low")
        evidence_tier = _normalize_evidence_tier(row)
        stored_parking = _detect_stored_parked_page(row)
        if stored_parking["is_parked"]:
            async with records_lock:
                stage2_model_debug_records.append(
                    {
                        "url": domain_url,
                        "source_workbook": source_workbook,
                        "shortlisted_cse": row.get("Cooresponding CSE", ""),
                        "shortlisted_domain": row.get("Legitimate Domains", ""),
                        "fetch_status": fetch_status,
                        "final_landing_url": stored_parking.get("final_landing_url", ""),
                        "parking_provider": stored_parking.get("parking_provider", ""),
                        "parking_reason": stored_parking.get("parking_reason", ""),
                        "brand_model_top1": "NA",
                        "brand_model_confidence": 0.0,
                        "domain_model_top1": "Unknown",
                        "domain_model_confidence": 0.0,
                        "model_brand_agrees_with_shortlist": False,
                        "model_domain_agrees_with_shortlist": False,
                        "model_feature_status": "skipped_parked_page",
                        "model_input_error": stored_parking.get("parking_reason", ""),
                        "model_usable": False,
                        **_stage1_debug_compat_payload(row),
                    }
                )
                stage3_classification_debug_records.append(
                    {
                        "url": domain_url,
                        "source_workbook": source_workbook,
                        "shortlisted_cse": row.get("Cooresponding CSE", ""),
                        "shortlisted_domain": row.get("Legitimate Domains", ""),
                        "fetch_status": fetch_status,
                        "final_landing_url": stored_parking.get("final_landing_url", ""),
                        "parking_provider": stored_parking.get("parking_provider", ""),
                        "parking_reason": stored_parking.get("parking_reason", ""),
                        "placeholder_or_parking_reason": stored_parking.get("parking_reason", ""),
                        "classification": "SKIPPED_PARKING_OR_PLACEHOLDER",
                        "confidence_band": row.get("confidence_band", "Low"),
                        "evidence_tier": row.get("evidence_tier", ""),
                        "lexical_score": row.get("lexical_score", 0.0),
                        "hash_score": row.get("hash_score", 0.0),
                        "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                        "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                        "strict_lexical_hit": row.get("strict_lexical_hit", False),
                        "lexical_score_pass": row.get("lexical_score_pass", False),
                        "fallback_rank_only": row.get("fallback_rank_only", False),
                        "typo_anchor": row.get("typo_anchor", False),
                        "hash_anchor": row.get("hash_anchor", False),
                        "clip_anchor": row.get("clip_anchor", False),
                        "generic_token_only_match": row.get("generic_token_only_match", False),
                        "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                        "clip_corroborated": row.get("clip_corroborated", False),
                        "stage1_passthrough": row.get("stage1_passthrough", False),
                        "tvc_brand_detected": False,
                        "tvc_detected_brand": "none",
                        "tvc_brand_spoofed": False,
                        "tvc_match_surface": "none",
                        "tvc_matched_alias": "",
                        "tvc_spoof_strong": False,
                        "ocr_text_len": 0,
                        "registrar": "NA",
                        "hosting_isp": "NA",
                        "hosting_country": "NA",
                        "dns_records": "NA",
                        "brand_model_top1": "NA",
                        "brand_model_confidence": 0.0,
                        "domain_model_top1": "Unknown",
                        "domain_model_confidence": 0.0,
                        "model_brand_agrees_with_shortlist": False,
                        "model_domain_agrees_with_shortlist": False,
                        "model_feature_status": "skipped_parked_page",
                        "model_input_error": stored_parking.get("parking_reason", ""),
                        "model_usable": False,
                        "classification_gate_reason": "parked_replay_excluded",
                        "review_only_reason": stored_parking.get("parking_reason", "parking_or_placeholder_excluded"),
                        "survival_path": "",
                        "drop_path": "parked_replay_excluded",
                        "non_lexical_corroboration_count": 0,
                        **_stage1_debug_compat_payload(row),
                    }
                )
                _upsert_classify_checkpoint(
                    row=row,
                    stage_status="skipped_parked_page",
                    final_pipeline_status="parked_or_placeholder",
                    final_decision="UNCLASSIFIED",
                    failure_reason=stored_parking.get("parking_reason", "parking_or_placeholder_excluded"),
                    worker_id=worker_id,
                )
                _append_classify_stage_event(
                    row=row,
                    worker_id=worker_id,
                    started_at=stage_started_at,
                    started_monotonic=stage_started_monotonic,
                    status="skipped_parked_page",
                )
                classify_metrics["parked"] += 1
                classify_progress.mark_completed(final_status="parked_or_placeholder")
            return
        if fetch_status not in eligible_fetch_statuses:
            classification_decision = _hybrid_hash_decision(
                row,
                registrar="NA",
                hosting_isp="NA",
                dns_records="NA",
                ocr_text_from_csv="",
                tvc_brand_spoofed=False,
                tvc_brand_spoof_strong=False,
                brand_model_agrees=False,
                domain_model_agrees=False,
                brand_model_confidence=0.0,
                domain_model_confidence=0.0,
                failed_fetch_suspected_min=failed_fetch_suspected_min,
                failed_fetch_review_min=failed_fetch_review_min,
            )
            classification = str(classification_decision.get("classification", "Legitimate"))
            emit_output = bool(classification_decision.get("emit_output", False))
            classification_gate_reason = str(classification_decision.get("classification_gate_reason", "") or "")
            review_only_reason = str(classification_decision.get("review_only_reason", "") or "")
            non_lexical_corroboration_count = int(classification_decision.get("non_lexical_corroboration_count", 0) or 0)
            source_of_detection = adjust_source(
                row.get("Cooresponding CSE", ""),
                row.get("Legitimate Domains", ""),
                "Unknown",
            )
            record = None
            if emit_output:
                record = {
                    "Application_ID": APPLICATION_ID,
                    "Source of detection": source_of_detection,
                    "Identified Phishing/Suspected Domain Name": domain_url,
                    "Corresponding CSE Domain Name": row.get("Legitimate Domains", ""),
                    "Critical Sector Entity Name": row.get("Cooresponding CSE", ""),
                    "Phishing/Suspected Domains (i.e. Class Label)": classification,
                    "Domain Registration Date": "NA",
                    "Registrar Name": "NA",
                    "Registrant Name or Registrant Organisation": "NA",
                    "Registrant Country": "NA",
                    "Name Servers": "NA",
                    "Hosting IP": "NA",
                    "Hosting ISP": "NA",
                    "Hosting Country": "NA",
                    "DNS Records (if any)": "NA",
                    "Evidence file name": "NA",
                    "Date of detection (DD-MM-YYYY)": datetime.now().strftime("%d-%m-%Y"),
                    "Time of detection (HH-MM-SS)": datetime.now().strftime("%H:%M:%S"),
                    "Date of Post (If detection is from Source: social media)": "NA",
                    "Remarks": "weak_or_single_signal_match; NA values are due to privacy issues.",
                }
            async with records_lock:
                if emit_output and record is not None:
                    records.append(record)
                    await asyncio.to_thread(_append_record_to_checkpoint, record, CHECKPOINT_CSV)
                elif classification == "REVIEW_ONLY":
                    review_row = dict(row)
                    review_row.update(
                        {
                            "review_reason": review_only_reason or "stage3_review_only",
                            "classification_gate_reason": classification_gate_reason,
                            "non_lexical_corroboration_count": non_lexical_corroboration_count,
                            "tvc_match_surface": "none",
                            "tvc_matched_alias": "",
                            "tvc_spoof_strong": False,
                        }
                    )
                    review_queue_records.append(review_row)
                stage2_model_debug_records.append(
                    {
                        "url": domain_url,
                        "source_workbook": source_workbook,
                        "shortlisted_cse": row.get("Cooresponding CSE", ""),
                        "shortlisted_domain": row.get("Legitimate Domains", ""),
                        "fetch_status": fetch_status,
                        "final_landing_url": row.get("final_landing_url", ""),
                        "parking_provider": row.get("parking_provider", ""),
                        "parking_reason": row.get("parking_reason", ""),
                        "brand_model_top1": "NA",
                        "brand_model_confidence": 0.0,
                        "domain_model_top1": "Unknown",
                        "domain_model_confidence": 0.0,
                        "model_brand_agrees_with_shortlist": False,
                        "model_domain_agrees_with_shortlist": False,
                        "model_feature_status": "skipped_non_fetched_fetch_state",
                        "model_input_error": classification_gate_reason or fetch_status,
                        "model_usable": False,
                        **_stage1_debug_compat_payload(row),
                    }
                )
                stage3_classification_debug_records.append(
                    {
                        "url": domain_url,
                        "source_workbook": source_workbook,
                        "shortlisted_cse": row.get("Cooresponding CSE", ""),
                        "shortlisted_domain": row.get("Legitimate Domains", ""),
                        "fetch_status": fetch_status,
                        "final_landing_url": row.get("final_landing_url", ""),
                        "parking_provider": row.get("parking_provider", ""),
                        "parking_reason": row.get("parking_reason", ""),
                        "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", row.get("parking_reason", "")),
                        "classification": classification,
                        "confidence_band": confidence_band,
                        "evidence_tier": evidence_tier,
                        "lexical_score": row.get("lexical_score", 0.0),
                        "hash_score": row.get("hash_score", 0.0),
                        "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                        "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                        "strict_lexical_hit": row.get("strict_lexical_hit", False),
                        "lexical_score_pass": row.get("lexical_score_pass", False),
                        "fallback_rank_only": row.get("fallback_rank_only", False),
                        "typo_anchor": row.get("typo_anchor", False),
                        "hash_anchor": row.get("hash_anchor", False),
                        "clip_anchor": row.get("clip_anchor", False),
                        "generic_token_only_match": row.get("generic_token_only_match", False),
                        "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                        "clip_corroborated": row.get("clip_corroborated", False),
                        "stage1_passthrough": row.get("stage1_passthrough", False),
                        "tvc_brand_detected": False,
                        "tvc_detected_brand": "none",
                        "tvc_brand_spoofed": False,
                        "tvc_match_surface": "none",
                        "tvc_matched_alias": "",
                        "tvc_spoof_strong": False,
                        "ocr_text_len": 0,
                        "registrar": "NA",
                        "hosting_isp": "NA",
                        "hosting_country": "NA",
                        "dns_records": "NA",
                        "brand_model_top1": "NA",
                        "brand_model_confidence": 0.0,
                        "domain_model_top1": "Unknown",
                        "domain_model_confidence": 0.0,
                        "model_brand_agrees_with_shortlist": False,
                        "model_domain_agrees_with_shortlist": False,
                        "model_feature_status": "skipped_non_fetched_fetch_state",
                        "model_input_error": classification_gate_reason or fetch_status,
                        "model_usable": False,
                        "classification_gate_reason": classification_gate_reason,
                        "review_only_reason": review_only_reason,
                        "survival_path": classification_gate_reason if (emit_output or classification == "REVIEW_ONLY") else "",
                        "drop_path": "" if (emit_output or classification == "REVIEW_ONLY") else classification_gate_reason,
                        "non_lexical_corroboration_count": non_lexical_corroboration_count,
                        **_stage1_debug_compat_payload(row),
                    }
                )
                _upsert_classify_checkpoint(
                    row=row,
                    stage_status=classification_gate_reason or "non_fetched",
                    final_pipeline_status=(
                        "completed" if emit_output else "review_only" if classification == "REVIEW_ONLY" else "classification_failed"
                    ),
                    final_decision=classification if emit_output else "UNCLASSIFIED" if classification == "REVIEW_ONLY" else "UNCLASSIFIED",
                    failure_reason=review_only_reason or classification_gate_reason or fetch_status,
                    worker_id=worker_id,
                    submission_record=record if emit_output else None,
                )
                _append_classify_stage_event(
                    row=row,
                    worker_id=worker_id,
                    started_at=stage_started_at,
                    started_monotonic=stage_started_monotonic,
                    status=classification_gate_reason or "non_fetched",
                )
                if emit_output:
                    classify_metrics["outputs"] += 1
                    if classification == "Legitimate":
                        classify_metrics["legitimate"] += 1
                    elif classification == "Suspected":
                        classify_metrics["suspected"] += 1
                    elif classification == "Phishing":
                        classify_metrics["phishing"] += 1
                elif classification == "REVIEW_ONLY":
                    classify_metrics["review"] += 1
                else:
                    classify_metrics["failed"] += 1
                classify_progress.mark_completed(
                    final_status="completed" if emit_output else "review_only" if classification == "REVIEW_ONLY" else "classification_failed"
                )
            return
        html_brand_text = " ".join(
            part for part in [
                str(row.get("html_title_text", "") or "").strip(),
                str(row.get("visible_text_excerpt", "") or "").strip(),
            ]
            if part
        )

        ocr_tvc = await _extract_hash_only_ocr_tvc(
            domain_url,
            screenshot_path,
            shortlisted_cse=str(row.get("Cooresponding CSE", "") or ""),
            shortlisted_domain=str(row.get("Legitimate Domains", "") or ""),
            html_text=html_brand_text,
        ) if fetch_status in eligible_fetch_statuses else {
            "ocr_text": "",
            "ocr_header_text": "",
            "ocr_footer_text": "",
            "tvc_brand_detected": False,
            "tvc_detected_brand": "none",
            "tvc_domain_match": False,
            "tvc_fuzzy_score": 0.0,
            "tvc_brand_spoofed": False,
            "tvc_match_surface": "none",
            "tvc_matched_alias": "",
            "tvc_spoof_strong": False,
        }

        try:
            net_feats = await extract_network_features_async(domain_url)
        except Exception as exc:
            logger.warning("Hash-only network feature extraction failed for %s: %s", domain_url, exc)
            net_feats = {}

        brand_model_top1 = "NA"
        brand_model_confidence = 0.0
        domain_model_top1 = "Unknown"
        domain_model_confidence = 0.0
        model_brand_agrees_with_shortlist = False
        model_domain_agrees_with_shortlist = False
        model_feature_status = "model_unavailable"
        model_input_error = ""
        model_usable = False

        resolved_ip = None
        if net_feats.get("ip_address"):
            resolved_ip = str(net_feats.get("ip_address"))
        async with dns_sem:
            try:
                loop = asyncio.get_running_loop()
                resolved_ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, host),
                    timeout=3.0,
                )
            except Exception:
                pass

        reg_data = None
        registration_lookup_status = "unknown"
        async with rdap_sem:
            try:
                base_url = _get_rdap_url(host)
                resp = await client.get(f"{base_url}{host}")
                if resp.status_code == 200:
                    reg_data = _parse_rdap_to_fields(resp.json())
                    registration_lookup_status = "registered"
                elif resp.status_code == 404:
                    registration_lookup_status = "not_registered"
                else:
                    registration_lookup_status = f"rdap_http_{resp.status_code}"
            except Exception:
                pass

        if registration_lookup_status == "not_registered":
            async with records_lock:
                stage2_model_debug_records.append(
                    {
                        "url": domain_url,
                        "source_workbook": source_workbook,
                        "shortlisted_cse": row.get("Cooresponding CSE", ""),
                        "shortlisted_domain": row.get("Legitimate Domains", ""),
                        "fetch_status": fetch_status,
                        "final_landing_url": row.get("final_landing_url", ""),
                        "parking_provider": row.get("parking_provider", ""),
                        "parking_reason": "not_registered_domain",
                        "brand_model_top1": "NA",
                        "brand_model_confidence": 0.0,
                        "domain_model_top1": "Unknown",
                        "domain_model_confidence": 0.0,
                        "model_brand_agrees_with_shortlist": False,
                        "model_domain_agrees_with_shortlist": False,
                        "model_feature_status": "skipped_not_registered_domain",
                        "model_input_error": "rdap_not_found",
                        "model_usable": False,
                        **_stage1_debug_compat_payload(row),
                    }
                )
                stage3_classification_debug_records.append(
                    {
                        "url": domain_url,
                        "source_workbook": source_workbook,
                        "shortlisted_cse": row.get("Cooresponding CSE", ""),
                        "shortlisted_domain": row.get("Legitimate Domains", ""),
                        "fetch_status": fetch_status,
                        "final_landing_url": row.get("final_landing_url", ""),
                        "parking_provider": row.get("parking_provider", ""),
                        "parking_reason": "not_registered_domain",
                        "placeholder_or_parking_reason": "not_registered_domain",
                        "classification": "SKIPPED_PARKING_OR_PLACEHOLDER",
                        "confidence_band": row.get("confidence_band", "Low"),
                        "evidence_tier": row.get("evidence_tier", ""),
                        "lexical_score": row.get("lexical_score", 0.0),
                        "hash_score": row.get("hash_score", 0.0),
                        "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                        "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                        "strict_lexical_hit": row.get("strict_lexical_hit", False),
                        "lexical_score_pass": row.get("lexical_score_pass", False),
                        "fallback_rank_only": row.get("fallback_rank_only", False),
                        "typo_anchor": row.get("typo_anchor", False),
                        "hash_anchor": row.get("hash_anchor", False),
                        "clip_anchor": row.get("clip_anchor", False),
                        "generic_token_only_match": row.get("generic_token_only_match", False),
                        "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                        "clip_corroborated": row.get("clip_corroborated", False),
                        "stage1_passthrough": row.get("stage1_passthrough", False),
                        "tvc_brand_detected": False,
                        "tvc_detected_brand": "none",
                        "tvc_brand_spoofed": False,
                        "tvc_match_surface": "none",
                        "tvc_matched_alias": "",
                        "tvc_spoof_strong": False,
                        "ocr_text_len": 0,
                        "registrar": "NA",
                        "hosting_isp": "NA",
                        "hosting_country": "NA",
                        "dns_records": "NA",
                        "brand_model_top1": "NA",
                        "brand_model_confidence": 0.0,
                        "domain_model_top1": "Unknown",
                        "domain_model_confidence": 0.0,
                        "model_brand_agrees_with_shortlist": False,
                        "model_domain_agrees_with_shortlist": False,
                        "model_feature_status": "skipped_not_registered_domain",
                        "model_input_error": "rdap_not_found",
                        "model_usable": False,
                        "classification_gate_reason": "not_registered_domain_excluded",
                        "review_only_reason": "not_registered_domain",
                        "survival_path": "",
                        "drop_path": "not_registered_domain_excluded",
                        "non_lexical_corroboration_count": 0,
                        **_stage1_debug_compat_payload(row),
                    }
                )
                _upsert_classify_checkpoint(
                    row=row,
                    stage_status="not_registered_domain",
                    final_pipeline_status="not_registered_domain",
                    final_decision="UNCLASSIFIED",
                    failure_reason="rdap_not_found",
                    worker_id=worker_id,
                )
                _append_classify_stage_event(
                    row=row,
                    worker_id=worker_id,
                    started_at=stage_started_at,
                    started_monotonic=stage_started_monotonic,
                    status="not_registered_domain",
                )
                classify_metrics["failed"] += 1
                classify_progress.mark_completed(final_status="not_registered_domain")
            return

        if reg_data is None and resolved_ip is not None:
            async with whois_sem:
                await whois_rate_limiter.acquire()
                try:
                    loop = asyncio.get_running_loop()
                    w = await asyncio.wait_for(
                        loop.run_in_executor(None, whois.whois, host),
                        timeout=5.0,
                    )
                    if w:
                        cd = w.creation_date
                        if isinstance(cd, list):
                            cd = cd[0]
                        reg_data = {
                            "reg_date": str(cd) if cd else "NA",
                            "registrar": w.registrar or "NA",
                            "registrant_name": w.name or w.org or getattr(w, "registrant_name", None) or "NA",
                            "registrant_country": w.country or "NA",
                            "name_servers": ";".join(str(ns) for ns in w.name_servers) if w.name_servers else "NA",
                        }
                except Exception:
                    pass

        dns_records = "NA"
        if resolved_ip is not None:
            async with dns_sem:
                try:
                    loop = asyncio.get_running_loop()

                    def _resolve_sync():
                        results = []
                        for qtype in ["A", "NS", "MX", "CNAME"]:
                            try:
                                answers = dns.resolver.resolve(host, qtype, lifetime=2.0)
                                results.extend([f"{qtype}:{record.to_text()}" for record in answers])
                            except Exception:
                                pass
                        return ";".join(results) if results else "NA"

                    dns_records = await loop.run_in_executor(None, _resolve_sync)
                except Exception:
                    pass

        rd = reg_data or {}
        reg_date = rd.get("reg_date", "NA")
        registrar = rd.get("registrar", "NA")
        registrant_name = rd.get("registrant_name", "NA")
        registrant_country = rd.get("registrant_country", "NA")
        name_servers = rd.get("name_servers", "NA")

        geo_input = pd.DataFrame([{"url": domain_url, "ip_address": resolved_ip or "NA"}])
        geo_dict = enrich_with_geoip(geo_input, ASN_DB_PATH, CITY_DB_PATH).iloc[0].to_dict()
        ip = str(geo_dict.get("ip_address") or (resolved_ip or "NA"))
        hosting_isp = str(geo_dict.get("asn_org", "NA")) if geo_dict.get("asn_org") and not pd.isna(geo_dict.get("asn_org")) else "NA"
        hosting_country = str(geo_dict.get("country", "NA")) if geo_dict.get("country") and not pd.isna(geo_dict.get("country")) else "NA"

        if feature_cols and scaler is not None and imputer is not None:
            try:
                x_frame = _build_hash_only_model_frame(row, net_feats, geo_dict, imputer)
                x_imp = imputer.transform(x_frame)
                x_sc = scaler.transform(x_imp)
                brand_model_top1, brand_model_confidence = _safe_predict_top1(brand_model, x_sc, brand_classes)
                domain_model_top1, domain_model_confidence = _safe_predict_top1(domain_model, x_sc, source_classes)
                shortlisted_cse = str(row.get("Cooresponding CSE", "") or "").strip().lower()
                shortlisted_domain = str(row.get("Legitimate Domains", "") or "").strip().lower()
                model_brand_agrees_with_shortlist = (
                    brand_model_top1 != "NA"
                    and shortlisted_cse
                    and str(brand_model_top1).strip().lower() == shortlisted_cse
                )
                model_domain_agrees_with_shortlist = (
                    domain_model_top1 not in {"NA", "Unknown"}
                    and shortlisted_domain
                    and str(domain_model_top1).strip().lower() == shortlisted_domain
                )
                model_feature_status = "ok"
                model_usable = True
            except Exception as exc:
                model_feature_status = "feature_error"
                model_input_error = str(exc)

        confidence_band = row.get("confidence_band", "Low")
        evidence_tier = _normalize_evidence_tier(row)
        classification_decision = _hybrid_hash_decision(
            row,
            registrar=registrar,
            hosting_isp=hosting_isp,
            dns_records=dns_records,
            ocr_text_from_csv=ocr_tvc.get("ocr_text", ""),
            tvc_brand_spoofed=bool(ocr_tvc.get("tvc_brand_spoofed", False)),
            tvc_brand_spoof_strong=bool(ocr_tvc.get("tvc_spoof_strong", False)),
            brand_model_agrees=model_brand_agrees_with_shortlist,
            domain_model_agrees=model_domain_agrees_with_shortlist,
            brand_model_confidence=brand_model_confidence,
            domain_model_confidence=domain_model_confidence,
            failed_fetch_suspected_min=failed_fetch_suspected_min,
            failed_fetch_review_min=failed_fetch_review_min,
        )
        classification = str(classification_decision.get("classification", "Legitimate"))
        emit_output = bool(classification_decision.get("emit_output", False))
        classification_gate_reason = str(classification_decision.get("classification_gate_reason", "") or "")
        review_only_reason = str(classification_decision.get("review_only_reason", "") or "")
        non_lexical_corroboration_count = int(classification_decision.get("non_lexical_corroboration_count", 0) or 0)
        source_of_detection = adjust_source(
            row.get("Cooresponding CSE", ""),
            row.get("Legitimate Domains", ""),
            domain_model_top1 if domain_model_top1 not in {"NA", ""} else "Unknown",
        )

        evidence_name = "NA"
        if emit_output and classification.lower() == "phishing":
            async with records_lock:
                serial_counter[0] += 1
                serial_no = serial_counter[0]
            evidence_path, evidence_name = format_evidence_filename(
                row.get("Cooresponding CSE", "Unknown"),
                domain_url,
                serial_no,
                application_id=APPLICATION_ID,
            )
            await asyncio.to_thread(move_screenshot_to_evidence, domain_url, evidence_path)

        detection_date = datetime.now().strftime("%d-%m-%Y")
        detection_time_str = datetime.now().strftime("%H:%M:%S")
        record = {
            "Application_ID": APPLICATION_ID,
            "Source of detection": source_of_detection,
            "Identified Phishing/Suspected Domain Name": domain_url,
            "Corresponding CSE Domain Name": row.get("Legitimate Domains", ""),
            "Critical Sector Entity Name": row.get("Cooresponding CSE", ""),
            "Phishing/Suspected Domains (i.e. Class Label)": classification,
            "Domain Registration Date": reg_date,
            "Registrar Name": registrar,
            "Registrant Name or Registrant Organisation": registrant_name,
            "Registrant Country": registrant_country,
            "Name Servers": name_servers,
            "Hosting IP": ip,
            "Hosting ISP": hosting_isp,
            "Hosting Country": hosting_country,
            "DNS Records (if any)": dns_records,
            "Evidence file name": evidence_name,
            "Date of detection (DD-MM-YYYY)": detection_date,
            "Time of detection (HH-MM-SS)": detection_time_str,
            "Date of Post (If detection is from Source: social media)": "NA",
            "Remarks": (
                "non_aligned_or_weak_cse_similarity; NA values are due to privacy issues."
                if classification == "Legitimate"
                else "weak_or_single_signal_match; NA values are due to privacy issues."
                if evidence_tier == "weak_evidence"
                else "NA values are due to privacy issues."
            ),
        }
        async with records_lock:
            if emit_output:
                records.append(record)
                await asyncio.to_thread(_append_record_to_checkpoint, record, CHECKPOINT_CSV)
            elif classification == "REVIEW_ONLY":
                review_row = dict(row)
                review_row.update(
                    {
                        "review_reason": review_only_reason or "stage3_review_only",
                        "classification_gate_reason": classification_gate_reason,
                        "non_lexical_corroboration_count": non_lexical_corroboration_count,
                        "tvc_match_surface": ocr_tvc.get("tvc_match_surface", "none"),
                        "tvc_matched_alias": ocr_tvc.get("tvc_matched_alias", ""),
                        "tvc_spoof_strong": ocr_tvc.get("tvc_spoof_strong", False),
                    }
                )
                review_queue_records.append(review_row)
            stage2_model_debug_records.append(
                {
                    "url": domain_url,
                    "source_workbook": source_workbook,
                    "shortlisted_cse": row.get("Cooresponding CSE", ""),
                    "shortlisted_domain": row.get("Legitimate Domains", ""),
                    "fetch_status": fetch_status,
                    "final_landing_url": row.get("final_landing_url", ""),
                    "parking_provider": row.get("parking_provider", ""),
                    "parking_reason": row.get("parking_reason", ""),
                    "brand_model_top1": brand_model_top1,
                    "brand_model_confidence": round(float(brand_model_confidence), 4),
                    "domain_model_top1": domain_model_top1,
                    "domain_model_confidence": round(float(domain_model_confidence), 4),
                    "model_brand_agrees_with_shortlist": model_brand_agrees_with_shortlist,
                    "model_domain_agrees_with_shortlist": model_domain_agrees_with_shortlist,
                    "model_feature_status": model_feature_status,
                    "model_input_error": model_input_error,
                    "model_usable": model_usable,
                    **_stage1_debug_compat_payload(row),
                }
            )
            stage3_classification_debug_records.append(
                {
                    "url": domain_url,
                    "source_workbook": source_workbook,
                    "shortlisted_cse": row.get("Cooresponding CSE", ""),
                    "shortlisted_domain": row.get("Legitimate Domains", ""),
                    "fetch_status": fetch_status,
                    "final_landing_url": row.get("final_landing_url", ""),
                    "parking_provider": row.get("parking_provider", ""),
                    "parking_reason": row.get("parking_reason", ""),
                    "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", row.get("parking_reason", "")),
                    "classification": classification,
                    "confidence_band": confidence_band,
                    "evidence_tier": evidence_tier,
                    "lexical_score": row.get("lexical_score", 0.0),
                    "hash_score": row.get("hash_score", 0.0),
                    "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                    "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                    "strict_lexical_hit": row.get("strict_lexical_hit", False),
                    "lexical_score_pass": row.get("lexical_score_pass", False),
                    "fallback_rank_only": row.get("fallback_rank_only", False),
                    "typo_anchor": row.get("typo_anchor", False),
                    "hash_anchor": row.get("hash_anchor", False),
                    "clip_anchor": row.get("clip_anchor", False),
                    "generic_token_only_match": row.get("generic_token_only_match", False),
                    "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                    "clip_corroborated": row.get("clip_corroborated", False),
                    "stage1_passthrough": row.get("stage1_passthrough", False),
                    "tvc_brand_detected": ocr_tvc.get("tvc_brand_detected", False),
                    "tvc_detected_brand": ocr_tvc.get("tvc_detected_brand", "none"),
                    "tvc_brand_spoofed": ocr_tvc.get("tvc_brand_spoofed", False),
                    "tvc_match_surface": ocr_tvc.get("tvc_match_surface", "none"),
                    "tvc_matched_alias": ocr_tvc.get("tvc_matched_alias", ""),
                    "tvc_spoof_strong": ocr_tvc.get("tvc_spoof_strong", False),
                    "ocr_text_len": len(str(ocr_tvc.get("ocr_text", "") or "")),
                    "registrar": registrar,
                    "hosting_isp": hosting_isp,
                    "hosting_country": hosting_country,
                    "dns_records": dns_records,
                    "brand_model_top1": brand_model_top1,
                    "brand_model_confidence": round(float(brand_model_confidence), 4),
                    "domain_model_top1": domain_model_top1,
                    "domain_model_confidence": round(float(domain_model_confidence), 4),
                    "model_brand_agrees_with_shortlist": model_brand_agrees_with_shortlist,
                    "model_domain_agrees_with_shortlist": model_domain_agrees_with_shortlist,
                    "model_feature_status": model_feature_status,
                    "model_input_error": model_input_error,
                    "model_usable": model_usable,
                    "classification_gate_reason": classification_gate_reason,
                    "review_only_reason": review_only_reason,
                    "survival_path": classification_gate_reason if (emit_output or classification == "REVIEW_ONLY") else "",
                    "drop_path": "" if (emit_output or classification == "REVIEW_ONLY") else classification_gate_reason,
                    "non_lexical_corroboration_count": non_lexical_corroboration_count,
                    **_stage1_debug_compat_payload(row),
                }
            )
        _upsert_classify_checkpoint(
            row=row,
            stage_status=classification_gate_reason or classification,
            final_pipeline_status=(
                "completed" if emit_output else "review_only" if classification == "REVIEW_ONLY" else "classification_failed"
            ),
            final_decision=classification if emit_output else "UNCLASSIFIED" if classification == "REVIEW_ONLY" else "UNCLASSIFIED",
            failure_reason=review_only_reason or classification_gate_reason,
            worker_id=worker_id,
            submission_record=record if emit_output else None,
        )
        _append_classify_stage_event(
            row=row,
            worker_id=worker_id,
            started_at=stage_started_at,
            started_monotonic=stage_started_monotonic,
            status=classification_gate_reason or classification,
        )
        if emit_output:
            classify_metrics["outputs"] += 1
            if classification == "Legitimate":
                classify_metrics["legitimate"] += 1
            elif classification == "Suspected":
                classify_metrics["suspected"] += 1
            elif classification == "Phishing":
                classify_metrics["phishing"] += 1
        elif classification == "REVIEW_ONLY":
            classify_metrics["review"] += 1
        else:
            classify_metrics["failed"] += 1
        classify_progress.mark_completed(
            final_status="completed" if emit_output else "review_only" if classification == "REVIEW_ONLY" else "classification_failed"
        )

    classify_worker_count = max(1, min(32, NETWORK_SEMAPHORE_LIMIT, len(classified_df)))
    classify_queue: asyncio.Queue[dict | None] = asyncio.Queue()
    for row in classified_df.to_dict("records"):
        await classify_queue.put(row)
    for _ in range(classify_worker_count):
        await classify_queue.put(None)

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        try:
            from tqdm import tqdm

            progress_bar = tqdm(
                total=len(classified_df),
                desc="Stage3 classify",
                unit="url",
                leave=True,
                dynamic_ncols=True,
            )
        except ImportError:
            progress_bar = None

        async def _progress_monitor() -> None:
            if progress_bar is None:
                return
            last_completed = 0
            while True:
                await asyncio.sleep(0.5)
                completed = classify_progress.completed
                if completed > last_completed:
                    progress_bar.update(completed - last_completed)
                    last_completed = completed
                progress_bar.set_postfix(
                    {
                        "act": len(active_workers),
                        "q": classify_queue.qsize(),
                        "out": classify_metrics["outputs"],
                        "rev": classify_metrics["review"],
                        "fail": classify_metrics["failed"],
                    },
                    refresh=False,
                )
                if completed >= len(classified_df):
                    break

        monitor_task = asyncio.create_task(_progress_monitor()) if progress_bar is not None else None

        async def _classify_worker(worker_index: int) -> None:
            worker_id = f"classify-{worker_index}"
            while True:
                row = await classify_queue.get()
                if row is None:
                    classify_queue.task_done()
                    break
                domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
                normalized_url = domain_url.strip().lower()
                source_workbook = str(row.get("source_workbook", "") or "")
                record_key = make_record_key(normalized_url, source_workbook)
                active_workers[worker_id] = normalized_url
                if checkpoint_store is not None:
                    checkpoint_store.update_worker_heartbeat(
                        stage_name="classify",
                        worker_id=worker_id,
                        record_key=record_key,
                        state="running",
                        details={"url": normalized_url},
                    )
                try:
                    await async_with_timeout_and_retry(
                        lambda: _process_hash_row(row, client, worker_id),
                        timeout=30.0,
                        max_retries=0,
                    )
                except Exception as exc:
                    error = normalize_exception(exc)
                    logger.error(
                        "Hash-only worker failure | worker=%s | url=%s | %s: %s",
                        worker_id,
                        domain_url,
                        error["error_type"],
                        error["error_message"],
                    )
                    _upsert_classify_checkpoint(
                        row=row,
                        stage_status="failed",
                        final_pipeline_status="classification_failed",
                        final_decision="UNCLASSIFIED",
                        failure_reason=error["error_message"],
                        worker_id=worker_id,
                        error_type=error["error_type"],
                        error_message=error["error_message"],
                    )
                    _append_classify_stage_event(
                        row=row,
                        worker_id=worker_id,
                        started_at=utc_now_iso(),
                        started_monotonic=time.perf_counter(),
                        status="failed",
                        error_type=error["error_type"],
                        error_message=error["error_message"],
                    )
                    classify_metrics["failed"] += 1
                    classify_progress.mark_completed(final_status="classification_failed")
                finally:
                    active_workers.pop(worker_id, None)
                    if checkpoint_store is not None:
                        checkpoint_store.clear_worker_heartbeat(stage_name="classify", worker_id=worker_id)
                    classify_queue.task_done()

        classify_watchdog = StageWatchdog(
            stage_name="classify",
            progress_tracker=classify_progress,
            checkpoint_store=checkpoint_store,
            warn_after_seconds=run_context.watchdog_warning_seconds if run_context is not None else 60,
            stall_after_seconds=run_context.stall_threshold_seconds if run_context is not None else 180,
            queue_size_getter=classify_queue.qsize,
            active_summary_getter=lambda: {"workers": classify_worker_count, "records": len(records), "reviews": len(review_queue_records)},
            logger_instance=logger,
        )
        workers = [asyncio.create_task(_classify_worker(index)) for index in range(classify_worker_count)]
        classify_watchdog.start()
        try:
            join_timeout = max(
                run_context.stall_threshold_seconds if run_context is not None else 180,
                30,
            )
            await asyncio.wait_for(classify_queue.join(), timeout=join_timeout)
            await asyncio.gather(*workers)
        except asyncio.TimeoutError as exc:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise RuntimeError("Hash-only classification worker pool stalled before draining the queue") from exc
        finally:
            if monitor_task is not None:
                monitor_task.cancel()
                await asyncio.gather(monitor_task, return_exceptions=True)
            if progress_bar is not None:
                completed = classify_progress.completed
                if completed > progress_bar.n:
                    progress_bar.update(completed - progress_bar.n)
                progress_bar.set_postfix(
                    {
                        "act": len(active_workers),
                        "q": classify_queue.qsize(),
                        "out": classify_metrics["outputs"],
                        "rev": classify_metrics["review"],
                        "fail": classify_metrics["failed"],
                    },
                    refresh=False,
                )
                progress_bar.close()
            await classify_watchdog.stop()

    parked_skip_count = sum(
        1
        for row in stage3_classification_debug_records
        if str(row.get("classification", "")).strip() == "SKIPPED_PARKING_OR_PLACEHOLDER"
    )
    review_only_count = sum(
        1
        for row in stage3_classification_debug_records
        if str(row.get("classification", "")).strip() == "REVIEW_ONLY"
    )
    stage3_review_df = pd.DataFrame(review_queue_records)
    merged_review_df = _merge_review_queue_frames(existing_review_df, low_conf_df, stage3_review_df)
    _write_hash_review_queue(merged_review_df)
    logger.info(
        "Hash-only stage summary | input_after_whitelist=%d | processed_for_stage3=%d | non_fetched_candidates=%d | skipped_parked_or_placeholder=%d | review_only=%d | final_output_records=%d",
        len(df_filtered),
        total_domains,
        non_fetched_count,
        parked_skip_count,
        review_only_count,
        len(records),
    )
    df_out = pd.DataFrame(records, columns=_submission_record_columns())
    df_out.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
    flagged_df = df_out[
        df_out["Phishing/Suspected Domains (i.e. Class Label)"].isin(["Phishing", "Suspected"])
    ].copy()
    flagged_df.to_csv(filtered_output_path, index=False, encoding="utf-8")
    _write_debug_csv(stage2_model_debug_records, STAGE2_MODEL_DEBUG_PATH)
    _write_debug_csv(stage3_classification_debug_records, STAGE3_CLASSIFICATION_DEBUG_PATH)
    if checkpoint_store is not None:
        checkpoint_store.export_all()
    logger.info("Stage2 model debug written to %s (%d rows)", STAGE2_MODEL_DEBUG_PATH, len(stage2_model_debug_records))
    logger.info("Stage3 classification debug written to %s (%d rows)", STAGE3_CLASSIFICATION_DEBUG_PATH, len(stage3_classification_debug_records))
    logger.info("Hash-only final output written to %s (%d records)", FINAL_OUTPUT, len(df_out))
    logger.info("Flagged-only final output written to %s (%d records)", filtered_output_path, len(flagged_df))
    return df_out

# ------------------------------------------------------------------
# Pipeline runner
# ------------------------------------------------------------------
async def run_pipeline(
    holdout_folder,
    ps02_whitelist_file,
    limit_whitelisted=None,
    limit_target_urls=None,
    use_existing_holdout=False,
    pipeline_mode="hash_only",
    high_confidence_threshold=78.0,
    medium_confidence_threshold=68.0,
    hashing_threshold=58.0,
    domain_similarity_threshold=0.85,
    typo_top_k=10,
    typo_min_score=0.75,
    lexical_pass_min_score=0.85,
    clip_margin_min=0.20,
    dns_timeout=5.0,
    dns_retries=0,
    dns_max_workers=None,
    shortlist_debug_csv=None,
    stage1_escalate_total_threshold=None,
    stage1_brand_min=None,
    stage1_credential_min=None,
    stage1_low_band_min=None,
    stage1_hard_trigger_brand_min=None,
    keep_stage1_suspected=False,
    keep_dns_rejected_strict_lexical=False,
    keep_fetch_failed_strict_lexical=False,
    failed_fetch_suspected_min=None,
    failed_fetch_review_min=None,
    run_context: RunContext | None = None,
    checkpoint_store: CheckpointStore | None = None,
    resume: bool = False,
    force_reprocess: bool = False,
):
    import time
    from tqdm import tqdm as tqdm_sync
    
    start_time = time.time()
    logger.info("🚀 Starting pipeline...")
    pipeline_mode = str(pipeline_mode or "hash_only").strip().lower()
    if pipeline_mode not in {"hash_only", "legacy_ocr"}:
        raise ValueError(f"Unsupported pipeline_mode '{pipeline_mode}'. Use 'hash_only' or 'legacy_ocr'.")
    if high_confidence_threshold < medium_confidence_threshold:
        raise ValueError("high_confidence_threshold must be >= medium_confidence_threshold")
    logger.info(
        "Pipeline mode=%s | high_confidence_threshold=%.2f | medium_confidence_threshold=%.2f | "
        "hashing_threshold=%.2f | domain_similarity_threshold=%.3f | typo_top_k=%d | "
        "typo_min_score=%.3f | lexical_pass_min_score=%.3f | clip_margin_min=%.3f | "
        "dns_timeout=%.2f | dns_retries=%d | dns_max_workers=%s | "
        "stage1_overrides={escalate_total=%s,brand_min=%s,credential_min=%s,low_band_min=%s,hard_trigger_brand_min=%s} | "
        "recall_passthroughs={stage1_suspected=%s,dns_rejected_strict_lexical=%s,fetch_failed_strict_lexical=%s} | "
        "failed_fetch_rescue={suspected_min=%s,review_min=%s}",
        pipeline_mode,
        high_confidence_threshold,
        medium_confidence_threshold,
        hashing_threshold,
        domain_similarity_threshold,
        int(typo_top_k),
        typo_min_score,
        lexical_pass_min_score,
        clip_margin_min,
        dns_timeout,
        int(dns_retries),
        dns_max_workers if dns_max_workers is not None else "adaptive",
        stage1_escalate_total_threshold if stage1_escalate_total_threshold is not None else "default",
        stage1_brand_min if stage1_brand_min is not None else "default",
        stage1_credential_min if stage1_credential_min is not None else "default",
        stage1_low_band_min if stage1_low_band_min is not None else "default",
        stage1_hard_trigger_brand_min if stage1_hard_trigger_brand_min is not None else "default",
        keep_stage1_suspected,
        keep_dns_rejected_strict_lexical,
        keep_fetch_failed_strict_lexical,
        failed_fetch_suspected_min if failed_fetch_suspected_min is not None else "off",
        failed_fetch_review_min if failed_fetch_review_min is not None else "off",
    )
    
    # Initialize semaphores here to be shared with process_urls
    network_semaphore = asyncio.Semaphore(NETWORK_SEMAPHORE_LIMIT)
    
    # Rate limiter: 20 requests per minute = 1 request every 3 seconds
    whois_rate_limiter = RateLimiter(requests_per_minute=20)
    
    # ROOT_DIR is now defined at the top of the file
    
    # --- This is your new output file ---
    holdout_csv_path = os.path.join(ROOT_DIR, "output", "holdout.csv")

    if not use_existing_holdout or not os.path.exists(holdout_csv_path):
        logger.info("Generating new holdout.csv via phishing_pipeline relocation...")
        from .shortlisting import load_url_records_from_excel_folder
        # Ensure parent module is in path
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        try:
            from .comparison import run_hashing_shortlist_async
            url_records = load_url_records_from_excel_folder(
                holdout_folder,
                limit=limit_target_urls,
            )
            urls = [record["url"] for record in url_records]
            url_sources = {
                record["url"]: record.get("source_workbooks", [])
                for record in url_records
            }
            holdout_df = await run_hashing_shortlist_async(
                list(urls),
                threshold=hashing_threshold,
                domain_similarity_threshold=domain_similarity_threshold,
                high_confidence_threshold=high_confidence_threshold,
                medium_confidence_threshold=medium_confidence_threshold,
                typo_top_k=typo_top_k,
                typo_min_score=typo_min_score,
                lexical_pass_min_score=lexical_pass_min_score,
                clip_margin_min=clip_margin_min,
                dns_timeout=dns_timeout,
                dns_retries=dns_retries,
                dns_max_workers=dns_max_workers,
                shortlist_debug_csv=shortlist_debug_csv,
                url_sources=url_sources,
                keep_stage1_suspected=keep_stage1_suspected,
                keep_dns_rejected_strict_lexical=keep_dns_rejected_strict_lexical,
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
            
            os.makedirs(os.path.dirname(holdout_csv_path), exist_ok=True)
            holdout_df.to_csv(holdout_csv_path, index=False)
            logger.info(f"Generated holdout.csv with {len(holdout_df)} matched rows.")
        except Exception as e:
            logger.error("Failed to generate holdout.csv using hashing shortlist: %s", e)
            return

        if not os.path.exists(holdout_csv_path):
             logger.error("Failed to generate holdout.csv. Exiting.")
             return
    else:
        logger.info("📂 Using existing holdout file: %s", holdout_csv_path)

    
    ps02_df = pd.read_excel(ps02_whitelist_file)
    if limit_whitelisted is not None:
        ps02_df = ps02_df.head(limit_whitelisted)

    # --- Use the new column name ---
    ps02_df["Legitimate Domains"] = ps02_df["Legitimate Domains"].astype(str).str.strip().str.lower()
    
    df_holdout = pd.read_csv(holdout_csv_path)
    df_holdout = _normalize_replayed_columns(
        df_holdout,
        ["parking_provider", "parking_reason", "placeholder_or_parking_reason", "final_landing_url"],
    )

    # --- Use the new column name ---
    df_filtered = df_holdout[
        df_holdout["Legitimate Domains"].isin(ps02_df["Legitimate Domains"])
    ].copy()

    # ── Resume from checkpoint if a previous run was interrupted ──────────
    done_domains = set()
    if checkpoint_store is None and resume and not force_reprocess and os.path.exists(CHECKPOINT_CSV):
        try:
            df_ckpt = pd.read_csv(CHECKPOINT_CSV)
            done_domains = set(
                df_ckpt["Identified Phishing/Suspected Domain Name"]
                .astype(str).str.strip().str.lower()
            )
            logger.info("Resuming from legacy checkpoint CSV: %d domains already completed", len(done_domains))
        except Exception as e:
            logger.warning("Could not read legacy checkpoint CSV, starting fresh: %s", e)

    if done_domains:
        df_filtered = df_filtered[
            ~df_filtered["Identified Phishing/Suspected Domain Name"]
             .astype(str).str.strip().str.lower().isin(done_domains)
        ]
        logger.info("%d domains remaining after legacy checkpoint resume", len(df_filtered))

    if pipeline_mode == "hash_only":
        df_out = await _run_hash_only_pipeline(
            df_filtered=df_filtered,
            whois_rate_limiter=whois_rate_limiter,
            high_confidence_threshold=high_confidence_threshold,
            medium_confidence_threshold=medium_confidence_threshold,
            failed_fetch_suspected_min=failed_fetch_suspected_min,
            failed_fetch_review_min=failed_fetch_review_min,
            run_context=run_context,
            checkpoint_store=checkpoint_store,
            resume=resume,
            force_reprocess=force_reprocess,
        )
        if checkpoint_store is None and os.path.exists(CHECKPOINT_CSV):
            try:
                os.remove(CHECKPOINT_CSV)
                logger.info("🗑 Removed checkpoint file (hash-only pipeline completed successfully)")
            except Exception as e:
                logger.warning("⚠ Could not remove checkpoint file: %s", e)
        pipeline_time = time.time() - start_time
        logger.info(
            "✅ Hash-only pipeline complete in %.1fs (%d records)",
            pipeline_time,
            len(df_out),
        )
        return df_out

    # Define a temp file path inside the phishing_pipeline folder
    temp_csv_path = os.path.join(os.path.dirname(__file__), "holdout_temp.csv")
    df_filtered.to_csv(temp_csv_path, index=False, encoding="utf-8")
    
    total_domains = len(df_filtered)
    
    # ================== PROGRESS BARS ==================
    # TqdmLoggingHandler routes ALL log output through tqdm.write()
    # so the 3 progress bars stay pinned at fixed screen positions.
    class _TqdmHandler(logging.Handler):
        def emit(self, record):
            try:
                msg = self.format(record)
                tqdm_sync.write(msg)
            except Exception:
                pass

    BAR_FMT = "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
    print("\n" + "="*70)
    print(f"📊 STREAMING PIPELINE: {total_domains} domains")
    print("="*70)
    print("  📸 Screenshots + Network  →  🔍 OCR (GPU)  →  ⚡ WHOIS/RDAP + Classify")
    print("  All 3 stages run CONCURRENTLY (streaming)")
    print("="*70 + "\n")

    screenshot_pbar = tqdm_sync(
        total=total_domains, desc="📸 Screenshots", unit="dom",
        bar_format=BAR_FMT, position=0, leave=True,
        dynamic_ncols=True, mininterval=5.0,
    )
    ocr_pbar = tqdm_sync(
        total=total_domains, desc="🔍 OCR        ", unit="dom",
        bar_format=BAR_FMT, position=1, leave=True,
        dynamic_ncols=True, mininterval=5.0,
    )
    p2_pbar = tqdm_sync(
        total=total_domains, desc="⚡ WHOIS/RDAP ", unit="dom",
        bar_format=BAR_FMT, position=2, leave=True,
        dynamic_ncols=True, mininterval=5.0,
    )

    # Install tqdm-safe logging — only WARNING+ to avoid bar redraws on every log line
    _tqdm_handler = _TqdmHandler()
    _tqdm_handler.setLevel(logging.WARNING)
    _tqdm_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    _root_logger = logging.getLogger()
    _original_handlers = _root_logger.handlers[:]
    _root_logger.handlers = [_tqdm_handler]
    

    # ================== PRE-LOAD MODELS (batch, fast) ==================
    logger.info("🔧 Pre-loading supporting models (brand_model + domain_model)...")
    brand_model, domain_model, brand_label_encoder, source_classes, feature_cols, scaler, imputer = load_models_and_preproc()

    # ================== PHASE 1 + PHASE 2 STREAMING (fully overlapped) ==================
    logger.info("\n" + "="*70)
    logger.info("📊 STREAMING PIPELINE: Phase 1 (OCR) ↔ Phase 2 (WHOIS/RDAP) overlapped")
    logger.info("="*70)

    phase1_start = time.time()

    # ── Shared state for Phase 2 workers ──────────────────────────────────
    all_records = []      # Final assembled submission rows
    records_lock = asyncio.Lock()
    rdap_times: list = []
    whois_times: list = []
    live_hosts: set = set()
    dns_map: dict = {}
    serial_counter = [0]  # mutable int for evidence serial numbers

    # Pre-populate from checkpoint if resuming
    if done_domains:
        try:
            df_ckpt = pd.read_csv(CHECKPOINT_CSV)
            all_records.extend(df_ckpt.to_dict("records"))
            serial_counter[0] = len(all_records)
            logger.info("♻️  Pre-loaded %d records from checkpoint (serial starts at %d)",
                        len(all_records), serial_counter[0])
        except Exception as e:
            logger.warning("⚠️ Could not pre-load checkpoint records: %s", e)

    # Semaphores for Phase 2 lookups (reuse the singletons from utils)
    rdap_sem  = _get_rdap_semaphore()
    whois_sem = _get_whois_semaphore()
    dns_sem   = _get_dns_prefilter_semaphore()

    def _get_rdap_url(host):
        ext = tldextract.extract(host)
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""
        return RDAP_DIRECT_URLS.get(tld, RDAP_FALLBACK_URL)

    # ── Phase 2 per-domain coroutine ─────────────────────────────────────
    async def _process_single_domain_phase2(feat_row: dict, client: httpx.AsyncClient):
        """
        RDAP → WHOIS → DNS records → GeoIP → ML classify → evidence PDF → record.
        Runs concurrently for up to MAX_CONCURRENT_RDAP = 10 domains at a time.
        """
        domain_url = feat_row.get("url", "")
        host = urlparse(domain_url).hostname or domain_url
        host = host.split(":")[0]

        # ── 1. DNS Pre-check ──────────────────────────────────────────────
        resolved_ip = None
        async with dns_sem:
            try:
                loop = asyncio.get_running_loop()
                resolved_ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, host),
                    timeout=3.0
                )
            except Exception:
                # Dead host — still assemble a record with NAs
                pass

        # ── 2. RDAP lookup ────────────────────────────────────────────────
        reg_data = None
        lookup_method = "NONE"
        async with rdap_sem:
            try:
                t0 = time.time()
                base_url = _get_rdap_url(host)
                resp = await client.get(f"{base_url}{host}")
                if resp.status_code == 200:
                    reg_data = _parse_rdap_to_fields(resp.json())
                    lookup_method = "RDAP"
                    async with records_lock:
                        rdap_times.append(time.time() - t0)
                elif resp.status_code == 429:
                    logger.warning("⚠️ RDAP 429 for %s", host)
            except Exception:
                pass

        # ── 3. WHOIS fallback (only if RDAP failed and host resolves) ─────
        if reg_data is None and resolved_ip is not None:
            async with whois_sem:
                await whois_rate_limiter.acquire()
                try:
                    loop = asyncio.get_running_loop()
                    t0 = time.time()
                    w = await asyncio.wait_for(
                        loop.run_in_executor(None, whois.whois, host),
                        timeout=5.0
                    )
                    if w:
                        cd = w.creation_date
                        if isinstance(cd, list): cd = cd[0]
                        reg_data = {
                            "reg_date": str(cd) if cd else "NA",
                            "registrar": w.registrar or "NA",
                            "registrant_name": w.name or w.org or getattr(w, "registrant_name", None) or "NA",
                            "registrant_country": w.country or "NA",
                            "name_servers": ";".join(str(ns) for ns in w.name_servers) if w.name_servers else "NA",
                        }
                        lookup_method = "WHOIS"
                        async with records_lock:
                            whois_times.append(time.time() - t0)
                except Exception:
                    pass

        # ── 4. DNS records batch ──────────────────────────────────────────
        dns_records = "NA"
        if resolved_ip is not None:
            async with dns_sem:
                try:
                    loop = asyncio.get_running_loop()
                    def _resolve_sync():
                        results = []
                        for qtype in ["A", "NS", "MX", "CNAME"]:
                            try:
                                answers = dns.resolver.resolve(host, qtype, lifetime=2.0)
                                results.extend([f"{qtype}:{r.to_text()}" for r in answers])
                            except Exception:
                                pass
                        return ";".join(results) if results else "NA"
                    dns_records = await loop.run_in_executor(None, _resolve_sync)
                except Exception:
                    pass

        # ── 5. Resolve registration fields ────────────────────────────────
        rd = reg_data or {}
        reg_date            = rd.get("reg_date", "NA")
        registrar           = rd.get("registrar", "NA")
        registrant_name     = rd.get("registrant_name", "NA")
        registrant_country  = rd.get("registrant_country", "NA")
        name_servers        = rd.get("name_servers", "NA")

        # ── 6. IP / GeoIP from feature dict (already enriched) ───────────
        ip = "NA"
        ip_from_feats = feat_row.get("ip_address")
        if ip_from_feats and not pd.isna(ip_from_feats):
            ip = str(ip_from_feats)
        elif resolved_ip:
            ip = resolved_ip

        hosting_isp     = str(feat_row.get("asn_org", "NA")) if feat_row.get("asn_org") and not pd.isna(feat_row.get("asn_org")) else "NA"
        hosting_country = str(feat_row.get("country", "NA"))  if feat_row.get("country")  and not pd.isna(feat_row.get("country"))  else "NA"

        # ── 7. Supporting domain-model prediction (not final class labeling) ─
        ml_source = "Unknown"
        try:
            row_series = pd.Series(feat_row)
            X_row = row_series.reindex(feature_cols, fill_value=0).values.reshape(1, -1)
            X_imp = imputer.transform(X_row)
            X_sc  = scaler.transform(X_imp)
            src_idx = domain_model.predict(X_sc)[0]
            ml_source = source_classes[src_idx]
        except Exception:
            pass

        adjusted_src = adjust_source(
            feat_row.get("Cooresponding CSE", ""),
            feat_row.get("Legitimate Domains", ""),
            ml_source,
        )

        # ── 8. Classification ─────────────────────────────────────────────
        classification = reclassify_label(
            domain_url, registrar, hosting_isp, dns_records,
            feat_row.get("ocr_text", ""),
            tvc_brand_spoofed=bool(feat_row.get("tvc_brand_spoofed", False)),
        )

        # ── 9. Evidence PDF ───────────────────────────────────────────────
        if classification.lower() == "phishing":
            async with records_lock:
                serial_counter[0] += 1
                serial_no = serial_counter[0]

            evidence_path, evidence_name = format_evidence_filename(
                feat_row.get("Cooresponding CSE", "Unknown"),
                domain_url, serial_no, application_id=APPLICATION_ID
            )
            await asyncio.to_thread(move_screenshot_to_evidence, domain_url, evidence_path)
        else:
            evidence_name = "NA"

        detection_date = datetime.now().strftime("%d-%m-%Y")
        detection_time_str = datetime.now().strftime("%H:%M:%S")

        record = {
            "Application_ID": APPLICATION_ID,
            "Source of detection": adjusted_src,
            "Identified Phishing/Suspected Domain Name": domain_url,
            "Corresponding CSE Domain Name": feat_row.get("Legitimate Domains", ""),
            "Critical Sector Entity Name": feat_row.get("Cooresponding CSE", ""),
            "Phishing/Suspected Domains (i.e. Class Label)": classification,
            "Domain Registration Date": reg_date,
            "Registrar Name": registrar,
            "Registrant Name or Registrant Organisation": registrant_name,
            "Registrant Country": registrant_country,
            "Name Servers": name_servers,
            "Hosting IP": ip,
            "Hosting ISP": hosting_isp,
            "Hosting Country": hosting_country,
            "DNS Records (if any)": dns_records,
            "Evidence file name": evidence_name,
            "Date of detection (DD-MM-YYYY)": detection_date,
            "Time of detection (HH-MM-SS)": detection_time_str,
            "Date of Post (If detection is from Source: social media)": "NA",
            "Remarks": "NA values are due to privacy issues.",
        }
        async with records_lock:
            all_records.append(record)
            # Flush to disk immediately — survives Kaggle kills
            await asyncio.to_thread(_append_record_to_checkpoint, record, CHECKPOINT_CSV)
        logger.debug("✅ Phase 2 done for %s [%s]", host, lookup_method)

    # ── Phase 2 worker: drains queue2, one domain at a time per slot ─────

    async def phase2_worker(queue2: asyncio.Queue, client: httpx.AsyncClient):
        while True:
            item = await queue2.get()
            if item is DONE_P2:
                queue2.task_done()
                break
            try:
                # GeoIP enrichment inline (fast, CPU-only, no I/O)
                feat_row = dict(item)
                host_url = feat_row.get("url", "")
                h = urlparse(host_url).hostname or host_url
                h = h.split(":")[0]
                feat_row = enrich_with_geoip(pd.DataFrame([feat_row]), ASN_DB_PATH, CITY_DB_PATH).iloc[0].to_dict()
                await _process_single_domain_phase2(feat_row, client)
                p2_pbar.update(1)
            except Exception as e:
                logger.error("[Phase2 worker] Error for %s: %s", item.get("url", "?"), e)
                p2_pbar.update(1)  # Still count failed domains
            finally:
                queue2.task_done()

    # ── Create queue2, start Phase 2 workers and Phase 1 concurrently ────
    # queue2 is created HERE so phase2_workers can wait on it before Phase 1
    # even produces any items. They'll block on queue2.get() until OCR arrives.
    PHASE2_QUEUE_DEPTH = max(MAX_CONCURRENT_RDAP * 4, MAX_CONCURRENT_OCR * 2)
    queue2: asyncio.Queue = asyncio.Queue(maxsize=PHASE2_QUEUE_DEPTH)
    DONE_P2 = object()  # Sentinel for phase2_workers

    logger.info("🚀 Launching %d Phase 2 workers + Phase 1 concurrently...", MAX_CONCURRENT_RDAP)

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as p2_client:
        # Launch Phase 2 workers BEFORE process_urls — they wait on queue2
        p2_tasks = [
            asyncio.create_task(phase2_worker(queue2, p2_client))
            for _ in range(MAX_CONCURRENT_RDAP)
        ]

        # Run Phase 1 (screenshots + OCR); feeds into queue2 as it goes
        await process_urls(temp_csv_path, FEATURES_CSV, network_semaphore,
                           phase2_queue=queue2,
                           screenshot_pbar=screenshot_pbar, ocr_pbar=ocr_pbar)

        # Phase 1 done — signal Phase 2 workers to stop after draining queue2
        for _ in range(MAX_CONCURRENT_RDAP):
            await queue2.put(DONE_P2)

        logger.info("⏳ Waiting for Phase 2 workers to complete...")
        await asyncio.gather(*p2_tasks, return_exceptions=True)

    total_time = time.time() - phase1_start

    # ── Close progress bars and restore logging ──────────────────────────
    screenshot_pbar.close()
    ocr_pbar.close()
    p2_pbar.close()

    # Restore original logging handlers
    _root_logger.handlers = _original_handlers

    logger.info("✅ Both phases complete in %.1f seconds (%d records)", total_time, len(all_records))

    # ── Speed summary ─────────────────────────────────────────────────────
    rdap_count  = len(rdap_times)
    whois_count = len(whois_times)
    rdap_avg    = sum(rdap_times)  / rdap_count  if rdap_times  else 0
    whois_avg   = sum(whois_times) / whois_count if whois_times else 0

    logger.info("📊 Lookup Speed Summary (Streaming):")
    logger.info("   ✅ RDAP:     %d (avg %.2fs)", rdap_count, rdap_avg)
    logger.info("   🐢 WHOIS:    %d (avg %.2fs)", whois_count, whois_avg)
    logger.info("   ❌ Failed:   %d", total_domains - rdap_count - whois_count)
    logger.info("   ⏱️  Total:    %.1fs (%.2fs/domain)", total_time,
                total_time / total_domains if total_domains else 0)

    # ── Write final output ────────────────────────────────────────────────
    df_out = pd.DataFrame(all_records)
    df_out.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
    logger.info("✅ Final output written to %s (%d records)", FINAL_OUTPUT, len(all_records))

    # Clean up checkpoint — pipeline completed successfully
    if os.path.exists(CHECKPOINT_CSV):
        try:
            os.remove(CHECKPOINT_CSV)
            logger.info("🗑 Removed checkpoint file (pipeline completed successfully)")
        except Exception as e:
            logger.warning("⚠ Could not remove checkpoint file: %s", e)

    # ── Clean up temp file ────────────────────────────────────────────────
    try:
        os.remove(temp_csv_path)
        logger.info("🗑 Removed temporary file: %s", temp_csv_path)
    except Exception as e:
        logger.warning("⚠ Could not remove temporary file: %s", e)

    pipeline_time = time.time() - start_time
    print("\n" + "="*70)
    print(f"✅ PIPELINE COMPLETE")
    print(f"   Total domains: {total_domains}")
    print(f"   Total time: {pipeline_time/60:.1f} minutes ({pipeline_time:.0f} seconds)")
    print(f"   Average: {pipeline_time/total_domains:.2f} seconds/domain" if total_domains else "")
    print("="*70 + "\n")

    return df_out


# ------------------------------------------------------------------
# Package results
# ------------------------------------------------------------------
def package_results(output_file=FINAL_OUTPUT, zip_path="PS-02_ISS_NLP_Submission.zip"):
    """
    Packages the final output Excel file and the evidence folder into
    a zip file matching the required submission structure.
    """
    import zipfile, os, pathlib, shutil
    
    # --- Define the paths for the new zip structure ---
    submission_root_folder = "PS-02_ISS_NLP_Submission"
    documentation_folder_name = "PS-02_ISS_NLP_Documentation"
    excel_file_name = "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
    
    # Get the evidence folder name from config (e.g., "PS-02_ISS_NLP_Evidences")
    evidence_folder_name = os.path.basename(EVIDENCE_DIR)
    
    # Define the *local* path for the temporary Excel file we will create
    # We'll save it in the same directory as this script (phishing_pipeline/)
    local_excel_path = os.path.join(BASE_DIR, excel_file_name)
    
    # Package from the main output by default so Legitimate rows are preserved.
    filtered_csv_file = output_file.replace(".csv", "_filtered.csv")
    csv_to_use = output_file

    if os.path.exists(output_file):
        try:
            df_check = pd.read_csv(output_file)
            if len(df_check) > 0:
                logger.info("Using main output file for packaging: %s", csv_to_use)
            elif os.path.exists(filtered_csv_file):
                filtered_df = pd.read_csv(filtered_csv_file)
                if len(filtered_df) > 0:
                    csv_to_use = filtered_csv_file
                    logger.info(
                        "Main output file is empty. Falling back to filtered output file: %s",
                        csv_to_use,
                    )
                else:
                    logger.info("Main and filtered output files are empty. Using main output file: %s", csv_to_use)
            else:
                logger.info("Main output file is empty and no filtered file found. Using main output file: %s", csv_to_use)
        except Exception:
            logger.info("Error checking main output file. Using main output file: %s", csv_to_use)
    elif os.path.exists(filtered_csv_file):
        try:
            filtered_df = pd.read_csv(filtered_csv_file)
            if len(filtered_df) > 0:
                csv_to_use = filtered_csv_file
                logger.info("Main output file missing. Falling back to filtered output file: %s", csv_to_use)
            else:
                logger.info("Filtered output file is empty. Main output file is still expected at: %s", csv_to_use)
        except Exception:
            logger.info("Error checking filtered output file. Main output file is still expected at: %s", csv_to_use)
    else:
        logger.info("No filtered file found. Using main output file: %s", csv_to_use)

    if not os.path.exists(csv_to_use):
        logger.error("❌ No output CSV file found to package: %s", csv_to_use)
        return

    # --- Convert the final CSV into the required submission Excel schema ---
    try:
        df_final_output = pd.read_csv(csv_to_use, dtype=str, keep_default_na=False)
        df_final_output = df_final_output.replace(r"^\s*$", "NA", regex=True)

        def _mapped_series(source_name: str) -> pd.Series:
            if source_name in df_final_output.columns:
                return df_final_output[source_name].astype(str).replace(r"^\s*$", "NA", regex=True)
            return pd.Series(["NA"] * len(df_final_output), dtype="string")

        def _relative_evidence_path(value: str) -> str:
            text = str(value or "").strip()
            if not text or text.upper() == "NA":
                return "NA"
            file_name = os.path.basename(text.replace("\\", "/"))
            return str(pathlib.PurePosixPath(evidence_folder_name, file_name))

        submission_df = pd.DataFrame(
            {
                "Identified Domain Name": _mapped_series("Identified Phishing/Suspected Domain Name"),
                "Corresponding CSE Name": _mapped_series("Corresponding CSE Domain Name"),
                "IP Address": _mapped_series("Hosting IP"),
                "Hosting ISP": _mapped_series("Hosting ISP"),
                "Hosting Country": _mapped_series("Hosting Country"),
                "Registrant Name": _mapped_series("Registrant Name or Registrant Organisation"),
                "Registrant Country": _mapped_series("Registrant Country"),
                "Name Servers": _mapped_series("Name Servers"),
                "Evidence File Path": _mapped_series("Evidence file name").map(_relative_evidence_path),
                "Source of Detection": _mapped_series("Source of detection"),
                "Remarks": _mapped_series("Remarks"),
                "Phishing (Yes)": _mapped_series("Phishing/Suspected Domains (i.e. Class Label)"),
            },
            columns=[
                "Identified Domain Name",
                "Corresponding CSE Name",
                "IP Address",
                "Hosting ISP",
                "Hosting Country",
                "Registrant Name",
                "Registrant Country",
                "Name Servers",
                "Evidence File Path",
                "Source of Detection",
                "Remarks",
                "Phishing (Yes)",
            ],
        )
        submission_df = submission_df.replace(r"^\s*$", "NA", regex=True)
        submission_df.to_excel(local_excel_path, index=False)
        logger.info("✅ Converted final output CSV to %s", excel_file_name)
    except Exception as e:
        logger.error("❌ Failed to create Excel file: %s", e)
        return

    # --- Create the new ZIP file with the correct structure ---
    files_added_count = 0
    # Note: zip_path is now created in the *output* directory
    output_dir = os.path.join(ROOT_DIR, "output")
    os.makedirs(output_dir, exist_ok=True)
    zip_path_full = os.path.join(output_dir, os.path.basename(zip_path))
    submission_dir_full = os.path.join(output_dir, submission_root_folder)
    if os.path.isdir(submission_dir_full):
        shutil.rmtree(submission_dir_full, ignore_errors=True)
    os.makedirs(submission_dir_full, exist_ok=True)
    submission_evidence_dir = os.path.join(submission_dir_full, evidence_folder_name)
    os.makedirs(submission_evidence_dir, exist_ok=True)
    
    with zipfile.ZipFile(zip_path_full, 'w', zipfile.ZIP_DEFLATED) as zipf:
        
        # 1) Add the Evidence folder and all its contents
        if os.path.exists(EVIDENCE_DIR):
            for root, _, files in os.walk(EVIDENCE_DIR):
                for file in files:
                    filepath = os.path.join(root, file)
                    # Arcname places it inside the new structure
                    arcname = os.path.join(submission_root_folder, evidence_folder_name, file)
                    zipf.write(filepath, arcname)
                    shutil.copy2(filepath, os.path.join(submission_evidence_dir, file))
                    files_added_count += 1
            logger.info("Added %d evidence files.", files_added_count)
        else:
            logger.warning("Evidence directory not found. Skipping: %s", EVIDENCE_DIR)

        # 2) Add the new Excel file to the Documentation folder
        if os.path.exists(local_excel_path):
            #arcname = os.path.join(submission_root_folder, documentation_folder_name, excel_file_name)
            arcname = os.path.join(submission_root_folder, excel_file_name)
            zipf.write(local_excel_path, arcname)
            shutil.copy2(local_excel_path, os.path.join(submission_dir_full, excel_file_name))
            files_added_count += 1
            logger.info("Added final Excel sheet.")
        else:
            logger.error("❌ Could not find temporary Excel file to add: %s", local_excel_path)
            
    # --- Clean up the temporary Excel file we created ---
    try:
        os.remove(local_excel_path)
        logger.info("🗑 Removed temporary Excel file: %s", local_excel_path)
    except Exception as e:
        logger.warning("⚠ Could not remove temporary Excel file: %s", e)

    logger.info("📦 Packaged results into %s. Files included: %d", zip_path_full, files_added_count)

    # --- Call the existing cleanup function ---
    # This will remove all the intermediate .csv, /screens, and /evidence folders
    # try:
    #     cleanup_generated_artifacts(zip_path=zip_path_full)
    # except Exception as e:
    #     logger.warning("⚠ Cleanup after packaging failed: %s", e)

    return zip_path_full


# def cleanup_generated_artifacts(root_dir=None, zip_path="PS-02_ISS_NLP_Submission.zip"):
#     """
#     Cleans up all intermediate files (CSVs, screenshots, evidence)
#     after the final zip has been created.
#     """
#     import os, shutil, pathlib
#     
#     if root_dir is None:
#         root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")) # project root
#     logger.info("🧹 Cleaning generated artifacts in %s (preserving code & models)...", root_dir)
#
#     project_root = pathlib.Path(root_dir)
#     zip_path_abs = pathlib.Path(zip_path).resolve() # Use absolute path for comparison
#
#     # List of files/folders to delete
#     # Note: We do *not* delete *.xlsx files, only the temporary one.
#     patterns_to_delete = [
#         "*.csv", # Deletes holdout.csv, features.csv, etc. from pipeline and root
#     ]
#     
#     folders_to_delete = [
#         SCREENS_DIR,  # The screenshot folder
#         EVIDENCE_DIR, # The evidence folder
#     ]
#
#     # Delete matching files in root and phishing_pipeline folder
#     for pattern in patterns_to_delete:
#         for p in project_root.glob(pattern):
#             if p.is_file() and p.resolve() != zip_path_abs:
#                 try:
#                     p.unlink()
#                     logger.info("🗑 Deleted file: %s", p)
#                 except Exception as e:
#                     logger.debug("Could not delete file: %s (%s)", p, e)
#         
#         for p in (project_root / "phishing_pipeline").glob(pattern):
#              if p.is_file() and p.resolve() != zip_path_abs:
#                 try:
#                     p.unlink()
#                     logger.info("🗑 Deleted file: %s", p)
#                 except Exception as e:
#                     logger.debug("Could not delete file: %s (%s)", p, e)
#
#     # Delete directories
#     for dir_path_str in folders_to_delete:
#         dir_path = pathlib.Path(dir_path_str)
#             
#         if dir_path.exists() and dir_path.is_dir():
#             try:
#                 shutil.rmtree(dir_path)
#                 logger.info("🗑 Removed folder: %s", dir_path)
#             except Exception as e:
#                 logger.warning("Could not remove folder: %s (%s)", dir_path, e)
#
#     logger.info("✅ Cleanup complete. Kept code, models, and final zip: %s", zip_path)


# -------------------- Main entry point --------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the phishing pipeline (pipeline.py).")
    parser.add_argument("holdout_folder",
                        help="Folder where CSVs will be read/written (pass '.' for current dir)")
    parser.add_argument("ps02_whitelist_file",
                        help="Path to PS-02 whitelist Excel file (e.g. PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx)")
    parser.add_argument("--limit", type=int, default=None,
                        help="Optional: limit how many whitelisted rows to process (for testing)")
    parser.add_argument("--target-limit", type=int, default=None,
                        help="Optional: limit how many target URLs are loaded before hashing shortlist generation")
    parser.add_argument("--use-existing-holdout", action="store_true",
                        help="If set and holdout.csv exists, reuse it instead of regenerating.")
    parser.add_argument("--pipeline-mode", choices=["hash_only", "legacy_ocr"], default="hash_only",
                        help="Run hash-only architecture (default) or legacy OCR pipeline.")
    parser.add_argument("--high-confidence-threshold", type=float, default=78.0,
                        help="Hash score threshold for High confidence band (default=78.0).")
    parser.add_argument("--medium-confidence-threshold", type=float, default=68.0,
                        help="Hash score threshold for Medium confidence band (default=68.0).")
    
    # ---
    # --- FIX 2: Corrected 'addD-argument' to 'add_argument'
    # ---
    parser.add_argument("--package-results", action="store_true",
                        help="If set, package filtered results + evidence into a zip after pipeline finishes.")
    # --- (End of Fix 2) ---
    
    args = parser.parse_args()

    # Run the pipeline async
    try:
        if sys.platform.startswith("win"):
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        # We wrap the call and cleanup
        async def main_wrapper():
            try:
                await run_pipeline(args.holdout_folder, args.ps02_whitelist_file,
                                   limit_whitelisted=args.limit,
                                   limit_target_urls=args.target_limit,
                                   use_existing_holdout=args.use_existing_holdout,
                                   pipeline_mode=args.pipeline_mode,
                                   high_confidence_threshold=args.high_confidence_threshold,
                                   medium_confidence_threshold=args.medium_confidence_threshold)
            finally:
                # Use the new async closer
                from .visual_features import close_browser_async
                await close_browser_async()
                # Also verify sync browser is closed just in case
                close_browser()
                
        asyncio.run(main_wrapper())
    except KeyboardInterrupt:
        logger.info("Pipeline stopped by user.")
    except Exception as e:
        logger.error("Pipeline failed: %s", e)

    # Optionally package results
    if args.package_results:
        input_name = os.path.basename(os.path.normpath(args.holdout_folder))
        zip_path = package_results(zip_path=f"Submission-{input_name}.zip")
        logger.info("Packaged results into %s", zip_path)
