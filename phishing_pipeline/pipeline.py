import sys, asyncio, re, os, socket, whois, dns.resolver, logging, time
import httpx
import pandas as pd
import tldextract
from tqdm.asyncio import tqdm
from datetime import datetime
from dateutil import parser
import warnings
from urllib.parse import urlparse
from fpdf import FPDF

# NEW: visual analysis imports
import cv2, imagehash
import numpy as np
from PIL import Image
# We have REMOVED pytesseract, as it's no longer used.
# EasyOCR in visual_features.py handles all text extraction now.

from .config import (
    FEATURES_CSV, FEATURES_ENRICH, FINAL_OUTPUT,
    ASN_DB_PATH, CITY_DB_PATH, SCREENS_DIR,
    EVIDENCE_DIR, APPLICATION_ID
)
from .utils import extract_all_features_async
from .visual_features import close_browser
from .geoip_utils import enrich_with_geoip
from .model_utils import load_models_and_preproc
from .shortlisting import generate_shortlisted_csv
from .rate_limiter import RateLimiter
from .utils import (
    MAX_CONCURRENT_RDAP, MAX_CONCURRENT_WHOIS, MAX_CONCURRENT_DNS_PREFILTER,
    _get_rdap_semaphore, _get_whois_semaphore, _get_dns_prefilter_semaphore,
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
# --- (End of Fix 1) ---

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
# Feature extraction (Chunked Processing for GPU Safety)
# ------------------------------------------------------------------
CHUNK_SIZE = 200  # Process 50 domains at a time (tune for your system)

async def process_urls(input_csv, output_csv=FEATURES_CSV, network_semaphore=None):
    """
    Extract features using Chunked Processing Pipeline.
    
    Processes domains in chunks to prevent GPU memory fragmentation and OOM errors.
    Each chunk: Network + Screenshots in parallel, then OCR sequentially.
    """
    import csv
    import gc
    import torch
    from .utils import extract_network_features_async, extract_visual_features_async
    
    df = pd.read_csv(input_csv)
    total_domains = len(df)
    logger.info("⚙️ Starting Chunked Pipeline for %d domains (chunk size: %d)...", total_domains, CHUNK_SIZE)
    
    if df.empty:
        with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
            pass
        return output_csv
    
    # Use provided semaphore or create new one
    if network_semaphore is None:
        network_semaphore = asyncio.Semaphore(50)
    
    # Convert DataFrame to list of dicts for chunking
    rows = df.to_dict('records')
    total_chunks = (total_domains + CHUNK_SIZE - 1) // CHUNK_SIZE
    
    # Open output file for writing
    all_results = []
    
    # Progress bar for chunks
    with tqdm(total=total_domains, desc="🌐 Phase 1: Features", unit="domain", 
              bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
        
        for chunk_idx in range(total_chunks):
            start = chunk_idx * CHUNK_SIZE
            end = min(start + CHUNK_SIZE, total_domains)
            chunk_rows = rows[start:end]
            
            logger.info(f"📦 Processing chunk {chunk_idx + 1}/{total_chunks} ({len(chunk_rows)} domains)")
            
            # ============ STAGE A: Network + Screenshots in PARALLEL ============
            async def process_single_domain(row):
                domain = row["Identified Phishing/Suspected Domain Name"]
                
                # Network features (fast, CPU)
                try:
                    net_feats = await extract_network_features_async(domain, network_semaphore)
                except Exception as e:
                    logger.error(f"Network failed for {domain}: {e}")
                    net_feats = {}
                
                # Visual features (screenshot + OCR + branding)
                try:
                    vis_feats, _ = await extract_visual_features_async(domain)
                except Exception as e:
                    logger.error(f"Visual failed for {domain}: {e}")
                    vis_feats = {}
                
                # Merge results
                final_url = vis_feats.get("url", domain)
                return {
                    "Cooresponding CSE": row.get("Cooresponding CSE", ""),
                    "Legitimate Domains": row.get("Legitimate Domains", ""),
                    **net_feats,
                    **vis_feats,
                    "url": final_url
                }
            
            # Process all domains in this chunk
            chunk_tasks = [process_single_domain(row) for row in chunk_rows]
            chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
            
            # Filter out exceptions and collect valid results
            for result in chunk_results:
                if isinstance(result, Exception):
                    logger.error(f"Chunk domain error: {result}")
                else:
                    all_results.append(result)
            
            pbar.update(len(chunk_rows))
            
            # ============ GPU CLEANUP BETWEEN CHUNKS ============
            try:
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                gc.collect()
                logger.debug(f"🧹 GPU cleanup after chunk {chunk_idx + 1}")
            except Exception:
                pass
    
    # Write all results to CSV
    if all_results:
        with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_results[0].keys()))
            writer.writeheader()
            writer.writerows(all_results)
    else:
        with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
            pass
    
    logger.info(f"✅ Phase 1 complete: {len(all_results)} domains processed")
    return output_csv

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
def reclassify_label(domain, registrar, host, dns, ocr_text_from_csv):
    """
    Re-classifies the label using heuristics.
    NOTE: This function NO LONGER uses pytesseract. It uses the
    'ocr_text_from_csv' which was generated by EasyOCR.
    """
    reg = str(registrar).lower()
    hst = str(host).lower()
    dns_str = str(dns).lower()
    dom = str(domain).lower()
    ocr_text = str(ocr_text_from_csv).lower() # Use the text from the CSV
    
    ssl_present = "ssl" in dns_str or "tls" in dns_str
    
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

# ------------------------------------------------------------------
# Pipeline runner
# ------------------------------------------------------------------
async def run_pipeline(holdout_folder, ps02_whitelist_file, limit_whitelisted=None, use_existing_holdout=False):
    import time
    from tqdm import tqdm as tqdm_sync
    
    start_time = time.time()
    logger.info("🚀 Starting pipeline...")
    
    # Initialize semaphores here to be shared with process_urls
    network_semaphore = asyncio.Semaphore(50)
    
    # Rate limiter: 20 requests per minute = 1 request every 3 seconds
    whois_rate_limiter = RateLimiter(requests_per_minute=20)
    
    # ROOT_DIR is now defined at the top of the file
    
    # --- This is your new output file ---
    holdout_csv_path = os.path.join(ROOT_DIR, "holdout.csv")

    if not use_existing_holdout or not os.path.exists(holdout_csv_path):
        logger.info("Generating new holdout.csv...")
        holdout_csv_path = generate_shortlisted_csv(
            holdout_folder=holdout_folder,
            ps02_whitelist_file=ps02_whitelist_file,
            limit_whitelisted=limit_whitelisted
        )
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

    # --- Use the new column name ---
    df_filtered = df_holdout[df_holdout["Legitimate Domains"].isin(ps02_df["Legitimate Domains"])]
    
    # Define a temp file path inside the phishing_pipeline folder
    temp_csv_path = os.path.join(os.path.dirname(__file__), "holdout_temp.csv")
    df_filtered.to_csv(temp_csv_path, index=False, encoding="utf-8")
    
    total_domains = len(df_filtered)
    
    # ================== MASTER PROGRESS TRACKER ==================
    print("\n" + "="*70)
    print(f"📊 PIPELINE OVERVIEW: {total_domains} domains")
    print("="*70)
    print("  Phase 1: Feature Extraction (Network + Screenshots + OCR)")
    print("  Phase 2: WHOIS Lookup & Classification")
    print("  Phase 3: Evidence Generation & Export")
    print("="*70 + "\n")
    
    master_pbar = tqdm_sync(
        total=100,
        desc="🔄 Overall Progress",
        unit="%",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}% [{elapsed}<{remaining}]",
        position=0
    )
    
    # ================== PHASE 1: Feature Extraction (60% of total work) ==================
    logger.info("\n" + "="*60)
    logger.info("📊 PHASE 1: Feature Extraction")
    logger.info("="*60)
    
    phase1_start = time.time()
    await process_urls(temp_csv_path, FEATURES_CSV, network_semaphore)
    df_features = pd.read_csv(FEATURES_CSV)
    df_features = enrich_with_geoip(df_features, ASN_DB_PATH, CITY_DB_PATH)
    df_features.to_csv(FEATURES_ENRICH, index=False, encoding="utf-8")
    phase1_time = time.time() - phase1_start
    
    master_pbar.update(60)  # Phase 1 = 60% of work
    logger.info("✅ Phase 1 Complete: %d domains in %.1f seconds", len(df_features), phase1_time)

    # ---------------- Load models ----------------
    model_label, model_source, le_label, source_classes, feature_cols, scaler, imputer = load_models_and_preproc()

    # ---------------- Numeric features ----------------
    # Fill NaN in ocr_text before selection, just in case
    df_features['ocr_text'] = df_features['ocr_text'].fillna("")
    
    X_num = df_features.reindex(columns=feature_cols, fill_value=0)
    X_num_imputed = imputer.transform(X_num)
    X_num_scaled = scaler.transform(X_num_imputed)

    # ---------------- Text TF-IDF features (if you had them) ----------------
    # (Assuming no TF-IDF based on your model_utils.py)
    X_all = X_num_scaled

    # ---------------- Predict labels ----------------
    # We still need to *predict* the label to use it, even if we don't save it.
    y_pred_label = model_label.predict(X_all)
    predicted_labels = le_label.inverse_transform(y_pred_label)
    # df_features["Predicted Label"] = predicted_labels # We no longer save this

    # ---------------- Predict sources ----------------
    y_pred_source = model_source.predict(X_all)
    predicted_sources = [source_classes[i] for i in y_pred_source]
    df_features["Predicted Source"] = predicted_sources

    # ---------------- Adjust sources (heuristic) ----------------
    adjusted_sources = [
        adjust_source(org, dom, ml_source)
        # --- Use the new column names ---
        for org, dom, ml_source in zip(df_features["Cooresponding CSE"], df_features["Legitimate Domains"], df_features["Predicted Source"])
    ]

    # ================== PHASE 2: WHOIS & Classification (35% of total work) ==================
    phase2_start = time.time()
    logger.info("\n" + "="*60)
    logger.info("📊 PHASE 2: WHOIS & Classification (3-Pass Parallel)")
    logger.info("="*60)
    
    records = []
    rdap_times = []   # Track RDAP lookup durations
    whois_times = []  # Track WHOIS fallback durations
    total_domains = len(df_features)

    # --- Build host list from feature URLs ---
    host_list = []
    for idx, row in df_features.iterrows():
        domain_url = row["url"]
        host = urlparse(domain_url).hostname or domain_url
        host = host.split(':')[0]
        host_list.append(host)

    # ======================== PASS 0: DNS Pre-filter ========================
    logger.info("🔍 Pass 0: DNS Pre-filter (%d domains, concurrency=%d)...",
                total_domains, MAX_CONCURRENT_DNS_PREFILTER)
    dns_start = time.time()
    dns_sem = _get_dns_prefilter_semaphore()

    async def _dns_check(host):
        """Quick DNS resolution check. Returns (host, ip_or_None)."""
        async with dns_sem:
            try:
                loop = asyncio.get_running_loop()
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, host),
                    timeout=3.0
                )
                return host, ip
            except Exception:
                return host, None

    dns_results = await asyncio.gather(*[_dns_check(h) for h in host_list])
    dns_map = {host: ip for host, ip in dns_results}  # host → ip or None
    live_hosts = {h for h, ip in dns_map.items() if ip is not None}
    dead_hosts = {h for h, ip in dns_map.items() if ip is None}
    dns_time = time.time() - dns_start
    logger.info("   ✅ DNS done in %.1fs: %d live, %d dead (skipped)",
                dns_time, len(live_hosts), len(dead_hosts))

    # ======================== PASS 1: RDAP Batch ========================
    # Only query live hosts; use direct RDAP URLs to bypass rdap.org rate limit
    rdap_targets = [h for h in host_list if h in live_hosts]
    logger.info("⚡ Pass 1: RDAP Batch (%d domains, concurrency=%d)...",
                len(rdap_targets), MAX_CONCURRENT_RDAP)
    rdap_start = time.time()
    rdap_sem = _get_rdap_semaphore()
    rdap_results = {}  # host → dict of reg data
    rdap_failures = []  # hosts that need WHOIS fallback

    def _get_rdap_url(host):
        """Map host to direct authoritative RDAP URL."""
        ext = tldextract.extract(host)
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""
        return RDAP_DIRECT_URLS.get(tld, RDAP_FALLBACK_URL)

    async def _rdap_one(host, client):
        """Single RDAP lookup with semaphore control."""
        async with rdap_sem:
            start = time.time()
            try:
                base_url = _get_rdap_url(host)
                resp = await client.get(f"{base_url}{host}")
                if resp.status_code == 200:
                    data = resp.json()
                    result = _parse_rdap_to_fields(data)
                    duration = time.time() - start
                    rdap_times.append(duration)
                    return host, result
                elif resp.status_code == 429:
                    logger.warning("⚠️ RDAP 429 for %s — rate limited", host)
                    return host, None
                else:
                    return host, None
            except Exception as e:
                logger.debug("RDAP failed for %s: %s", host, e)
                return host, None

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as rdap_client:
        rdap_tasks = [_rdap_one(h, rdap_client) for h in rdap_targets]
        rdap_raw = await asyncio.gather(*rdap_tasks, return_exceptions=True)

    for item in rdap_raw:
        if isinstance(item, Exception):
            continue
        host, data = item
        if data:
            rdap_results[host] = data
        else:
            rdap_failures.append(host)

    rdap_time = time.time() - rdap_start
    logger.info("   ✅ RDAP done in %.1fs: %d success, %d need WHOIS",
                rdap_time, len(rdap_results), len(rdap_failures))

    # ======================== PASS 2: WHOIS Fallback ========================
    logger.info("🐢 Pass 2: WHOIS Fallback (%d domains, concurrency=%d)...",
                len(rdap_failures), MAX_CONCURRENT_WHOIS)
    whois_start_time = time.time()
    whois_sem = _get_whois_semaphore()
    whois_results = {}  # host → dict of reg data

    async def _whois_one(host):
        """Single WHOIS lookup with semaphore + rate limiter."""
        async with whois_sem:
            await whois_rate_limiter.acquire()
            start = time.time()
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    loop = asyncio.get_running_loop()
                    w = await asyncio.wait_for(
                        loop.run_in_executor(None, whois.whois, host),
                        timeout=15
                    )
                    if w:
                        result = {}
                        creation_date = w.creation_date
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        result["reg_date"] = str(creation_date) if creation_date else "NA"
                        result["registrar"] = w.registrar or "NA"
                        result["registrant_name"] = w.name or w.org or getattr(w, 'registrant_name', None) or "NA"
                        result["registrant_country"] = w.country or "NA"
                        if w.name_servers:
                            result["name_servers"] = ";".join(str(ns) for ns in w.name_servers)
                        else:
                            result["name_servers"] = "NA"
                        duration = time.time() - start
                        whois_times.append(duration)
                        return host, result
                except asyncio.TimeoutError:
                    logger.warning("⚠️ WHOIS timeout for %s (attempt %d/%d)", host, attempt+1, max_retries)
                except Exception as e:
                    logger.warning("⚠️ WHOIS failed for %s: %s (attempt %d/%d)", host, e, attempt+1, max_retries)
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
            return host, None

    whois_tasks = [_whois_one(h) for h in rdap_failures]
    whois_raw = await asyncio.gather(*whois_tasks, return_exceptions=True)

    for item in whois_raw:
        if isinstance(item, Exception):
            continue
        host, data = item
        if data:
            whois_results[host] = data

    whois_time = time.time() - whois_start_time
    logger.info("   ✅ WHOIS done in %.1fs: %d success, %d failed",
                whois_time, len(whois_results), len(rdap_failures) - len(whois_results))

    # ======================== Merge results into records ========================
    from tqdm import tqdm as tqdm_sync
    with tqdm_sync(total=total_domains, desc="📝 Building Records", unit="domain",
                   bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as rec_pbar:
        for idx, row in df_features.iterrows():
            domain_url = row["url"]
            host = host_list[idx]

            # --- Defaults ---
            reg_date = "NA"
            registrar = "NA"
            registrant_name = "NA"
            registrant_country = "NA"
            name_servers = "NA"
            lookup_method = "NONE"

            # --- Pull from RDAP or WHOIS results ---
            if host in rdap_results:
                d = rdap_results[host]
                lookup_method = "RDAP"
                reg_date = d.get("reg_date", "NA")
                registrar = d.get("registrar", "NA")
                registrant_name = d.get("registrant_name", "NA")
                registrant_country = d.get("registrant_country", "NA")
                name_servers = d.get("name_servers", "NA")
            elif host in whois_results:
                d = whois_results[host]
                lookup_method = "WHOIS"
                reg_date = d.get("reg_date", "NA")
                registrar = d.get("registrar", "NA")
                registrant_name = d.get("registrant_name", "NA")
                registrant_country = d.get("registrant_country", "NA")
                name_servers = d.get("name_servers", "NA")

            # --- IP (from DNS pre-filter or features) ---
            ip = "NA"
            ip_from_features = row.get("ip_address", None)
            if ip_from_features and not pd.isna(ip_from_features):
                ip = str(ip_from_features)
            elif dns_map.get(host):
                ip = dns_map[host]

            # --- DNS records lookup ---
            dns_records = "NA"
            try:
                dns_recs = []
                if host and host in live_hosts:
                    for qtype in ["A", "NS", "MX", "CNAME"]:
                        try:
                            answers = dns.resolver.resolve(host, qtype, lifetime=3)
                            dns_recs.extend([f"{qtype}:{r.to_text()}" for r in answers])
                        except:
                            pass
                if dns_recs:
                    dns_records = ";".join(dns_recs)
            except Exception as e:
                logger.debug("DNS lookup failed for %s: %s", host, e)

            # --- GeoIP/ISP lookup (from features file) ---
            hosting_isp = "NA"
            hosting_country = "NA"
            isp_from_features = row.get("asn_org", None)
            if isp_from_features and not pd.isna(isp_from_features):
                hosting_isp = str(isp_from_features)
            country_from_features = row.get("country", None)
            if country_from_features and not pd.isna(country_from_features):
                hosting_country = str(country_from_features)

            # --- Evidence and screenshot ---
            evidence_path, evidence_name = format_evidence_filename(
                row["Cooresponding CSE"], domain_url, idx+1, application_id=APPLICATION_ID
            )
            move_screenshot_to_evidence(domain_url, evidence_path)

            # --- Classification ---
            ocr_text_from_csv = row.get("ocr_text", "")
            classification = reclassify_label(
                domain_url, registrar, hosting_isp, dns_records, ocr_text_from_csv
            )

            detection_date = datetime.now().strftime("%d-%m-%Y")
            detection_time = datetime.now().strftime("%H:%M:%S")

            records.append({
                "Application_ID": APPLICATION_ID,
                "Source of detection": adjusted_sources[idx],
                "Identified Phishing/Suspected Domain Name": domain_url,
                "Corresponding CSE Domain Name": row["Legitimate Domains"],
                "Critical Sector Entity Name": row["Cooresponding CSE"],
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
                "Time of detection (HH-MM-SS)": detection_time,
                "Date of Post (If detection is from Source: social media)": "NA",
                "Remarks": "NA values are due to privacy issues."
            })
            rec_pbar.update(1)

    phase2_time = time.time() - phase2_start
    master_pbar.update(35)  # Phase 2 = 35% of work
    logger.info("✅ Phase 2 Complete: %d records in %.1f seconds", len(records), phase2_time)
    
    # --- Speed summary ---
    rdap_count = len(rdap_times)
    whois_count = len(whois_times)
    failed_count = total_domains - rdap_count - whois_count
    rdap_avg = sum(rdap_times) / rdap_count if rdap_times else 0
    whois_avg = sum(whois_times) / len(whois_times) if whois_times else 0
    logger.info("")
    logger.info("📊 Lookup Speed Summary (3-Pass Parallel):")
    logger.info("   🏓 DNS Pre-filter:  %.1fs (%d live, %d dead)", dns_time, len(live_hosts), len(dead_hosts))
    logger.info("   ⚡ RDAP Batch:      %.1fs, %d domains, avg %.2fs/domain", rdap_time, rdap_count, rdap_avg)
    logger.info("   🐢 WHOIS Fallback:  %.1fs, %d domains, avg %.2fs/domain", whois_time, whois_count, whois_avg)
    logger.info("   ❌ Total Failed:    %d domains", failed_count)
    logger.info("   ⏱️  Phase 2 Total:   %.1fs", phase2_time)
    logger.info("")
    
    df_out = pd.DataFrame(records)
    # Save to CSV
    df_out.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
    logger.info("✅ Final output written to %s", FINAL_OUTPUT)

    # ---------------- Filtering step ----------------
    start = datetime(2025, 10, 1).date()
    end   = datetime(2025, 10, 15).date()

    def parse_date(val):
        if not val or pd.isna(val) or val == "NA":
            return None
        try:
            dt = parser.parse(str(val), fuzzy=True)
            return dt.date()
        except:
            return None

    df_temp = df_out.copy()
    df_temp["_parsed_reg_date"] = df_temp["Domain Registration Date"].apply(parse_date)
    mask = df_temp["_parsed_reg_date"].notna() & df_temp["_parsed_reg_date"].between(start, end)
    df_filtered = df_temp.loc[mask].drop(columns=["_parsed_reg_date"])
    
    # --- Ensure we use the new column order for the filtered file as well ---
    if not df_filtered.empty:
        # Get column order from the *full* output dataframe
        df_filtered = df_filtered[df_out.columns] 

    filtered_path = FINAL_OUTPUT.replace(".csv", "_filtered.csv")
    df_filtered.to_csv(filtered_path, index=False, encoding="utf-8")

    logger.info("✅ Filtered %d domains registered between %s and %s",
                len(df_filtered), start.isoformat(), end.isoformat())
    logger.info("📄 Filtered output written to %s", filtered_path)

    # Remove the temporary holdout_temp.csv file
    try:
        os.remove(temp_csv_path)
        logger.info("🗑 Removed temporary file: %s", temp_csv_path)
    except Exception as e:
        logger.warning("⚠ Could not remove temporary file: %s", e)

    # Final progress update and timing
    master_pbar.update(5)  # Phase 3 (filtering/cleanup) = 5%
    master_pbar.close()
    
    total_time = time.time() - start_time
    print("\n" + "="*70)
    print(f"✅ PIPELINE COMPLETE")
    print(f"   Total domains: {total_domains}")
    print(f"   Total time: {total_time/60:.1f} minutes ({total_time:.0f} seconds)")
    print(f"   Average: {total_time/total_domains:.2f} seconds/domain")
    print("="*70 + "\n")
    
    return df_out
    
    # Note: run_pipeline does NOT close the browser context automatically here anymore
    # because we might want to keep it open? No, we should close it.
    # actually better to do it in the finally block of the caller or here.
    # close_browser() will be called by the outer wrapper.

# ------------------------------------------------------------------
# Package results
# ------------------------------------------------------------------
def package_results(output_file=FINAL_OUTPUT, zip_path="PS-02_ISS_NLP_Submission.zip"):
    """
    Packages the final output Excel file and the evidence folder into
    a zip file matching the required submission structure.
    """
    import zipfile, os, pathlib
    
    # --- Define the paths for the new zip structure ---
    submission_root_folder = "PS-02_ISS_NLP_Submission"
    documentation_folder_name = "PS-02_ISS_NLP_Documentation"
    excel_file_name = "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
    
    # Get the evidence folder name from config (e.g., "PS-02_ISS_NLP_Evidences")
    evidence_folder_name = os.path.basename(EVIDENCE_DIR)
    
    # Define the *local* path for the temporary Excel file we will create
    # We'll save it in the same directory as this script (phishing_pipeline/)
    local_excel_path = os.path.join(BASE_DIR, excel_file_name)
    
    # --- Find which CSV to use (filtered or main) ---
    filtered_csv_file = output_file.replace(".csv", "_filtered.csv")
    csv_to_use = None
    
    if os.path.exists(filtered_csv_file):
        try:
            df_check = pd.read_csv(filtered_csv_file)
            if len(df_check) > 0:
                csv_to_use = filtered_csv_file
                logger.info("Using filtered output file: %s", csv_to_use)
            else:
                csv_to_use = output_file
                logger.info("Filtered file is empty. Using main output file: %s", csv_to_use)
        except Exception:
            csv_to_use = output_file
            logger.info("Error checking filtered file. Using main output file: %s", csv_to_use)
    else:
        csv_to_use = output_file
        logger.info("No filtered file found. Using main output file: %s", csv_to_use)

    if not os.path.exists(csv_to_use):
        logger.error("❌ No output CSV file found to package: %s", csv_to_use)
        return

    # --- Convert the final CSV to the new Excel file ---
    try:
        df_final_output = pd.read_csv(csv_to_use)
        
        # --- NEW: Fill any remaining NaNs with "NA" before saving to Excel ---
        # This is a final safeguard.
        df_final_output.fillna("NA", inplace=True)
        
        df_final_output.to_excel(local_excel_path, index=False)
        logger.info("✅ Converted final output CSV to %s", excel_file_name)
    except Exception as e:
        logger.error("❌ Failed to create Excel file: %s", e)
        return

    # --- Create the new ZIP file with the correct structure ---
    files_added_count = 0
    # Note: zip_path is now created in the *root* directory
    zip_path_full = os.path.join(ROOT_DIR, zip_path) 
    
    with zipfile.ZipFile(zip_path_full, 'w', zipfile.ZIP_DEFLATED) as zipf:
        
        # 1) Add the Evidence folder and all its contents
        if os.path.exists(EVIDENCE_DIR):
            for root, _, files in os.walk(EVIDENCE_DIR):
                for file in files:
                    filepath = os.path.join(root, file)
                    # Arcname places it inside the new structure
                    arcname = os.path.join(submission_root_folder, evidence_folder_name, file)
                    zipf.write(filepath, arcname)
                    files_added_count += 1
            logger.info("Added %d evidence files.", files_added_count)
        else:
            logger.warning("Evidence directory not found. Skipping: %s", EVIDENCE_DIR)

        # 2) Add the new Excel file to the Documentation folder
        if os.path.exists(local_excel_path):
            #arcname = os.path.join(submission_root_folder, documentation_folder_name, excel_file_name)
            arcname = os.path.join(submission_root_folder, excel_file_name)
            zipf.write(local_excel_path, arcname)
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
    try:
        cleanup_generated_artifacts(zip_path=zip_path_full)
    except Exception as e:
        logger.warning("⚠ Cleanup after packaging failed: %s", e)

    return zip_path_full


def cleanup_generated_artifacts(root_dir=None, zip_path="PS-02_ISS_NLP_Submission.zip"):
    """
    Cleans up all intermediate files (CSVs, screenshots, evidence)
    after the final zip has been created.
    """
    import os, shutil, pathlib
    
    if root_dir is None:
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")) # project root
    logger.info("🧹 Cleaning generated artifacts in %s (preserving code & models)...", root_dir)

    project_root = pathlib.Path(root_dir)
    zip_path_abs = pathlib.Path(zip_path).resolve() # Use absolute path for comparison

    # List of files/folders to delete
    # Note: We do *not* delete *.xlsx files, only the temporary one.
    patterns_to_delete = [
        "*.csv", # Deletes holdout.csv, features.csv, etc. from pipeline and root
    ]
    
    folders_to_delete = [
        SCREENS_DIR,  # The screenshot folder
        EVIDENCE_DIR, # The evidence folder
    ]

    # Delete matching files in root and phishing_pipeline folder
    for pattern in patterns_to_delete:
        for p in project_root.glob(pattern):
            if p.is_file() and p.resolve() != zip_path_abs:
                try:
                    p.unlink()
                    logger.info("🗑 Deleted file: %s", p)
                except Exception as e:
                    logger.debug("Could not delete file: %s (%s)", p, e)
        
        for p in (project_root / "phishing_pipeline").glob(pattern):
             if p.is_file() and p.resolve() != zip_path_abs:
                try:
                    p.unlink()
                    logger.info("🗑 Deleted file: %s", p)
                except Exception as e:
                    logger.debug("Could not delete file: %s (%s)", p, e)

    # Delete directories
    for dir_path_str in folders_to_delete:
        dir_path = pathlib.Path(dir_path_str)
            
        if dir_path.exists() and dir_path.is_dir():
            try:
                shutil.rmtree(dir_path)
                logger.info("🗑 Removed folder: %s", dir_path)
            except Exception as e:
                logger.warning("Could not remove folder: %s (%s)", dir_path, e)

    logger.info("✅ Cleanup complete. Kept code, models, and final zip: %s", zip_path)


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
    parser.add_argument("--use-existing-holdout", action="store_true",
                        help="If set and holdout.csv exists, reuse it instead of regenerating.")
    
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
                                   limit_whitelisted=args.limit, use_existing_holdout=args.use_existing_holdout)
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
        zip_path = package_results()
        logger.info("Packaged results into %s", zip_path)