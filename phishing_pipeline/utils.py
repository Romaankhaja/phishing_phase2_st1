import os, re
import psutil
import tldextract
import numpy as np
import logging
import gc
from PIL import Image, ImageDraw
import sys, asyncio
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Resource management
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
 

from .config import ROOT_DIR, SCREENS_DIR, WHITELISTS_DIR
from .features import (
    extract_url_features,
    extract_subdomain_features,
    extract_path_features,
    entropy_features,
    ssl_features,
    get_ip_address,
)
from .visual_features import (
    capture_screenshot,
    capture_screenshot_async,
    branding_guidelines_features,
    extract_ocr_text,
    preprocess_image_for_ocr,   # Phase A: CPU image prep, lockless
    run_ocr_inference,           # Phase B: GPU inference, minimal lock hold
    extract_spatial_ocr_features,# Spatial zone segmentation (CPU-only post-process)
    laplacian_variance,
    get_favicon_features_async,
)

logger = logging.getLogger(__name__)

# ================== DYNAMIC RESOURCE ALLOCATION ==================
def _read_env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        logger.warning("Invalid integer override for %s=%r; using %d", name, raw, default)
        return default


def _get_optimal_concurrency():
    """
    Calculate runtime limits from the host profile.
    """
    cpu_cores = os.cpu_count() or 4
    ram_gb = psutil.virtual_memory().total / (1024**3)

    vram_gb = 0.0
    if TORCH_AVAILABLE and torch.cuda.is_available():
        try:
            vram_bytes = torch.cuda.get_device_properties(0).total_memory
            vram_gb = vram_bytes / (1024**3)
        except Exception:
            vram_gb = 0.0

    logger.info(
        "System Resources Detected: CPU=%d cores, RAM=%.1fGB, VRAM=%.1fGB",
        cpu_cores,
        ram_gb,
        vram_gb,
    )

    server_class = cpu_cores >= 32 and ram_gb >= 96

    if vram_gb > 0:
        if server_class and vram_gb >= 40.0:
            max_ocr = max(8, min(16, int(vram_gb / 6.0)))
        elif vram_gb < 6.0:
            max_ocr = 3
        else:
            max_ocr = max(1, min(12, int(vram_gb / 3.0)))
    else:
        max_ocr = max(2, min(8, int(cpu_cores / 2)))

    if server_class:
        max_screenshots = min(96, max(24, min(int(ram_gb / 2.5), cpu_cores * 2)))
        max_image_proc = min(192, cpu_cores * 3)
        max_cpu = min(768, cpu_cores * 12)
        max_rdap = min(48, max(16, cpu_cores))
        max_whois = min(8, max(3, cpu_cores // 8))
        max_dns_prefilter = min(768, max(256, cpu_cores * 8))
        network_limit = min(256, max(96, max_screenshots * 2))
        chunk_size = min(512, max(96, max_screenshots * 4))
    else:
        max_screenshots = min(32, max(1, min(int(ram_gb / 0.5), cpu_cores * 2)))
        max_image_proc = cpu_cores * 2
        max_cpu = cpu_cores * 10
        max_rdap = 15
        max_whois = 3
        max_dns_prefilter = 200
        network_limit = min(128, max(32, max_screenshots * 2))
        chunk_size = max(32, max_screenshots * 5)

    return {
        "ocr": _read_env_int("PHISHING_OCR_WORKERS", max_ocr),
        "screenshots": _read_env_int("PHISHING_SCREENSHOT_WORKERS", max_screenshots),
        "image_proc": _read_env_int("PHISHING_IMAGE_WORKERS", max_image_proc),
        "cpu": _read_env_int("PHISHING_CPU_TASKS", max_cpu),
        "chunk_size": _read_env_int("PHISHING_CHUNK_SIZE", chunk_size),
        "rdap": _read_env_int("PHISHING_RDAP_WORKERS", max_rdap),
        "whois": _read_env_int("PHISHING_WHOIS_WORKERS", max_whois),
        "dns_prefilter": _read_env_int("PHISHING_DNS_PREFILTER_WORKERS", max_dns_prefilter),
        "network": _read_env_int("PHISHING_NETWORK_SEMAPHORE", network_limit),
    }


_CONCURRENCY_PROFILE = _get_optimal_concurrency()

MAX_CONCURRENT_OCR = _CONCURRENCY_PROFILE["ocr"]
MAX_CONCURRENT_SCREENSHOTS = _CONCURRENCY_PROFILE["screenshots"]
MAX_CONCURRENT_IMAGE_PROCESSING = _CONCURRENCY_PROFILE["image_proc"]
MAX_CONCURRENT_CPU_TASKS = _CONCURRENCY_PROFILE["cpu"]
CHUNK_SIZE = _CONCURRENCY_PROFILE["chunk_size"]
MAX_CONCURRENT_RDAP = _CONCURRENCY_PROFILE["rdap"]
MAX_CONCURRENT_WHOIS = _CONCURRENCY_PROFILE["whois"]
MAX_CONCURRENT_DNS_PREFILTER = _CONCURRENCY_PROFILE["dns_prefilter"]
NETWORK_SEMAPHORE_LIMIT = _CONCURRENCY_PROFILE["network"]

logger.info(
    "Dynamic Concurrency Limits: OCR=%d, Screenshots=%d, ImgProc=%d, CPU=%d, RDAP=%d, WHOIS=%d, DNS=%d, Net=%d, CHUNK_SIZE=%d",
    MAX_CONCURRENT_OCR,
    MAX_CONCURRENT_SCREENSHOTS,
    MAX_CONCURRENT_IMAGE_PROCESSING,
    MAX_CONCURRENT_CPU_TASKS,
    MAX_CONCURRENT_RDAP,
    MAX_CONCURRENT_WHOIS,
    MAX_CONCURRENT_DNS_PREFILTER,
    NETWORK_SEMAPHORE_LIMIT,
    CHUNK_SIZE,
)

_ocr_semaphore: asyncio.Semaphore | None = None
_screenshot_semaphore: asyncio.Semaphore | None = None
_image_semaphore: asyncio.Semaphore | None = None
_cpu_semaphore: asyncio.Semaphore | None = None
_rdap_semaphore: asyncio.Semaphore | None = None
_whois_semaphore: asyncio.Semaphore | None = None
_dns_prefilter_semaphore: asyncio.Semaphore | None = None

def _get_ocr_semaphore() -> asyncio.Semaphore:
    global _ocr_semaphore
    if _ocr_semaphore is None:
        _ocr_semaphore = asyncio.Semaphore(MAX_CONCURRENT_OCR)
    return _ocr_semaphore

def _get_screenshot_semaphore() -> asyncio.Semaphore:
    global _screenshot_semaphore
    if _screenshot_semaphore is None:
        _screenshot_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCREENSHOTS)
    return _screenshot_semaphore

def _get_image_semaphore() -> asyncio.Semaphore:
    global _image_semaphore
    if _image_semaphore is None:
        _image_semaphore = asyncio.Semaphore(MAX_CONCURRENT_IMAGE_PROCESSING)
    return _image_semaphore

def _get_cpu_semaphore() -> asyncio.Semaphore:
    global _cpu_semaphore
    if _cpu_semaphore is None:
        _cpu_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CPU_TASKS)
    return _cpu_semaphore

def _get_rdap_semaphore() -> asyncio.Semaphore:
    global _rdap_semaphore
    if _rdap_semaphore is None:
        _rdap_semaphore = asyncio.Semaphore(MAX_CONCURRENT_RDAP)
    return _rdap_semaphore

def _get_whois_semaphore() -> asyncio.Semaphore:
    global _whois_semaphore
    if _whois_semaphore is None:
        _whois_semaphore = asyncio.Semaphore(MAX_CONCURRENT_WHOIS)
    return _whois_semaphore

def _get_dns_prefilter_semaphore() -> asyncio.Semaphore:
    global _dns_prefilter_semaphore
    if _dns_prefilter_semaphore is None:
        _dns_prefilter_semaphore = asyncio.Semaphore(MAX_CONCURRENT_DNS_PREFILTER)
    return _dns_prefilter_semaphore



# ================== VRAM-AWARE OCR GATE ==================

async def wait_for_vram(min_free_gb: float = 1.5, poll_interval: float = 0.5):
    """
    Block asynchronously until the GPU has at least `min_free_gb` of free VRAM.
    Used by Stage 2 OCR workers in the two-stage pipeline to prevent OOM.
    Falls through instantly if CUDA is not available (CPU-only mode).
    """
    if not TORCH_AVAILABLE:
        return
    try:
        import torch
        if not torch.cuda.is_available():
            return
        while True:
            free_bytes, total_bytes = torch.cuda.mem_get_info()
            free_gb = free_bytes / (1024 ** 3)
            if free_gb >= min_free_gb:
                return
            logger.debug(
                "[VRAM Gate] Only %.2fGB free (need %.1fGB). Waiting...",
                free_gb, min_free_gb
            )
            torch.cuda.empty_cache()
            gc.collect()
            await asyncio.sleep(poll_interval)
    except Exception as e:
        logger.warning("wait_for_vram check failed: %s â€” proceeding anyway", e)

# ================== RESOURCE MONITOR SINGLETON ==================
# Imported here so pipeline.py can use it without a separate import chain.
from .resource_manager import ResourceMonitor
_resource_monitor = ResourceMonitor()

def cleanup_gpu_cache():
    if TORCH_AVAILABLE:
        try:
            torch.cuda.empty_cache()
            logger.debug("GPU cache cleared")
        except Exception as e:
            logger.warning("Failed to clear GPU cache: %s", e)
    gc.collect()
    logger.debug("Python garbage collection executed")

def ensure_dirs():
    os.makedirs(SCREENS_DIR, exist_ok=True)

def extract_all_features(url: str, csv_file: str | None = None) -> tuple:
    """
    Extract all features (URL, visual, cryptographic) from a single URL (sync).
    
    This is the synchronous version - good for single URL processing.
    For batch processing, use extract_all_features_async() instead.
    
    Args:
        url: Target URL to analyze
        csv_file: Optional CSV file path (unused, kept for compatibility)
    
    Returns:
        Tuple of (features_dict, screenshot_path)
    """
    ensure_dirs()

    try:
        ext = tldextract.extract(url)
        domain_full = ".".join(part for part in [ext.domain, ext.suffix] if part) or url
        screenshot_path = os.path.join(SCREENS_DIR, f"{domain_full}.png")

        # Capture screenshot
        target_url, capture_ok = capture_screenshot(url, screenshot_path)

        if not capture_ok:
            # Create placeholder image if capture failed
            img = Image.new("RGB", (1280, 720), color=(255, 255, 255))
            d = ImageDraw.Draw(img)
            d.text((20, 30), f"Failed to capture: {url}", fill=(0, 0, 0))
            img.save(screenshot_path)
            logger.debug("Screenshot capture failed for %s", url)

        # Extract all independent features in parallel where possible
        url_feats = extract_url_features(target_url)
        subdomain_feats = extract_subdomain_features(target_url)
        path_feats = extract_path_features(target_url)
        entropy_feats = entropy_features(target_url)
        ssl_feats = ssl_features(target_url)
        ip_addr = get_ip_address(target_url)

        # Extract visual features with fallback values
        branding_feats = _safe_extract_branding(screenshot_path)
        ocr_text = _safe_extract_ocr(screenshot_path)
        lap_var = _safe_extract_laplacian(screenshot_path)
        fav_feats = get_favicon_features(target_url)
        fav_feats.pop("favicon_path", None)

        # Combine all features
        all_feats = {
            "url": target_url,
            "ip_address": ip_addr,
            **url_feats,
            **subdomain_feats,
            **path_feats,
            **entropy_feats,
            **ssl_feats,
            **branding_feats,
            **fav_feats,
            "ocr_text": ocr_text,
            "laplacian_variance": lap_var
        }

        return all_feats, screenshot_path
    
    except Exception as e:
        logger.error("Unexpected error in extract_all_features for %s: %s", url, e)
        # Return empty feature dict with screenshot path
        return {}, ""

async def extract_network_features_async(url: str, semaphore: asyncio.Semaphore | None = None) -> dict:
    """Run fast network/structure features."""
    if semaphore:
        async with semaphore:
            return await _extract_network_impl(url)
    return await _extract_network_impl(url)

async def _extract_network_impl(url: str) -> dict:
    loop = asyncio.get_running_loop()
    cpu_sem = _get_cpu_semaphore()

    async def run_cpu_task(func, *args):
        async with cpu_sem:
            return await loop.run_in_executor(None, func, *args)

    # Fast tasks
    t_ip = run_cpu_task(get_ip_address, url)
    t_ssl = run_cpu_task(ssl_features, url)
    t_url_feats = run_cpu_task(extract_url_features, url)
    t_sub_feats = run_cpu_task(extract_subdomain_features, url)
    t_pth_feats = run_cpu_task(extract_path_features, url)
    t_ent_feats = run_cpu_task(entropy_features, url)
    
    results = await asyncio.gather(
        t_ip, t_ssl, t_url_feats, t_sub_feats, t_pth_feats, t_ent_feats,
        return_exceptions=True
    )
    
    (ip_addr, ssl_feats, url_feats, subdomain_feats, path_feats, entropy_feats) = results

    # Normalize errors
    ip_addr = ip_addr if not isinstance(ip_addr, Exception) else None
    ssl_feats = ssl_feats if not isinstance(ssl_feats, Exception) else {"ssl_present": 0, "ssl_valid": 0, "ssl_days_to_expiry": -1, "ssl_issuer": None}
    url_feats = url_feats if not isinstance(url_feats, Exception) else {}
    subdomain_feats = subdomain_feats if not isinstance(subdomain_feats, Exception) else {}
    path_feats = path_feats if not isinstance(path_feats, Exception) else {}
    entropy_feats = entropy_feats if not isinstance(entropy_feats, Exception) else {}

    return {
        "ip_address": ip_addr,
        **url_feats,
        **subdomain_feats,
        **path_feats,
        **entropy_feats,
        **ssl_feats
    }

async def extract_visual_features_async(url: str, semaphore: asyncio.Semaphore | None = None) -> tuple:
    """Run slow visual features (Screenshot, OCR, Branding)."""
    if semaphore:
        async with semaphore:
            return await _extract_visual_impl(url)
    return await _extract_visual_impl(url)

async def _extract_visual_impl(url: str) -> tuple:
    ensure_dirs()
    try:
        ext = tldextract.extract(url)
        domain_full = ".".join(part for part in [ext.domain, ext.suffix] if part) or url
        screenshot_path = os.path.join(SCREENS_DIR, f"{domain_full}.png")

        screenshot_sem = _get_screenshot_semaphore()
        async with screenshot_sem:
            target_url, capture_ok = await capture_screenshot_async(url, screenshot_path)

        if not capture_ok:
            await asyncio.to_thread(_create_dummy_image, url, screenshot_path)
            logger.debug("Screenshot capture failed for %s", url)

        loop = asyncio.get_running_loop()
        ocr_sem = _get_ocr_semaphore()
        img_sem = _get_image_semaphore()

        async def run_ocr_task(func, *args):
            async with ocr_sem:
                return await loop.run_in_executor(None, func, *args)

        async def run_image_task(func, *args):
            async with img_sem:
                return await loop.run_in_executor(None, func, *args)

        t_ocr = run_ocr_task(_safe_extract_ocr, screenshot_path)
        t_brand = run_image_task(_safe_extract_branding, screenshot_path)
        t_lap = run_image_task(_safe_extract_laplacian, screenshot_path)
        t_fav = get_favicon_features_async(target_url)

        results = await asyncio.gather(t_ocr, t_brand, t_lap, t_fav, return_exceptions=True)
        (ocr_text, branding_feats, lap_var, fav_feats) = results

        # Normalize errors
        ocr_text = ocr_text if not isinstance(ocr_text, Exception) else ""
        branding_feats = branding_feats if not isinstance(branding_feats, Exception) else DEFAULT_BRANDING_FEATURES
        lap_var = lap_var if not isinstance(lap_var, Exception) else float("nan")
        if isinstance(fav_feats, (Exception, type(None))): fav_feats = {}
        else: fav_feats.pop("favicon_path", None)

        feats = {
            "url": target_url, # Updated URL after redirect
            "ocr_text": ocr_text,
            "laplacian_variance": lap_var,
            **branding_feats,
            **fav_feats
        }
        return feats, screenshot_path

    except Exception as e:
        logger.error("Visual extraction error for %s: %s", url, e)
        return {}, ""

# Kept for backward compatibility but calls the new split functions internally? 
# Actually simpler to just have it call them both:
async def extract_all_features_async(url: str, semaphore: asyncio.Semaphore | None = None) -> tuple:
    if semaphore:
        async with semaphore:
             return await _extract_all_impl_combined(url)
    return await _extract_all_impl_combined(url)

async def _extract_all_impl_combined(url: str) -> tuple:
    try:
        # A simple join of the two new functions
        net_feats = await _extract_network_impl(url)
        vis_feats, screen_path = await _extract_visual_impl(url)
        # Merge, prioritizing visual's URL if redirected
        final_url = vis_feats.get("url", url) 
        combined = {**net_feats, **vis_feats}
        combined["url"] = final_url
        return combined, screen_path
    except Exception as e:
        logger.error("Unexpected error in async feature extraction for %s: %s", url, e)
        return {}, ""

def _create_dummy_image(url, path):
    try:
        img = Image.new("RGB", (1280, 720), color=(255, 255, 255))
        d = ImageDraw.Draw(img)
        d.text((20, 30), f"Failed to capture: {url}", fill=(0, 0, 0))
        img.save(path)
    except:
        pass

logger = logging.getLogger(__name__)

# =====================================================================
# Default Feature Values (Consistent Sentinels)
# =====================================================================
DEFAULT_BRANDING_FEATURES = {
    "brand_colors": [],
    "avg_color_diff": -1.0,
    "logo_hash": None,
    "logo_match_score": -1
}

# =====================================================================
# Safe Feature Extraction Wrappers (Consistent Error Handling)
# =====================================================================

def _safe_extract_branding(path: str) -> dict:
    """
    Safely extract branding features with fallback.
    
    Args:
        path: Path to screenshot file
    
    Returns:
        Dictionary with branding features or defaults if extraction fails
    """
    try:
        if not os.path.exists(path):
            logger.debug("Screenshot file not found: %s", path)
            return DEFAULT_BRANDING_FEATURES.copy()
        
        return branding_guidelines_features(path)
    
    except FileNotFoundError:
        logger.debug("Screenshot file not found for branding extraction: %s", path)
        return DEFAULT_BRANDING_FEATURES.copy()
    except Exception as e:
        logger.error("Branding extraction failed for %s: %s", path, e)
        return DEFAULT_BRANDING_FEATURES.copy()


def _safe_extract_ocr(path: str) -> str:
    """
    Combined OCR wrapper (backward compat / single-threaded use).
    For the two-stage pipeline, call _safe_preprocess_image + _safe_run_ocr separately.
    """
    try:
        if not os.path.exists(path):
            logger.debug("Screenshot file not found for OCR: %s", path)
            return ""
        return extract_ocr_text(path)
    except FileNotFoundError:
        logger.debug("Screenshot file not found for OCR: %s", path)
        return ""
    except Exception as e:
        logger.error("OCR extraction failed for %s: %s", path, e)
        return ""


def _safe_preprocess_image(path: str):
    """
    Phase A wrapper â€” CPU only, no lock.
    Returns numpy array or None. Run this in parallel while GPU is busy.
    """
    try:
        if not os.path.exists(path):
            logger.debug("Screenshot not found for preprocess: %s", path)
            return None
        return preprocess_image_for_ocr(path)
    except Exception as e:
        logger.error("Image preprocess failed for %s: %s", path, e)
        return None


def _safe_run_ocr(img_np) -> tuple:
    """
    Phase B wrapper â€” GPU serialized, minimal lock scope.
    Pass the numpy array from _safe_preprocess_image().

    Returns:
        tuple[str, list]: (flat_text, raw_results)
    """
    try:
        return run_ocr_inference(img_np)
    except Exception as e:
        logger.error("OCR inference failed: %s", e)
        return "", []


def _safe_extract_laplacian(path: str) -> float:
    """
    Safely extract Laplacian variance with fallback.
    
    Args:
        path: Path to screenshot file
    
    Returns:
        Laplacian variance value or NaN if extraction fails
    """
    try:
        if not os.path.exists(path):
            logger.debug("Screenshot file not found for Laplacian: %s", path)
            return float("nan")
        
        return laplacian_variance(path)
    
    except FileNotFoundError:
        logger.debug("Screenshot file not found for Laplacian: %s", path)
        return float("nan")
    except Exception as e:
        logger.error("Laplacian variance extraction failed for %s: %s", path, e)
        return float("nan")


# =====================================================================
# Textual-Visual Consistency (TVC) Features
# =====================================================================

# Canonical TVC brand families. The whitelist/entity data is merged into this at runtime.
# `aliases` are broad detection aliases. `spoof_aliases` are the stricter subset
# allowed to drive spoof escalation.
TVC_BRAND_OVERRIDES = {
    "sbi": {"aliases": {"sbi", "state bank of india", "onlinesbi"}, "domains": {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"}},
    "icici": {"aliases": {"icici", "icici bank", "icicibank"}, "domains": {"icicibank.com"}},
    "hdfc": {"aliases": {"hdfc", "hdfc bank", "hdfcbank"}, "domains": {"hdfcbank.com"}},
    "axis": {"aliases": {"axis", "axis bank", "axisbank", "axis upi", "axisupi"}, "spoof_aliases": {"axis bank", "axisbank", "axis upi", "axisupi"}, "domains": {"axisbank.com"}},
    "kotak": {"aliases": {"kotak", "kotak bank", "kotakbank"}, "domains": {"kotak.com", "kotakbank.com"}},
    "pnb": {"aliases": {"pnb", "punjab national bank", "pnbindia"}, "domains": {"pnbindia.in"}},
    "canara": {"aliases": {"canara", "canara bank", "canarabank"}, "domains": {"canarabank.com"}},
    "bob": {"aliases": {"bank of baroda", "baroda", "bankofbaroda", "bob"}, "domains": {"bankofbaroda.in", "bankofbaroda.com"}},
    "airtel": {"aliases": {"airtel", "bharti airtel"}, "domains": {"airtel.in", "airtel.com"}},
    "irctc": {"aliases": {"irctc"}, "domains": {"irctc.co.in"}},
    "nic": {"aliases": {"nic", "national informatics centre"}, "spoof_aliases": {"national informatics centre"}, "domains": {"nic.in", "gov.in"}},
    "iocl": {"aliases": {"iocl", "indian oil", "indianoil"}, "domains": {"iocl.com"}},
    "lic": {"aliases": {"lic", "life insurance corporation", "licindia"}, "domains": {"licindia.in"}},
    "uidai": {"aliases": {"uidai", "aadhaar", "aadhaar india"}, "domains": {"uidai.gov.in", "myaadhaar.uidai.gov.in"}},
    "eci": {"aliases": {"eci", "election commission", "election commission of india"}, "domains": {"eci.gov.in"}},
    "cams": {"aliases": {"cams", "camsonline"}, "domains": {"camsonline.com"}},
    "kfintech": {"aliases": {"kfintech", "kfin"}, "domains": {"kfintech.com"}},
    "coalindia": {"aliases": {"coal india", "coalindia"}, "domains": {"coalindia.in"}},
    "incometax": {"aliases": {"income tax", "income tax india", "incometax"}, "domains": {"incometax.gov.in"}},
    "isro": {"aliases": {"isro", "indian space research organisation", "indian space research organization"}, "domains": {"isro.gov.in"}},
    "google": {"aliases": {"google"}, "domains": {"google.com", "google.co.in"}},
    "facebook": {"aliases": {"facebook", "fb"}, "domains": {"facebook.com", "fb.com"}},
    "instagram": {"aliases": {"instagram"}, "domains": {"instagram.com"}},
    "microsoft": {"aliases": {"microsoft", "outlook", "live"}, "domains": {"microsoft.com", "live.com", "outlook.com", "microsoftonline.com"}},
    "paypal": {"aliases": {"paypal"}, "domains": {"paypal.com"}},
    "amazon": {"aliases": {"amazon"}, "domains": {"amazon.com", "amazon.in"}},
    "whatsapp": {"aliases": {"whatsapp"}, "domains": {"whatsapp.com"}},
    "telegram": {"aliases": {"telegram"}, "domains": {"telegram.org"}},
}
_TVC_BRAND_CATALOG = None
_TVC_GENERIC_SPOOF_ALIASES = {"axis", "cloud", "mail", "myvi", "nic"}


def _normalize_tvc_text(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(value or "").lower())).strip()


def _expand_tvc_aliases(values) -> set[str]:
    expanded = set()
    for value in values or []:
        alias_norm = _normalize_tvc_text(value)
        if alias_norm:
            expanded.add(alias_norm)
            expanded.add(alias_norm.replace(" ", ""))
    return expanded


def _curate_tvc_spoof_aliases(values) -> set[str]:
    return {
        alias
        for alias in _expand_tvc_aliases(values)
        if alias and alias not in _TVC_GENERIC_SPOOF_ALIASES
    }


def _add_brand_catalog_entry(
    catalog: dict,
    canonical: str,
    aliases=None,
    domains=None,
    spoof_aliases=None,
    *,
    auto_promote_primary_detection: bool = True,
    auto_promote_primary_spoof: bool = False,
):
    key = _normalize_tvc_text(canonical).replace(" ", "")
    if not key:
        return
    entry = catalog.setdefault(
        key,
        {
            "aliases": set(),
            "detection_aliases": set(),
            "spoof_aliases": set(),
            "domains": set(),
        },
    )
    detection_aliases = _expand_tvc_aliases(aliases)
    entry["aliases"].update(detection_aliases)
    entry["detection_aliases"].update(detection_aliases)
    if spoof_aliases is None:
        spoof_aliases = aliases
    entry["spoof_aliases"].update(_curate_tvc_spoof_aliases(spoof_aliases))
    for domain in domains or []:
        domain_norm = str(domain or "").strip().lower()
        if domain_norm:
            entry["domains"].add(domain_norm)
            primary = tldextract.extract(domain_norm).domain.lower()
            if primary and auto_promote_primary_detection:
                entry["aliases"].add(primary)
                entry["detection_aliases"].add(primary)
            if primary and auto_promote_primary_spoof and primary not in _TVC_GENERIC_SPOOF_ALIASES:
                entry["spoof_aliases"].add(primary)


def _get_tvc_brand_catalog() -> dict:
    global _TVC_BRAND_CATALOG
    if _TVC_BRAND_CATALOG is not None:
        return _TVC_BRAND_CATALOG

    catalog = {}
    for canonical, payload in TVC_BRAND_OVERRIDES.items():
        _add_brand_catalog_entry(
            catalog,
            canonical,
            payload.get("aliases"),
            payload.get("domains"),
            payload.get("spoof_aliases"),
            auto_promote_primary_detection=True,
            auto_promote_primary_spoof=False,
        )

    whitelist_path = os.path.join(WHITELISTS_DIR, "Stage_2_Legitimate_Domains_80.xlsx")
    if os.path.exists(whitelist_path):
        try:
            import pandas as pd

            wl_df = pd.read_excel(whitelist_path, usecols=["Cooresponding CSE", "Legitimate Domains"])
            wl_df["Cooresponding CSE"] = wl_df["Cooresponding CSE"].ffill()
            for _, row in wl_df.iterrows():
                cse_name = str(row.get("Cooresponding CSE", "") or "").strip()
                legit_domain = str(row.get("Legitimate Domains", "") or "").strip().lower()
                primary = tldextract.extract(legit_domain).domain.lower()
                canonical = primary or cse_name
                detection_aliases = {cse_name, primary, cse_name.replace(" ", "")}
                spoof_aliases = {cse_name, cse_name.replace(" ", "")}
                _add_brand_catalog_entry(
                    catalog,
                    canonical,
                    detection_aliases,
                    {legit_domain},
                    spoof_aliases,
                    auto_promote_primary_detection=True,
                    auto_promote_primary_spoof=False,
                )
        except Exception as exc:
            logger.warning("Failed to load TVC whitelist brand map: %s", exc)

    entity_db_path = os.path.join(ROOT_DIR, "data", "entity_hash_db.json")
    if os.path.exists(entity_db_path):
        try:
            import json

            with open(entity_db_path, "r", encoding="utf-8") as fh:
                entity_db = json.load(fh)
            for entity_name, payload in entity_db.items():
                domains = payload.get("domains", []) if isinstance(payload, dict) else []
                primary = ""
                if domains:
                    primary = tldextract.extract(str(domains[0])).domain.lower()
                canonical = primary or entity_name
                detection_aliases = {entity_name, entity_name.replace(" ", ""), primary}
                spoof_aliases = {entity_name, entity_name.replace(" ", "")}
                _add_brand_catalog_entry(
                    catalog,
                    canonical,
                    detection_aliases,
                    domains,
                    spoof_aliases,
                    auto_promote_primary_detection=True,
                    auto_promote_primary_spoof=False,
                )
        except Exception as exc:
            logger.warning("Failed to load TVC entity brand map: %s", exc)

    _TVC_BRAND_CATALOG = catalog
    return _TVC_BRAND_CATALOG


def _resolve_tvc_brand(shortlisted_cse: str, shortlisted_domain: str) -> str | None:
    catalog = _get_tvc_brand_catalog()
    shortlisted_domain = str(shortlisted_domain or "").strip().lower()
    shortlisted_cse_norm = _normalize_tvc_text(shortlisted_cse)
    shortlisted_cse_compact = shortlisted_cse_norm.replace(" ", "")
    best_brand = None
    best_score = -1
    for canonical, payload in catalog.items():
        domains = payload["domains"]
        aliases = payload.get("detection_aliases", payload.get("aliases", set()))
        if shortlisted_domain:
            matching_domains = [
                legit_domain
                for legit_domain in domains
                if shortlisted_domain == legit_domain or shortlisted_domain.endswith("." + legit_domain)
            ]
            if matching_domains:
                domain_score = max(len(match) for match in matching_domains)
                if domain_score > best_score:
                    best_brand = canonical
                    best_score = domain_score
        if shortlisted_cse_norm and (shortlisted_cse_norm in aliases or shortlisted_cse_compact in aliases):
            alias_score = max(len(shortlisted_cse_norm), len(shortlisted_cse_compact))
            if alias_score > best_score:
                best_brand = canonical
                best_score = alias_score
    return best_brand


def extract_tvc_features(
    url: str,
    ocr_header_text: str,
    ocr_footer_text: str,
    ocr_full_text: str = "",
    html_text: str = "",
    shortlisted_cse: str = "",
    shortlisted_domain: str = "",
) -> dict:
    """
    Textual-Visual Consistency: checks if visual brand signals match the actual domain.

    Compares brand names found in OCR/header/footer/html text against the website's
    actual domain using the runtime TVC brand catalog.

    Args:
        url:             The URL being analyzed
        ocr_header_text: OCR text from the header zone (brand/logo area)
        ocr_footer_text: OCR text from the footer zone (legal/copyright area)

    Search order:
        1. header/footer OCR
        2. full OCR
        3. HTML title / visible text fallback

    The spoof flag is only raised when the detected brand aligns with the
    shortlisted CSE/domain family and the actual domain does not.
    """
    from rapidfuzz import fuzz

    catalog = _get_tvc_brand_catalog()
    ext = tldextract.extract(url)
    actual_domain = f"{ext.domain}.{ext.suffix}".lower()
    shortlist_brand = _resolve_tvc_brand(shortlisted_cse, shortlisted_domain)
    search_surfaces = [
        ("ocr_header_footer", _normalize_tvc_text(f"{ocr_header_text} {ocr_footer_text}"), True, 3),
        ("ocr_full", _normalize_tvc_text(ocr_full_text), True, 2),
        ("html", _normalize_tvc_text(html_text), False, 1),
    ]
    best_brand_hit = None
    best_match_score = 0.0
    domain_matches_brand = False
    best_surface = ""
    best_alias = ""
    best_detection_rank = (-1, -1, -1, -1.0)
    spoof_hit = None
    spoof_surface = ""
    spoof_alias = ""
    spoof_match_score = 0.0
    spoof_domain_match = False
    spoof_rank = (-1, -1, -1, -1.0)

    for surface_name, surface, allow_spoof, surface_priority in search_surfaces:
        if not surface:
            continue
        for brand, payload in catalog.items():
            aliases = payload.get("detection_aliases", payload.get("aliases", set()))
            spoof_aliases = payload.get("spoof_aliases", set())
            legit_domains = payload["domains"]
            if not aliases or not legit_domains:
                continue
            matched_aliases = [alias for alias in aliases if alias and alias in surface]
            if not matched_aliases:
                continue
            matched_alias = max(matched_aliases, key=len)

            is_legit = any(
                actual_domain == legit_domain or actual_domain.endswith("." + legit_domain)
                for legit_domain in legit_domains
            )
            fuzzy_scores = [fuzz.ratio(actual_domain, legit_domain) for legit_domain in legit_domains]
            score = (max(fuzzy_scores) / 100.0) if fuzzy_scores else 0.0
            shortlist_alignment = 1 if shortlist_brand is None else int(brand == shortlist_brand)
            detection_rank = (shortlist_alignment, surface_priority, len(matched_alias), score)
            if detection_rank > best_detection_rank:
                best_detection_rank = detection_rank
                best_match_score = score
                best_brand_hit = brand
                domain_matches_brand = is_legit
                best_surface = surface_name
                best_alias = matched_alias

            matched_spoof_aliases = [alias for alias in matched_aliases if alias in spoof_aliases]
            if not allow_spoof or not matched_spoof_aliases:
                continue
            matched_spoof_alias = max(matched_spoof_aliases, key=len)
            spoof_candidate_rank = (shortlist_alignment, surface_priority, len(matched_spoof_alias), score)
            if spoof_candidate_rank > spoof_rank:
                spoof_rank = spoof_candidate_rank
                spoof_hit = brand
                spoof_surface = surface_name
                spoof_alias = matched_spoof_alias
                spoof_match_score = score
                spoof_domain_match = is_legit

    aligned_to_shortlist = bool(spoof_hit) and (shortlist_brand is None or spoof_hit == shortlist_brand)
    spoofed = bool(spoof_hit) and aligned_to_shortlist and (not spoof_domain_match)
    return {
        "tvc_brand_detected": best_brand_hit is not None,
        "tvc_detected_brand": best_brand_hit or "none",
        "tvc_domain_match": domain_matches_brand,
        "tvc_fuzzy_score": round(best_match_score, 4),
        "tvc_brand_spoofed": spoofed,
        "tvc_match_surface": spoof_surface or best_surface or "none",
        "tvc_matched_alias": spoof_alias or best_alias or "",
        "tvc_spoof_strong": spoofed,
    }

