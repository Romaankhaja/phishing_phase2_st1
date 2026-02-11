import os, re
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
 

from .config import SCREENS_DIR
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
    laplacian_variance,
    get_favicon_features_async,
)

logger = logging.getLogger(__name__)

# ================== RESOURCE MANAGEMENT SEMAPHORES ==================
# These semaphores limit concurrent operations to prevent memory exhaustion
# Tuned for RTX 2050 with 2GB VRAM
MAX_CONCURRENT_OCR = 1
MAX_CONCURRENT_SCREENSHOTS = 8
MAX_CONCURRENT_IMAGE_PROCESSING = 5
MAX_CONCURRENT_CPU_TASKS = 20

_ocr_semaphore: asyncio.Semaphore | None = None
_screenshot_semaphore: asyncio.Semaphore | None = None
_image_semaphore: asyncio.Semaphore | None = None
_cpu_semaphore: asyncio.Semaphore | None = None

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
            logger.warning("Screenshot capture failed for %s", url)

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
            logger.warning("Screenshot capture failed for %s", url)

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
            logger.warning("Screenshot file not found: %s", path)
            return DEFAULT_BRANDING_FEATURES.copy()
        
        return branding_guidelines_features(path)
    
    except FileNotFoundError:
        logger.warning("Screenshot file not found for branding extraction: %s", path)
        return DEFAULT_BRANDING_FEATURES.copy()
    except Exception as e:
        logger.error("Branding extraction failed for %s: %s", path, e)
        return DEFAULT_BRANDING_FEATURES.copy()


def _safe_extract_ocr(path: str) -> str:
    """
    Safely extract OCR text with fallback.
    
    Args:
        path: Path to screenshot file
    
    Returns:
        Extracted text string or empty string if extraction fails
    """
    try:
        if not os.path.exists(path):
            logger.warning("Screenshot file not found for OCR: %s", path)
            return ""
        
        return extract_ocr_text(path)
    
    except FileNotFoundError:
        logger.warning("Screenshot file not found for OCR: %s", path)
        return ""
    except Exception as e:
        logger.error("OCR extraction failed for %s: %s", path, e)
        return ""


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
            logger.warning("Screenshot file not found for Laplacian: %s", path)
            return float("nan")
        
        return laplacian_variance(path)
    
    except FileNotFoundError:
        logger.warning("Screenshot file not found for Laplacian: %s", path)
        return float("nan")
    except Exception as e:
        logger.error("Laplacian variance extraction failed for %s: %s", path, e)
        return float("nan")

