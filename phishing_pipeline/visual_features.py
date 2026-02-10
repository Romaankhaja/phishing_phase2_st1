import os, re, base64, mimetypes, requests, asyncio, warnings, logging as _logging, socket
import aiohttp  # For HEAD request pre-check
# Suppress harmless PyTorch RNN warning from EasyOCR's LSTM
warnings.filterwarnings("ignore", message="RNN module weights are not part of single contiguous chunk")
# Suppress screenshot failure warnings (they clutter the terminal)
class ScreenshotWarningFilter(_logging.Filter):
    def filter(self, record):
        return "Failed to capture screenshot" not in record.getMessage()
_logging.getLogger("phishing_pipeline.visual_features").addFilter(ScreenshotWarningFilter())
import numpy as np, cv2, imagehash
from PIL import Image
from urllib.parse import urlparse
from sklearn.cluster import KMeans
from colormath.color_objects import LabColor, sRGBColor
from colormath.color_conversions import convert_color
from colormath.color_diff import delta_e_cie2000
from playwright.sync_api import sync_playwright, Playwright, Browser, BrowserContext
from playwright.async_api import async_playwright, Playwright as AsyncPlaywright, Browser as AsyncBrowser, BrowserContext as AsyncBrowserContext
import tldextract
import easyocr
import torch
import logging

from .config import SCREENS_DIR

# ------------------ Global "Lazy" Initializers ------------------
# We initialize these to None. They will be created on-demand
# by the getter functions below, ensuring they only load when used.


_play: Playwright | None = None
_browser: Browser | None = None
_context: BrowserContext | None = None

# _async_* variables are now handled by AsyncBrowserManager class
_ocr_reader: easyocr.Reader | None = None
_ocr_call_count: int = 0  # Counter for periodic GPU cache cleanup

logger = logging.getLogger(__name__)

def _get_browser_context() -> BrowserContext:
    """
    Initializes and returns a single, shared Playwright browser context.
    
    This function ensures Playwright only starts when it's first needed.
    Implements lazy initialization pattern for resource efficiency.
    
    Returns:
        Playwright BrowserContext instance
    
    Raises:
        RuntimeError: If Playwright initialization fails
    """
    global _play, _browser, _context
    
    # If we've already initialized it, just return the existing context
    if _context:
        return _context

    try:
        logger.info("🚀 Initializing Playwright browser for the first time...")
        _play = sync_playwright().start()
        _browser = _play.chromium.launch(headless=True)
        _default_viewport = {"width": 1280, "height": 900}
        _context = _browser.new_context(viewport=_default_viewport)
        logger.info("✅ Playwright browser context is ready.")
        return _context
    
    except ImportError as e:
        logger.error("❌ Playwright not installed: %s", e)
        raise RuntimeError("Playwright library required for screenshot capture") from e
    except Exception as e:
        logger.error("❌ Failed to initialize Playwright browser: %s", e)
        raise RuntimeError(f"Playwright initialization failed: {e}") from e



def _get_ocr_reader() -> easyocr.Reader:
    """
    Initializes and returns a single, shared EasyOCR reader.
    
    This function ensures the model only loads when it's first needed.
    Implements lazy initialization for memory efficiency.
    
    Returns:
        EasyOCR Reader instance
    
    Raises:
        RuntimeError: If EasyOCR fails to initialize
    """
    global _ocr_reader
    if _ocr_reader is None:
        try:
            # Check GPU availability
            gpu_available = torch.cuda.is_available()
            if gpu_available:
                logger.info("🚀 GPU detected: %s", torch.cuda.get_device_name(0))
            else:
                logger.warning("⚠️ GPU not available, using CPU (will be slower)")
            
            # Use GPU if available, otherwise CPU
            _ocr_reader = easyocr.Reader(['en'], gpu=gpu_available)
            logger.info("✅ EasyOCR initialized successfully (GPU: %s)", gpu_available)
        
        except ImportError as e:
            logger.error("❌ EasyOCR not installed. Install with: pip install easyocr")
            raise RuntimeError("EasyOCR library required for text extraction") from e
        except Exception as e:
            logger.error("❌ Failed to initialize EasyOCR: %s", e)
            raise RuntimeError(f"EasyOCR initialization failed: {e}") from e
    
    return _ocr_reader

def close_browser():
    """Cleanly close browser + context when done."""
    global _play, _browser, _context
    
    # Only try to close if they were actually initialized
    if _context:
        try:
            _context.close()
            _context = None
        except Exception as e:
            logger.warning("Error closing Playwright context: %s", e)
    if _browser:
        try:
            _browser.close()
            _browser = None
        except Exception as e:
            logger.warning("Error closing Playwright browser: %s", e)
    if _play:
        try:
            _play.stop()
            _play = None
        except Exception as e:
            logger.warning("Error stopping Playwright: %s", e)
    
    logger.info("💤 Playwright browser has been closed.")


# ------------------ Robust Browser Manager ------------------

class AsyncBrowserManager:
    """
    Manages the lifecycle of the Async Playwright browser to prevent
    'Context closed' errors. Auto-restarts if the browser crashes.
    """
    def __init__(self):
        self._play = None
        self._browser = None
        self._context = None
        self._lock = asyncio.Lock()
        
    async def get_context(self) -> AsyncBrowserContext:
        """
        Returns a valid, open browser context. 
        Restarts the browser if the current context is closed or missing.
        """
        async with self._lock:
            # Check if current context exists and is open
            if self._context:
                try:
                    # There is no direct .is_closed() on AsyncBrowserContext in all versions, 
                    # but if browser is connected, context is likely fine.
                    if self._browser and self._browser.is_connected():
                        return self._context
                except Exception:
                    pass
                
                logger.warning("⚠️ Found closed or disconnected browser context. Restarting...")
                await self._force_close()

            # Initialize new one
            return await self._start_new_session()

    async def _start_new_session(self) -> AsyncBrowserContext:
        """Internal method to launch a fresh Playwright session."""
        try:
            logger.info("🚀 Launching new Async Playwright session...")
            self._play = await async_playwright().start()
            self._browser = await self._play.chromium.launch(headless=True)
            self._context = await self._browser.new_context(viewport={"width": 1280, "height": 900})
            logger.info("✅ New Async Browser Context Ready.")
            return self._context
        except Exception as e:
            logger.error("❌ Failed to start browser session: %s", e)
            raise

    async def _force_close(self):
        """Aggressively cleans up resources."""
        if self._context:
            try:
                await self._context.close()
            except Exception: pass
        if self._browser:
            try:
                await self._browser.close()
            except Exception: pass
        if self._play:
            try:
                await self._play.stop()
            except Exception: pass
        
        self._context = None
        self._browser = None
        self._play = None

    async def close(self):
        """Graceful shutdown at end of script."""
        async with self._lock:
            await self._force_close()
            logger.info("💤 Async Browser Manager shutdown complete.")

# Singleton instance
_async_browser_manager = AsyncBrowserManager()

async def close_browser_async():
    """Wrapper to close the singleton manager."""
    await _async_browser_manager.close()

# ------------------ Pre-Flight Checks for Speed ------------------

async def quick_dns_check(host: str, timeout: float = 2.0) -> bool:
    """
    Quick DNS resolution check before attempting screenshot.
    
    Saves 4-5 seconds per dead domain by failing fast.
    
    Args:
        host: Domain hostname to check
        timeout: Maximum time to wait for DNS resolution
    
    Returns:
        True if domain resolves, False otherwise
    """
    try:
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(
            loop.getaddrinfo(host, 80),
            timeout=timeout
        )
        return True
    except (asyncio.TimeoutError, socket.gaierror, OSError):
        return False
    except Exception:
        return False

async def is_site_reachable(url: str, timeout: float = 1.5) -> bool:
    """
    Quick HEAD request to verify site responds before full screenshot.
    
    Saves 3-4 seconds per unreachable site.
    
    Args:
        url: Full URL to check (with http/https)
        timeout: Maximum time to wait for response
    
    Returns:
        True if site responds (any status), False if unreachable
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(
                url, 
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
                ssl=False  # Skip SSL verification for speed
            ) as response:
                # Any response (even 403/404) means site is reachable
                return True
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False
    except Exception:
        return False

# ------------------ Screenshot ------------------
def capture_screenshot(url: str, out_file: str, width: int = 1280, height: int = 900) -> tuple[str, bool]:
    """
    Capture screenshot synchronously using Playwright.
    
    Args:
        url: Target URL to capture
        out_file: Output file path for screenshot
        width: Viewport width (default 1280)
        height: Viewport height (default 900)
    
    Returns:
        Tuple of (normalized_url, success_flag)
    """
    try:
        if not url.startswith("http"):
            try_urls = [f"https://{url}", f"http://{url}"]
        else:
            try_urls = [url]

        # Use the getter function to ensure browser is running
        context = _get_browser_context()
        page = context.new_page()
        
        for target in try_urls:
            try:
                page.goto(target, timeout=5000)  # Timeout in milliseconds
                page.screenshot(path=out_file, full_page=True)
                page.close()
                return target, True
            except Exception as nav_error:
                logger.debug("Navigation to %s failed: %s", target, nav_error)
                continue
        
        page.close()
        logger.warning("Failed to capture screenshot for %s", url)
        return try_urls[-1], False
    
    except Exception as e:
        logger.error("Screenshot capture error for %s: %s", url, e)
        return url, False

async def capture_screenshot_async(url: str, out_file: str, width: int = 1280, height: int = 900) -> tuple[str, bool]:
    """
    Capture screenshot asynchronously with automatic retry and browser recovery.
    
    Includes pre-flight checks:
    1. DNS resolution check (2s timeout) - skips dead domains
    2. HEAD request check (1.5s timeout) - skips unreachable sites
    """
    if not url.startswith("http"):
        try_urls = [f"https://{url}", f"http://{url}"]
    else:
        try_urls = [url]

    # ============ PRE-FLIGHT CHECKS (Save 4-5s per dead domain) ============
    
    # Extract hostname for DNS check
    try:
        host = urlparse(try_urls[0]).hostname
    except:
        host = url
    
    # 1. Quick DNS check - skip if domain doesn't resolve
    if host and not await quick_dns_check(host, timeout=2.0):
        logger.debug(f"⚡ DNS failed for {host}, skipping screenshot")
        return url, False
    
    # 2. Quick HEAD check - skip if site doesn't respond
    for target_url in try_urls:
        if await is_site_reachable(target_url, timeout=1.5):
            # Found a reachable URL, proceed with this one first
            try_urls = [target_url] + [u for u in try_urls if u != target_url]
            break
    else:
        # Neither https nor http responded
        logger.debug(f"⚡ HEAD check failed for {url}, skipping screenshot")
        return url, False
    
    # ============ BROWSER SCREENSHOT (only if pre-checks pass) ============
    
    # Retry logic for the entire operation (in case browser crashes mid-op)
    MAX_RETRIES = 2
    for attempt in range(MAX_RETRIES):
        try:
            # 1. Get a healthy context from the manager
            context = await _async_browser_manager.get_context()
            
            # 2. Create page
            page = await context.new_page()
            
            # 3. Try URLs
            for target in try_urls:
                try:
                    await page.goto(target, timeout=5000, wait_until='domcontentloaded')
                    await page.screenshot(path=out_file, full_page=True)
                    await page.close()
                    return target, True
                except Exception as nav_error:
                    # If it's a "Target closed" error, it might be the browser dying
                    if "closed" in str(nav_error).lower() or "context" in str(nav_error).lower():
                        raise nav_error # Re-raise to trigger the outer retry loop
                    logger.debug(f"Attempt {attempt}: Nav failed for {target}: {nav_error}")
                    continue
            
            await page.close()
            return try_urls[-1], False

        except Exception as e:
            err_msg = str(e).lower()
            if "closed" in err_msg or "context" in err_msg:
                if attempt < MAX_RETRIES - 1:
                    logger.warning(f"⚠️ Browser context died capturing {url}. Restarting and retrying... (Attempt {attempt+1})")
                    # Force restart the browser for the next loop
                    await _async_browser_manager._force_close()
                    await asyncio.sleep(1) # Breathe
                    continue
            
            logger.error(f"❌ Async screenshot error for {url}: {e}")
            return url, False
    
    return url, False



# ------------------ Brand Colors ------------------
def extract_brand_colors(image_path: str, num_colors: int = 3) -> list:
    """
    Extract dominant brand colors from image using KMeans clustering.
    
    Args:
        image_path: Path to image file
        num_colors: Number of dominant colors to extract (default 3)
    
    Returns:
        List of RGB color tuples
    """
    try:
        img = Image.open(image_path).convert("RGB")
        npimg = np.array(img)
        # Speed up by downsampling
        npimg = cv2.resize(npimg, (150, 150))
        pixels = npimg.reshape((-1, 3))
        kmeans = KMeans(n_clusters=num_colors, n_init=10, random_state=42)
        kmeans.fit(pixels)
        centers = kmeans.cluster_centers_.astype(int).tolist()
        return centers
    
    except FileNotFoundError as e:
        logger.warning("Image file not found for color extraction: %s", image_path)
        return []
    except Exception as e:
        logger.error("Color extraction failed for %s: %s", image_path, e)
        return []

def branding_guidelines_features(image_path: str, brand_colors: list | None = None, brand_logo_hash: object | None = None) -> dict:
    """
    Extract branding features from screenshot.
    
    Includes dominant colors, perceptual hash, and color difference from reference.
    
    Args:
        image_path: Path to screenshot image
        brand_colors: Reference brand colors for comparison (optional)
        brand_logo_hash: Reference logo hash for matching (optional)
    
    Returns:
        Dictionary with branding metrics
    """
    info = {
        "brand_colors": [],
        "avg_color_diff": -1.0,
        "logo_hash": None,
        "logo_match_score": -1
    }
    try:
        if not os.path.exists(image_path):
            logger.warning("Image not found for branding analysis: %s", image_path)
            return info
        
        img = Image.open(image_path).convert("RGB")
        info["brand_colors"] = extract_brand_colors(image_path, 3)
        
        # Extract perceptual hash for logo matching
        ph = imagehash.phash(img)
        info["logo_hash"] = str(ph)
        
        # Compare with reference logo hash if provided
        if brand_logo_hash and hasattr(brand_logo_hash, "hash") and brand_logo_hash.hash.shape == ph.hash.shape:
            info["logo_match_score"] = ph - brand_logo_hash
        
        # Compare colors with reference colors if provided
        if brand_colors:
            try:
                ref_labs = [convert_color(sRGBColor(*c, is_upscaled=True), LabColor) for c in brand_colors]
                dom_labs = [convert_color(sRGBColor(*c, is_upscaled=True), LabColor) for c in info["brand_colors"]]
                dists = []
                for dl in dom_labs:
                    dists.extend([delta_e_cie2000(dl, rl) for rl in ref_labs])
                if dists:
                    info["avg_color_diff"] = float(np.mean(dists))
            except Exception as e:
                logger.warning("Color comparison failed: %s", e)
                info["avg_color_diff"] = -1.0
    
    except FileNotFoundError:
        logger.warning("Image file not found for branding analysis: %s", image_path)
    except Exception as e:
        logger.error("Branding feature extraction failed for %s: %s", image_path, e)
    
    return info

# ------------------ Favicon ------------------
def _save_favicon_from_data_url(data_url, dst_basename):
    header, encoded = data_url.split(",", 1)
    mime = re.match(r"data:(.*?);base64", header).group(1)
    ext = mimetypes.guess_extension(mime) or ".ico"
    out_path = os.path.join(SCREENS_DIR, f"{dst_basename}_favicon{ext}")
    with open(out_path, "wb") as f:
        f.write(base64.b64decode(encoded))
    return out_path

async def detect_favicon_async(domain_or_url):
    url = domain_or_url if domain_or_url.startswith("http") else "https://" + domain_or_url
    try:
        context = await _async_browser_manager.get_context()
        page = await context.new_page()
        
        await page.goto(url, timeout=5000)
        icons = await page.locator("link[rel*='icon']").evaluate_all("els => els.map(el => el.href)")
        await page.close()
        if icons and len(icons) > 0:
            return True, icons[0]
        else:
            parsed = urlparse(url)
            return True, f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    except Exception:
        return False, None

async def get_favicon_features_async(url):
    feats = {
        "favicon_detected": False,
        "favicon_url": None,
        "favicon_size": -1,
        "favicon_hash": None,
        "favicon_colors": []
    }
    has_fav, icon_url = await detect_favicon_async(url)
    feats["favicon_detected"] = bool(has_fav and icon_url)
    feats["favicon_url"] = icon_url
    if not feats["favicon_detected"]:
        return feats

    try:
        # network/IO part in thread pool
        parsed = tldextract.extract(url)
        base = parsed.domain or "site"
        
        # We'll use asyncio.to_thread for the requests part
        def _fetch_favicon():
            if icon_url and icon_url.startswith("data:image"):
                return _save_favicon_from_data_url(icon_url, base)
            else:
                resp = requests.get(icon_url, timeout=8, stream=True)
                if resp.status_code != 200 or len(resp.content) < 50:
                    return None
                ext = os.path.splitext(urlparse(icon_url).path)[-1] or ".ico"
                path = os.path.join(SCREENS_DIR, f"{base}_favicon{ext}")
                with open(path, "wb") as f:
                    f.write(resp.content)
                return path
        
        path = await asyncio.to_thread(_fetch_favicon)
        if not path:
            return feats

        # Image processing in thread pool
        def _process_image(p):
            img = Image.open(p).convert("RGB").resize((32, 32))
            return str(img.size), str(imagehash.phash(img)), extract_brand_colors(p, 3)
            
        feats["favicon_size"], feats["favicon_hash"], feats["favicon_colors"] = await asyncio.to_thread(_process_image, path)
    except Exception:
        pass
    return feats

# ------------------ OCR (EasyOCR) ------------------
def extract_ocr_text(image_path: str) -> str:
    """
    Extract visible text from screenshot using EasyOCR.
    
    Performs text recognition on full page screenshot.
    Results are normalized and whitespace-cleaned.
    
    Args:
        image_path: Path to screenshot file
    
    Returns:
        Extracted text string (empty if extraction fails)
    """
    global _ocr_call_count
    
    def _do_ocr(img_np):
        """Inner function to perform OCR (can be retried on OOM)."""
        reader = _get_ocr_reader()
        results = reader.readtext(img_np, detail=0)  # detail=0 → only text
        txt = " ".join(results)
        return re.sub(r"\s+", " ", txt).strip()
    
    try:
        if not os.path.exists(image_path):
            logger.warning("Image file not found for OCR: %s", image_path)
            return ""
        
        # Optimize image for OCR to save VRAM
        img = Image.open(image_path).convert('L') # Convert to grayscale
        
        # Downscale if too large (limit width to 800px for 2GB VRAM)
        max_width = 800
        if img.width > max_width:
            ratio = max_width / img.width
            new_height = int(img.height * ratio)
            img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
        
        # Force cleanup BEFORE OCR if counter is high
        if _ocr_call_count > 0 and _ocr_call_count % 3 == 0:
            torch.cuda.empty_cache()
            import gc
            gc.collect()
            
        img_np = np.array(img)
        
        # Try OCR with OOM retry safeguard
        try:
            txt = _do_ocr(img_np)
        except torch.cuda.OutOfMemoryError:
            logger.warning("⚠️ CUDA OOM during OCR, clearing cache and retrying...")
            torch.cuda.empty_cache()
            import gc
            gc.collect()
            txt = _do_ocr(img_np)  # Retry after cleanup
        
        return txt
        
    except FileNotFoundError:
        logger.warning("Image file not found for OCR: %s", image_path)
        return ""
    except Exception as e:
        logger.error("OCR extraction failed for %s: %s", image_path, e)
        return ""
    finally:
        # Aggressive GPU cleanup (every 3 OCR calls)
        _ocr_call_count += 1
        if _ocr_call_count % 3 == 0:
            try:
                torch.cuda.empty_cache()
                import gc
                gc.collect()
            except Exception:
                pass

# ------------------ Sharpness ------------------
def laplacian_variance(image_path: str, min_size: int = 50) -> float:
    """
    Calculate Laplacian variance of image (sharpness metric).
    
    Measures image clarity/focus. Higher variance = sharper image.
    Used to detect blurry/low-quality screenshots (potential indicator of spoofed content).
    
    Args:
        image_path: Path to image file
        min_size: Minimum contour size to process (default 50 pixels)
    
    Returns:
        Variance value (higher = sharper), or NaN if extraction fails
    """
    try:
        if not os.path.exists(image_path):
            logger.warning("Image file not found for Laplacian: %s", image_path)
            return float("nan")
        
        img = cv2.imread(image_path)
        if img is None:
            logger.warning("Could not read image for Laplacian: %s", image_path)
            return float("nan")
            
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        variances = []
        for cnt in contours:
            x, y, w, h = cv2.boundingRect(cnt)
            if w < min_size or h < min_size:
                continue
            roi = gray[y:y+h, x:x+w]
            variances.append(cv2.Laplacian(roi, cv2.CV_64F).var())
        
        if variances:
            return float(np.mean(variances))
        
        # Fallback to full image if no large-enough contours are found
        return float(cv2.Laplacian(gray, cv2.CV_64F).var())
    
    except FileNotFoundError:
        logger.warning("Image file not found for Laplacian: %s", image_path)
        return float("nan")
    except Exception as e:
        logger.error("Laplacian variance failed for %s: %s", image_path, e)
        return float("nan")