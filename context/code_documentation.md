# Phishing Pipeline Code Documentation

This document provides a comprehensive overview of the `phishing_pipeline` codebase, detailing the purpose of each file and the functionality of its methods.

---

## 1. File: `phishing_pipeline/__init__.py`

**Purpose of the file:**
This file serves as the initialization module for the `phishing_pipeline` package. It is designed to be lightweight, exposing only the essential entry points for the pipeline without triggering the import of heavy dependencies (like ML models or browser automation tools) until they are actually needed. This optimization ensures that importing the package is fast.

**Functions:**

* **`run_pipeline(*args, **kwargs)`**
  * Acts as a lazy-loading wrapper for the main pipeline execution logic.
  * Imports the implementation from `.pipeline` only when this function is invoked.
  * Accepts any arguments required by the underlying `run_pipeline` function.
  * Prevents performance bottlenecks during the initial package import.

* **`package_results(*args, **kwargs)`**
  * Acts as a lazy-loading wrapper for the result packaging functionality.
  * Imports the implementation from `.pipeline` only when called.
  * Facilitates the compression and organization of output files (CSVs, evidence) into a submission-ready ZIP file.

---

## 2. File: `phishing_pipeline/config.py`

**Purpose of the file:**
This file acts as the central configuration hub for the entire project. It defines all the necessary file paths, directory structures, global constants, and tunable parameters. By centralizing these values, it ensures that changes to paths or thresholds need only be made in one place.

**Variables and Constants:**

* **Directory Paths:** `BASE_DIR`, `UPLOADS_DIR`, `SCREENS_DIR`, `EVIDENCE_DIR`.
* **File Paths:** Paths for CSVs (`FEATURES_CSV`, `FEATURES_ENRICH`), ML models (`MODEL_LABEL_PATH`, etc.), and GeoIP databases (`ASN_DB_PATH`, `CITY_DB_PATH`).
* **Column Names:** Defines standard column names like `DOMAIN_COL` and `ORG_COL` for consistency across dataframes.
* **System Limits:** `MAX_VARIANTS` and `MAX_WORKERS` to control processing scale.

---

## 3. File: `phishing_pipeline/features.py`

**Purpose of the file:**
This module is responsible for extracting "lightweight" features from URLs. It handles structural analysis (e.g., length, character counts), lexical analysis (e.g., finding keywords), and network-layer checks (e.g., DNS resolution, SSL certificate inspection). These features are fast to compute compared to visual analysis.

**Functions:**

* **`_normalize_and_parse_url(url: str)`**
  * Helper function that standardizes the input URL by adding a protocol (https) if missing.
  * Parses the URL using `urllib` to separate it into components (scheme, netloc, path).
  * Validates the URL to ensure it is not empty or excessively long.
  * Returns both the normalized string and the parsed result object for downstream use.

* **`extract_url_features(url: str)`**
  * Analyzes the overall structure of the URL string.
  * Counts specific characters that are often used in phishing (dots, hyphens, @ symbols).
  * Calculates the length of the URL and the length of the domain part.
  * Detects the presence of suspicious patterns like IP addresses used as domains.

* **`extract_subdomain_features(url: str)`**
  * Uses `tldextract` to isolate the subdomain part of the URL.
  * Counts the number of subdomain levels (e.g., `secure.login.example.com` has 2 subdomains).
  * Calculates the average length of these subdomain parts.
  * Checks for repeated digits or hyphens which are common in machine-generated phishing domains.

* **`extract_path_features(url: str)`**
  * Focuses on the path, query parameters, and fragments of the URL.
  * Measures the length of the path.
  * Checks for the existence of query strings (often used to pass stolen credentials).
  * Detects if the URL uses anchors/fragments.

* **`entropy_of_string(s: str)`**
  * Mathematically calculates the Shannon entropy of a given string.
  * A generic helper used to measure how "random" or "chaotic" a string looks.
  * High entropy often indicates algorithmic generation (e.g., `a8f93ha.com`) vs. human-readable dictionary words.

* **`entropy_features(url: str)`**
  * Applies the entropy calculation to specific parts of the URL.
  * Computes entropy for the full URL string.
  * Computes entropy for just the domain name.
  * Returns these values as features to help detect DGA (Domain Generation Algorithm) domains.

* **`get_ip_address(url: str)`**
  * Performs a DNS lookup to resolve the hostname to an IP address.
  * Uses `socket.gethostbyname` to find the A record.
  * Includes error handling for DNS timeouts or non-existent domains (NxDomain).
  * Returns the IP string or None if resolution fails.

* **`ssl_features(url: str)`**
  * Initiates a secure connection to the target server to inspect its SSL/TLS certificate.
  * Verifies if an SSL certificate is present and currently valid (not expired).
  * Calculates the number of days remaining until the certificate expires (phishing sites often use short-lived free certs).
  * Extracts the Issuer's Organization to see if it's a paid CA (e.g., DigiCert) or free/automated (e.g., Let's Encrypt).

---

## 4. File: `phishing_pipeline/geoip_utils.py`

**Purpose of the file:**
This utility module handles the enrichment of IP addresses with geolocation and infrastructure data. It interfaces with local MaxMind GeoIP databases to provide physical context (Country, City) and network context (ASN, ISP) for the hosting server.

**Functions:**

* **`enrich_with_geoip(df, asn_db_path, city_db_path)`**
  * Accepts a Pandas DataFrame containing a column of IP addresses.
  * Iterates through the IPs and queries the ASN database to find the Autonomous System Number and Organization (ISP).
  * Queries the City database to find the Country, Region, and City.
  * Handles potential errors (like missing database files) gracefully by filling fields with None.
  * Returns the original DataFrame enriched with new columns (`asn`, `asn_org`, `country`, `region`, `city`).

---

## 5. File: `phishing_pipeline/model_utils.py`

**Purpose of the file:**
This module manages the lifecycle of machine learning artifacts. It is responsible for loading the pre-trained XGBoost models and their associated preprocessing transformers (encoders, scalers, imputers) from disk into memory.

**Functions:**

* **`load_models_and_preproc()`**
  * Loads the primary risk classification model (`xgb_label_model.joblib`).
  * Loads the source attribution model (`xgb_source_model.joblib`).
  * Loads the LabelEncoder to convert numerical predictions back to text classes (Phishing/Legitimate).
  * Loads class definitions, feature column lists, Scalers (for normalization), and Imputers (for handling missing data).
  * Returns all these loaded objects in a tuple for the pipeline to use.

---

## 6. File: `phishing_pipeline/pipeline.py`

**Purpose of the file:**
This is the core orchestration engine of the application. It ties together all valid components—preprocessing, feature extraction, model prediction, evidence generation, and reporting—into a cohesive workflow. It uses a **Chunked Processing Pipeline** to efficiently process thousands of URLs while preventing GPU memory exhaustion.

**Constants:**

* **`CHUNK_SIZE = 50`** — Number of domains processed per batch. Tunable per system (50 for local 2GB VRAM, 100-150 for Kaggle T4).

**Functions:**

* **`normalize_text(s)`**
  * A robust text cleaning utility.
  * Removes all non-alphanumeric characters from a string.
  * Converts the text to lowercase.
  * Ensures consistent string matching for brand names and sources.

* **`domain_tokens_from_url(url)`**
  * Deconstructs a URL into its constituent keywords.
  * Uses `tldextract` to separate subdomains, domain, and suffix.
  * Splits subdomains by dots to isolate individual words.
  * Returns a list of tokens used for brand keyword matching.

* **`adjust_source(org_name, whitelisted_domain, ml_source)`**
  * Refines the "Source of Detection" using a heuristic approach.
  * Checks if the legitimate domain or organization name matches known high-priority entities (features "SBI", "IRCTC", etc.).
  * Overrides the Machine Learning model's source prediction if a deterministic keyword match is found.
  * Maps keywords to broader categories (e.g., "hdfc" -> "Banking/Financial").

* **`process_urls(input_csv, output_csv, network_semaphore)`**
  * The main asynchronous driver for the feature extraction phase.
  * **Architecture:** Chunked Processing — processes domains in batches of `CHUNK_SIZE` to prevent GPU memory fragmentation.
  * Within each chunk: Network features + Screenshots run in parallel via `asyncio.gather()`.
  * Between chunks: Explicit GPU cleanup with `torch.cuda.empty_cache()` and `gc.collect()`.
  * Displays a progress bar showing Phase 1 domains processed.
  * No longer uses `ResourceMonitor` (replaced by chunking strategy).

* **`format_evidence_filename(org_name, domain, serial_no, ...)`**
  * Standardizes the naming convention for evidence files.
  * Constructs a filename using the organization tag, the domain name, and a unique serial number.
  * Ensures the target evidence directory exists.
  * Returns both the full absolute path and the relative filename.

* **`move_screenshot_to_evidence(domain_url, pdf_path)`**
  * Locates the raw PNG screenshot captured earlier in the pipeline.
  * Embeds this image into a new PDF document using the `FPDF` library.
  * Calculates proper dimensions to fit the image on an A4 page.
  * Saves the PDF to the final evidence folder.
  * Handles errors (like missing screenshots) by creating a PDF with an error message.

* **`reclassify_label(domain, registrar, host, dns, ocr_text)`**
  * Implements the final decision logic for classifying a domain.
  * Combines the ML prediction with rule-based heuristics.
  * Checks for "red flag" infrastructure (suspicious registrars like "Freenom" or hosts like "Contabo").
  * Uses OCR text and URL tokens to find brand impersonation attempts.
  * Determines the final label: "Phishing", "Suspected", or "Legitimate".

* **`run_pipeline(holdout_folder, ps02_whitelist_file, ...)`**
  * The high-level entry point that runs the full end-to-end process.
  * **Master Progress Bar:** Tracks overall pipeline progress across 3 phases (Phase 1: 60%, Phase 2: 35%, Phase 3: 5%).
  * **Phase 1:** Triggers `process_urls` for feature extraction, enriches with GeoIP data.
  * **Phase 2:** Performs WHOIS lookups with `RateLimiter` (20 req/min), classifies domains. WHOIS timeout set to 15 seconds.
  * **Phase 3:** Generates evidence PDFs, writes final CSV, applies filtering.
  * Displays final summary with total time, average speed per domain.

* **`package_results(output_file, zip_path)`**
  * Creates the final deliverable artifact.
  * Converts the main CSV output into an Excel file as per submission requirements.
  * Zips the Evidence folder and the Excel file together.
  * Ensures the zip file follows the strict directory structure required by the evaluation platform.

* **`cleanup_generated_artifacts(root_dir, zip_path)`**
  * Performs housekeeping after the pipeline finishes.
  * Deletes temporary CSVs, the screens folder, and the raw evidence folder.
  * Preserves logic files and the final Output ZIP.
  * Keeps the workspace clean for the next run.

---

## 7. File: `phishing_pipeline/resource_manager.py`

**Purpose of the file:**
This module acts as a safeguard for system stability. Since the pipeline runs resource-heavy tasks like browser automation (RAM) and neural network inference (GPU/CPU), this manager monitors system vitals and throttles execution to prevent crashes or "Out of Memory" errors.

> **Note:** As of the chunked processing update, `ResourceMonitor` is **no longer actively used** by `process_urls()`. GPU memory management is now handled through explicit `torch.cuda.empty_cache()` + `gc.collect()` calls between chunks. The file is retained for potential future use.

**Functions:**

* **`ResourceMonitor.__init__(cpu_threshold, ram_threshold, ...)`**
  * Configures the safety limits for the hardware (e.g., 90% CPU, 85% RAM).
  * Detects if a CUDA-enabled GPU is available to track VRAM usage.
  * Sets the polling interval for checks.

* **`check_resources()`**
  * Takes a snapshot of current system health.
  * Queries `psutil` for CPU and RAM percentage.
  * Queries PyTorch for GPU memory usage (if applicable).
  * Returns `True` only if all metrics are below the configured safety thresholds.
  * Includes logic to force garbage collection or cache clearing if limits are approached.

* **`wait_for_resources()`**
  * An asynchronous "gatekeeper" method.
  * If `check_resources()` returns `False`, this method sleeps (non-blocking) and retries.
  * Ensures that new resource-intensive tasks are only started when the system has capacity.
  * Prevents the pipeline from spawning thousands of browsers and crashing the OS.

---

## 7b. File: `phishing_pipeline/rate_limiter.py` *(NEW)*

**Purpose of the file:**
This utility module implements a time-based rate limiter for throttling WHOIS and other network requests. It ensures compliance with server rate limits to prevent IP blocking. Used by `run_pipeline()` during Phase 2 WHOIS lookups.

**Class: `RateLimiter`**

* **`__init__(requests_per_minute=20)`**
  * Configures the maximum allowed request rate (default: 20 req/min = 3s delay).
  * Initializes an `asyncio.Lock` for thread-safe async operation.
  * Calculates the minimum delay between requests.

* **`acquire()`**
  * Async method — blocks (non-blocking sleep) until enough time has passed since the last request.
  * Called before each WHOIS lookup to space out requests.
  * Safe to call from multiple coroutines.

* **`reset()`**
  * Resets the internal timer. Useful for testing or pipeline restarts.

---

## 8. File: `phishing_pipeline/shortlisting.py`

**Purpose of the file:**
This module implements the "Shortlisting" phase. It filters a massive list of potential phishing URLs down to the most relevant candidates by comparing them against a whitelist of legitimate domains (e.g., matching "sbi-verify.com" against "sbi.co.in"). It uses fuzzy string matching to find spoofing attempts.

**Functions:**

* **`normalize_url(url)`**
  * Standardizes URLs for comparison.
  * Handles "homoglyphs" (characters that look alike, like Cyrillic 'a' vs Latin 'a') using unicode normalization.
  * Strips protocol and converts to lowercase.

* **`get_clean_parts(url)`**
  * Extracts the "core" parts of a domain that carry meaning.
  * Removes TLDs (com, org) and generic subdomains (www).
  * Returns a set of unique string tokens (e.g., `["facebook", "login"]`).

* **`is_similar_advanced(cand_url, legit_url, ...)`**
  * The core comparison engine.
  * Uses `Jaro-Winkler` distance to measure string similarity between the candidate and the legitimate domain.
  * Uses `Attributes` like `fuzz.token_set_ratio` to find partial matches.
  * Returns `True` if the candidate is confusingly similar to the legitimate domain.

* **`load_urls_from_excel_folder(folder_path)`**
  * Scans a directory for Excel files containing raw URL feeds.
  * Smartly identifies the column containing URLs (handling variable headers like "URL", "Domain Name").
  * Aggregates all unique targets into a single set.

* **`run_shortlisting_process(...)`**
  * Orchestrates the shortlisting workflow.
  * Loads the legitimate whitelist and the target URL feeds.
  * Runs the `is_similar_advanced` check on every candidate-whitelist pair.
  * Generates the `holdout.csv` file containing only the suspicious matches.

---

## 9. File: `phishing_pipeline/utils.py`

**Purpose of the file:**
This file contains lower-level utility functions and acts as the bridge between the raw features and the pipeline orchestration. It manages the specific semaphores for concurrency control and provides wrapper functions that combine multiple feature extraction steps into single callable units.

**Concurrency Settings (Tunable):**

| Setting | Local (2GB VRAM) | Kaggle T4 (15GB) | Purpose |
|---------|------------------|-------------------|---------|
| `MAX_CONCURRENT_OCR` | 1 | 3 | GPU-bound OCR tasks |
| `MAX_CONCURRENT_SCREENSHOTS` | 10 | 16 | Browser instances (I/O bound) |
| `MAX_CONCURRENT_IMAGE_PROCESSING` | 5 | 10 | CPU image analysis |
| `MAX_CONCURRENT_CPU_TASKS` | 20 | 40 | DNS, URL parsing, etc. |

**Functions:**

* **`_get_*_semaphore()` (OCR, Screenshot, CPU)**
  * Implements the Singleton pattern for asyncio Semaphores.
  * Ensures that all parts of the code share the same limits (e.g., only 1 OCR task at a time).
  * Prevents creating multiple separate throttles that would defeat the purpose.

* **`extract_all_features(url)`**
  * A synchronous wrapper for extracting everything.
  * Useful for testing a single URL in isolation.
  * Calls all the individual feature extractors and returns a consolidated dictionary.

* **`extract_network_features_async(url, semaphore)`**
  * Bundles all the fast, CPU-bound extraction tasks.
  * Runs `get_ip_address`, `ssl_features`, `extract_url_features`, etc. concurrently.
  * Used as the "Stage 1" processor in the pipeline.

* **`extract_visual_features_async(url, semaphore)`**
  * Bundles all the slow, I/O-bound visual tasks.
  * Triggers the screenshot capture.
  * Runs OCR, color analysis, and sharpness checks on the captured image.
  * Used as the "Stage 2" processor in the pipeline.

* **`_safe_extract_*(path)` (branding, ocr, laplacian)**
  * Decorators/Wrappers for the visual extraction functions.
  * Add try-catch blocks around the complex image processing calls.
  * Ensure that a failure in one feature (e.g., OCR fails) does not crash the entire pipeline for that URL.
  * Return "safe" default values (like empty strings or NaNs) on failure.

---

## 10. File: `phishing_pipeline/visual_features.py`

**Purpose of the file:**
This is the heavy-lifting module for visual analysis. It houses the code for controlling the headless browser (Playwright) to take screenshots, running the Optical Character Recognition (OCR) model (EasyOCR), and performing computer vision tasks like logo detection and image quality assessment. Includes **pre-flight checks** to skip dead/unreachable domains before expensive browser operations.

**Classes:**

* **`AsyncBrowserManager`**
  * Manages the lifecycle of the async Playwright browser to prevent "Context closed" errors.
  * Auto-restarts the browser if it crashes mid-operation.
  * Thread-safe via `asyncio.Lock`.
  * Methods: `get_context()`, `_start_new_session()`, `_force_close()`, `close()`.

**Functions — Initialization:**

* **`_get_browser_context()`**
  * Lazy-loading initializer for the sync Playwright browser.
  * Ensures the browser process is only started when the first screenshot is requested.
  * Returns a shared browser context to be reused, saving startup time.

* **`_get_ocr_reader()`**
  * Lazy-loading initializer for the EasyOCR model.
  * Loads the neural network weights into VRAM (or RAM) only on the first call.
  * Checks for GPU availability to enable hardware acceleration.

**Functions — Pre-Flight Checks** *(NEW)*:

* **`quick_dns_check(host, timeout=2.0)`**
  * Performs async DNS resolution check before attempting screenshot.
  * Skips dead domains in ~0.5s instead of waiting 5s for browser timeout.
  * Saves 4-5 seconds per dead domain.
  * Handles `TimeoutError`, `socket.gaierror`, and `OSError`.

* **`is_site_reachable(url, timeout=1.5)`**
  * Sends a lightweight HTTP HEAD request to verify site responds.
  * Uses `aiohttp` with SSL verification disabled for speed.
  * Any response (even 403/404) counts as reachable.
  * Saves 3-4 seconds per unreachable site.

**Functions — Screenshot Capture:**

* **`capture_screenshot_async(url, out_file)`**
  * **Pre-flight:** Runs DNS check (2s) and HEAD request (1.5s) before launching browser. Skips if either fails.
  * Navigates to the URL using a headless Chromium browser via `AsyncBrowserManager`.
  * Waits for the page to load (DOM Content Loaded, 5s timeout).
  * Saves a full-page screenshot to the specified path.
  * Includes auto-retry logic (2 attempts) to handle browser crashes or timeouts.
  * Automatic browser restart if context dies mid-operation.

**Functions — Image Analysis:**

* **`extract_brand_colors(image_path, num_colors)`**
  * Uses K-Means clustering to analyze the image's color palette.
  * Identifies the `k` most dominant colors (e.g., the primary red of Netflix).
  * Used to compare against known brand guidelines.

* **`branding_guidelines_features(image_path)`**
  * Extracts a "perceptual hash" of the visual content.
  * Allows for "fuzzy" image matching (finding a logo even if it's slightly resized or shifted).
  * Returns metrics indicating how closely the site visually resembles a target brand.

* **`extract_ocr_text(image_path)`**
  * The primary text extraction function.
  * Pre-processes the image (converts to grayscale, resizes to max 800px) to reduce GPU memory.
  * Includes periodic GPU cleanup every 3 OCR calls (`torch.cuda.empty_cache()` + `gc.collect()`).
  * OOM retry safeguard: if CUDA OOM occurs, clears cache and retries once.
  * Feeds the image to EasyOCR to read all visible text on the webpage.
  * Returns the raw text string, which is crucial for detecting keywords like "Login", "Password", or "Bank".

* **`laplacian_variance(image_path)`**
  * Computes the variance of the Laplacian (a measure of edge detection).
  * Acts as a "Blur Detector". High variance = Sharp image; Low variance = Blurry.
  * Helps identify low-quality screenshots or broken pages that shouldn't be analyzed deeply.

* **`get_favicon_features_async(url)`**
  * Detects the website's favicon (the small icon in the tab).
  * Downloads the icon and analyzes its hash and color.
  * Helps detect if a phishing site is reusing the exact icon of the victim brand.
