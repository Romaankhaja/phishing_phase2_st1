# Legacy shortlisting implementation.
import os
import pandas as pd
import logging
import tldextract
from rapidfuzz import fuzz
import jellyfish
import unicodedata
import glob
import sys
import re
 
# Attempt relative config import (like your original)
try:
    from .config import ROOT_DIR
except Exception:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from phishing_pipeline.config import ROOT_DIR

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Defaults (used when caller doesn't provide explicit paths)
DEFAULT_holdout_folder = os.path.join(ROOT_DIR, "data", "holdout_sets", "PS-02_hold-out_Set_2")
DEFAULT_TARGET_URLS_FILE = os.path.join(ROOT_DIR, "data", "target_urls.txt")
DEFAULT_WHITELIST_FILE = os.path.join(ROOT_DIR, "data", "whitelists", "PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx")
DEFAULT_MERGED_TARGET_FILE = os.path.join(ROOT_DIR, "output", "merge.txt")
DEFAULT_FOUND_FILE = os.path.join(ROOT_DIR, "output", "found.txt")
DEFAULT_OUTPUT_FILE = os.path.join(ROOT_DIR, "output", "holdout.csv")

GENERIC_DOMAIN_PARTS = {
    'com', 'in', 'gov', 'co', 'net', 'www', 'io', 'xyz', 'app', 'site',
    'online', 'shop', 'store', 'info', 'live', 'club', 'dev', 'io', 'ai'
}
GENERIC_PRIMARY_DOMAINS = {'mail', 'email', 'gov', 'nic'}
HOMOGLYPHS = {
    "а": "a", "ο": "o", "е": "e", "і": "i", "ѕ": "s", "р": "p", "с": "c", "υ": "u", "ν": "v",
    "０": "0", "１": "1", "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E", "Ｆ": "F", "Ｇ": "G",
    "Ｈ": "H", "Ｉ": "I", "Ｊ": "J", "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N",
    "Ｏ": "O", "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T", "Ｕ": "U",
    "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y", "Ｚ": "Z",
    "1": "l", "0": "o", "3": "e", "5": "s", "@": "a"
}

def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = str(url).strip().lower()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    url = "".join(HOMOGLYPHS.get(ch, ch) for ch in unicodedata.normalize("NFKC", url))
    return url

def get_clean_parts(url: str) -> set:
    try:
        ext = tldextract.extract(url)
        subdomain_parts = set(ext.subdomain.split('.')) if ext.subdomain else set()
        domain_part = {ext.domain} if ext.domain else set()
        all_parts = subdomain_parts.union(domain_part)
        clean_parts = {
            part for part in all_parts
            if part not in GENERIC_DOMAIN_PARTS and len(part) > 2
        }
        return clean_parts
    except Exception:
        return set()

def get_primary_part(url: str) -> str:
    try:
        return tldextract.extract(url).domain
    except Exception:
        return ""

def is_similar_advanced(cand_url_norm: str, legit_url_norm: str,
                        cand_primary: str, legit_primary: str, legit_parts: set) -> bool:
    if not cand_primary or not legit_primary:
        return False
    if cand_url_norm == legit_url_norm:
        return False
    try:
        if jellyfish.jaro_winkler_similarity(cand_primary, legit_primary) >= 0.85:
            return True
    except Exception:
        pass
    try:
        if fuzz.token_set_ratio(cand_primary, legit_primary) >= 90:
            return True
    except Exception:
        pass
    return False

def _discover_excel_files(folder_path: str) -> list[str]:
    if os.path.isfile(folder_path) and folder_path.endswith((".xlsx", ".xls", ".csv")):
        files = [folder_path]
    else:
        files = glob.glob(os.path.join(folder_path, "*.xlsx")) + glob.glob(os.path.join(folder_path, "*.xls")) + glob.glob(os.path.join(folder_path, "*.csv"))
    return [f for f in files if not os.path.basename(f).startswith("~$")]


def _looks_like_url_value(value: str) -> bool:
    text = str(value or "").strip()
    if not text or " " in text:
        return False
    return bool(
        re.match(
            r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#].*)?$",
            text,
            re.IGNORECASE,
        )
    )


def _safe_first_column_url_fallback(values: list[str]) -> bool:
    normalized_values = [
        str(value or "").strip()
        for value in values
        if str(value or "").strip().lower() not in {"url", "domain", "domain_name", "website"}
    ]
    if not normalized_values:
        return False
    url_like_count = sum(1 for value in normalized_values if _looks_like_url_value(value))
    return url_like_count >= max(1, int(len(normalized_values) * 0.6))


def load_url_records_from_excel_folder(folder_path, limit: int | None = None):
    logger.info(f"Reading Excel files from: {folder_path}")
    url_records: dict[str, dict] = {}
    max_urls = None if limit is None else max(0, int(limit))

    files = _discover_excel_files(folder_path)
    if not files:
        logger.warning(f"No .xlsx, .xls, or .csv files found in {folder_path}.")
        return []
    logger.info(f"Found {len(files)} files.")
    if max_urls == 0:
        logger.info("Target URL limit set to 0; skipping Excel URL loading.")
        return []

    for f in files:
        try:
            if f.endswith(".csv"):
                header_df = pd.read_csv(f, nrows=0)
            else:
                header_df = pd.read_excel(f, nrows=0)
            possible_cols = ["Identified Phishing/Suspected Domain Name", "URL", "url", "Domain", "domain_name"]
            found_col = None
            fallback_to_first_col = False
            for col in possible_cols:
                if col in header_df.columns:
                    found_col = col
                    break
            if not found_col:
                for col in header_df.columns:
                    if "url" in str(col).lower() or "domain" in str(col).lower():
                        found_col = col
                        break
            if not found_col:
                found_col = header_df.columns[0]
                fallback_to_first_col = True
            remaining_limit = None
            if max_urls is not None:
                remaining_limit = max_urls - len(url_records)
                if remaining_limit <= 0:
                    logger.info("Reached target URL limit (%d total).", max_urls)
                    break

            if f.endswith(".csv"):
                df = pd.read_csv(
                    f,
                    usecols=[found_col],
                    nrows=remaining_limit,
                )
            else:
                df = pd.read_excel(
                    f,
                    usecols=[found_col],
                    nrows=remaining_limit,
                )
            urls = df[found_col].dropna().astype(str)
            if fallback_to_first_col:
                sample_values = urls.head(5).tolist()
                sample_looks_like_urls = _safe_first_column_url_fallback(sample_values)
                if sample_looks_like_urls:
                    logger.debug("No known URL column in %s. Using first column: %s", f, found_col)
                else:
                    logger.warning("No known URL column in %s. Using first column: %s", f, found_col)
            added_from_file = 0
            workbook_name = os.path.basename(f)
            for url in urls:
                normalized = url.strip().lower()
                if not normalized:
                    continue
                record = url_records.get(normalized)
                if record is None:
                    record = {
                        "url": normalized,
                        "source_workbooks": [],
                    }
                    url_records[normalized] = record
                    added_from_file += 1
                if workbook_name not in record["source_workbooks"]:
                    record["source_workbooks"].append(workbook_name)
                if max_urls is not None and len(url_records) >= max_urls:
                    logger.info(
                        "Loaded %d new URLs from '%s' before reaching target limit (%d total).",
                        added_from_file,
                        f,
                        max_urls,
                    )
                    return list(url_records.values())
            logger.info(f"Loaded {len(urls)} URLs from '{f}'")
        except Exception as e:
            logger.error(f"Failed to read {f}: {e}")
    return list(url_records.values())


def load_urls_from_excel_folder(folder_path, limit: int | None = None):
    url_records = load_url_records_from_excel_folder(folder_path, limit=limit)
    return {record["url"] for record in url_records}

def load_urls_from_txt(file_path):
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_path}")
        return set()
    with open(file_path, "r", encoding="utf-8") as f:
        urls = {line.strip().lower() for line in f if line.strip()}
    if urls:
        logger.info(f"Loaded {len(urls)} URLs from {file_path}")
    return urls

def write_list_to_txt(url_list, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        for url in sorted(url_list):
            f.write(f"{url}\n")
    logger.info(f"Saved {len(url_list)} URLs to {output_file}")

def run_shortlisting_process(holdout_folder: str | None = None,
                             target_urls_file: str | None = None,
                             whitelist_file: str | None = None,
                             merged_target_file: str | None = None,
                             found_file: str | None = None,
                             output_file: str | None = None,
                             limit_whitelisted: int | None = None,
                             write_outputs: bool = True) -> pd.DataFrame:
    """
    Run the shortlisting process and return a pandas DataFrame of matches.

    Parameters allow callers (e.g., main_controller.py) to pass custom paths.
    """
    holdout_folder = holdout_folder or DEFAULT_holdout_folder
    target_urls_file = target_urls_file or DEFAULT_TARGET_URLS_FILE
    whitelist_file = whitelist_file or DEFAULT_WHITELIST_FILE
    merged_target_file = merged_target_file or DEFAULT_MERGED_TARGET_FILE
    found_file = found_file or DEFAULT_FOUND_FILE
    output_file = output_file or DEFAULT_OUTPUT_FILE

    logger.info("--- Step 1: Combine URL sources ---")
    excel_urls = load_urls_from_excel_folder(holdout_folder)
    txt_urls = load_urls_from_txt(target_urls_file)
    master_urls = excel_urls.union(txt_urls)
    logger.info(f"Total {len(master_urls)} unique URLs in the master list.")
    if write_outputs:
        write_list_to_txt(master_urls, merged_target_file)

    logger.info("--- Step 3: Find duplicates (found.txt) ---")
    found_urls = excel_urls.intersection(txt_urls)
    logger.info(f"Found {len(found_urls)} URLs that are in BOTH sources.")
    if write_outputs:
        write_list_to_txt(found_urls, found_file)

    logger.info("--- Step 2: Find similar domains (holdout.csv) ---")
    try:
        wl_df = pd.read_excel(whitelist_file)
        # Normalize column names if necessary
        wl_df.rename(columns={
            "Cooresponding CSE": "Cooresponding CSE",
            "Legitimate Domains": "Legitimate Domains"
        }, inplace=True)
        if "Cooresponding CSE" not in wl_df.columns or "Legitimate Domains" not in wl_df.columns:
            logger.error("Whitelist file must contain 'Cooresponding CSE' and 'Legitimate Domains' columns.")
            return pd.DataFrame()
        wl_df["Cooresponding CSE"] = wl_df["Cooresponding CSE"].ffill()
        if limit_whitelisted:
            wl_df = wl_df.head(limit_whitelisted)
    except FileNotFoundError:
        logger.error(f"Whitelist file not found at {whitelist_file}.")
        return pd.DataFrame()
    except Exception as e:
        logger.error(f"Error reading whitelist file {whitelist_file}: {e}")
        return pd.DataFrame()

    whitelist_processed = []
    for _, row in wl_df.iterrows():
        org = str(row["Cooresponding CSE"]).strip()
        dom = str(row["Legitimate Domains"]).strip().lower()
        if not dom or dom == "nan":
            continue
        normalized_url = normalize_url(dom)
        legit_primary = get_primary_part(normalized_url)
        if legit_primary in GENERIC_PRIMARY_DOMAINS:
            logger.warning(f"Ignoring generic whitelist domain: {dom}")
            continue
        whitelist_processed.append({
            "url": dom,
            "org": org,
            "norm_url": normalized_url,
            "parts": get_clean_parts(normalized_url),
            "primary": legit_primary
        })

    logger.info("Loaded and pre-processed %d whitelisted domains.", len(whitelist_processed))

    candidates_processed = []
    for url in master_urls:
        normalized_url = normalize_url(url)
        candidates_processed.append({
            "url": url,
            "norm_url": normalized_url,
            "primary": get_primary_part(normalized_url)
        })

    all_rows, seen = [], set()
    logger.info("Starting advanced matching... (Candidates: %d, Whitelist: %d)", len(candidates_processed), len(whitelist_processed))

    for cand in candidates_processed:
        if cand["url"] in seen:
            continue
        for legit in whitelist_processed:
            if is_similar_advanced(
                cand["norm_url"], legit["norm_url"],
                cand["primary"], legit["primary"], legit["parts"]
            ):
                key = (legit["org"], legit["url"], cand["url"])
                if key not in seen:
                    seen.add(key)
                    all_rows.append({
                        "Cooresponding CSE": legit["org"],
                        "Legitimate Domains": legit["url"],
                        "Identified Phishing/Suspected Domain Name": cand["url"]
                    })
                break

    out_df = pd.DataFrame(all_rows).drop_duplicates()
    if write_outputs and not out_df.empty:
        out_df.to_csv(output_file, index=False, encoding="utf-8")
        logger.info("Shortlisted domains saved to %s with %d rows.", output_file, len(out_df))
    elif out_df.empty:
        logger.warning("No similar domains were found. Output DataFrame is empty.")

    logger.info("--- Shortlisting process complete ---")
    return out_df

# ----------------------------------------------------------------------
# Backward compatibility wrapper for legacy pipeline callers.
# ----------------------------------------------------------------------
def generate_shortlisted_csv(holdout_folder, ps02_whitelist_file,
                             limit_whitelisted=None, write_outputs=True):
    """
    Wrapper to keep legacy pipeline callers working.
    Calls run_shortlisting_process() and returns the output CSV path.
    """
    out_df = run_shortlisting_process(
        holdout_folder=holdout_folder,
        whitelist_file=ps02_whitelist_file,
        limit_whitelisted=limit_whitelisted,
        write_outputs=write_outputs
    )
    return os.path.abspath(DEFAULT_OUTPUT_FILE)  # path to holdout.csv
