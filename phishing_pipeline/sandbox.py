# phishing_pipeline/sandbox.py
"""
Sandbox malware-detection helpers for the Playwright screenshot browser.

Attaches response/download listeners to an *existing* Playwright page
so that malicious payloads (Office docs, ZIP, APK, binaries) and
automated downloads are detected **during the same visit** used for
screenshot capture — zero extra browser overhead.

Detection logic is identical to the original ``sandbox_pro.py`` script.
"""

import logging

logger = logging.getLogger(__name__)

# ── Malicious indicators (same as sandbox_pro.py) ──────────────────────────
MALICIOUS_MIME_INDICATORS = [
    "powerpoint",
    "officedocument",
    "zip",
    "octet-stream",
    "android",          # catches application/vnd.android.package-archive (.apk)
    "executable",       # catches application/x-msdownload, x-executable
    "x-msdos-program",
]

MALICIOUS_DISPOSITION_INDICATORS = [
    "download",
    "attachment",
]

# File-extension blacklist for download events (Playwright Download objects)
DANGEROUS_EXTENSIONS = {
    ".apk", ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
    ".zip", ".rar", ".7z", ".iso", ".img",
    ".docm", ".xlsm", ".pptm",  # macro-enabled Office
    ".jar", ".scr", ".dll",
}


def attach_sandbox_listeners(page, target_url: str) -> dict:
    """
    Attach response + download event listeners to a Playwright page.

    Call this **before** ``page.goto(...)``.  The returned *report* dict is
    mutated in-place by the event handlers as the page loads.

    Parameters
    ----------
    page : playwright.async_api.Page
        An open Playwright page (tab) — not yet navigated.
    target_url : str
        The URL we intend to visit (used for status-code matching).

    Returns
    -------
    dict
        A mutable report dict with keys:
        ``sandbox_verdict``, ``sandbox_reason``,
        ``sandbox_status_code``, ``sandbox_details``.
    """
    report = {
        "sandbox_verdict": "SAFE",
        "sandbox_reason": "Clean",
        "sandbox_status_code": 200,
        "sandbox_details": [],
    }

    # Normalise for URL comparison (with/without trailing slash)
    url_variants = {target_url, target_url.rstrip("/"), target_url.rstrip("/") + "/"}

    # ── Response listener ──────────────────────────────────────────────────
    def _on_response(response):
        # Record main-page HTTP status
        if response.url in url_variants or response.url.rstrip("/") in url_variants:
            report["sandbox_status_code"] = response.status

        ctype = (response.headers.get("content-type") or "").lower()
        disposition = (response.headers.get("content-disposition") or "").lower()

        mime_hit = any(ind in ctype for ind in MALICIOUS_MIME_INDICATORS)
        disp_hit = any(ind in disposition for ind in MALICIOUS_DISPOSITION_INDICATORS)

        if mime_hit or disp_hit:
            report["sandbox_verdict"] = "NOT SAFE"
            report["sandbox_reason"] = f"Malicious Payload Detected: {ctype}"
            detail = f"MIME: {ctype}"
            if disposition:
                detail += f" | Disposition: {disposition}"
            report["sandbox_details"].append(detail)
            logger.warning("🔬 Sandbox: malicious response from %s — %s", response.url, detail)

    # ── Download listener ──────────────────────────────────────────────────
    def _on_download(download):
        suggested = (download.suggested_filename or "").lower()
        ext = "." + suggested.rsplit(".", 1)[-1] if "." in suggested else ""

        report["sandbox_verdict"] = "NOT SAFE"
        if ext in DANGEROUS_EXTENSIONS:
            report["sandbox_reason"] = f"Dangerous Download Triggered: {suggested}"
        else:
            report["sandbox_reason"] = f"Direct Download Triggered: {suggested}"
        report["sandbox_details"].append(f"Download: {suggested}")
        logger.warning("🔬 Sandbox: download triggered — %s", suggested)

    page.on("response", _on_response)
    page.on("download", _on_download)

    return report


def finalize_sandbox_report(report: dict) -> dict:
    """
    Post-navigation check: if the server returned 4xx/5xx and we still
    think it's SAFE, downgrade to INCONCLUSIVE (we can't trust the page).

    Call this **after** ``page.goto(...)`` and the download-wait period.
    """
    if report["sandbox_status_code"] >= 400 and report["sandbox_verdict"] == "SAFE":
        report["sandbox_verdict"] = "INCONCLUSIVE"
        report["sandbox_reason"] = (
            f"Server returned error {report['sandbox_status_code']} (Access Denied)"
        )
    return report
