# WHOIS Strategy & Pipeline FAQ

**Date:** February 5, 2026

## 1. Why Timeouts & Blocking Happen
WHOIS servers (like VeriSign for .com) are extremely strict.
*   **Rate Limits:** They often allow only 10-20 requests per minute from a single IP.
*   **IP Blocking:** If you exceed this, they "shadow ban" your IP, causing all subsequent requests to *timeout* or be "refused" (WinError 10061).
*   **"No Match":** This can mean the domain is invalid, OR that the server has blocked you and is returning empty responses.

## 2. Solutions & Prevention

### A. The "Patient" Approach (Current)
*   **Strategy:** Wait longer between requests.
*   **Pros:** Free, no extra config.
*   **Cons:** Very slow (could take hours for 1000 domains).
*   **Fix:** Increase `whois_semaphore` limit? **NO.** Increasing concurrency *increases* blocking. The only fix here is *slowing down*.

### B. The "Professional" Approach (Proxies)
*   **Strategy:** Route traffic through rotating residential proxies (e.g., BrightData, Smartproxy).
*   **Pros:** Fast, no blocking.
*   **Cons:** Costs money, requires setup.

### C. The "Fail-Safe" Approach (Recommended)
*   **Strategy:** Accept that some lookups will fail. 
*   **Logic:** If WHOIS fails (timeout/block), mark the domain as **"Suspected"** (which we just implemented).
*   **Why:** A domain that hides its WHOIS or resides on a blocked network is inherently suspicious.

## 3. Faster Alternatives

1.  **rdap (Registration Data Access Protocol):**
    *   Newer, JSON-based replacement for WHOIS.
    *   Often has better rate limits (but not infinite).
    *   *Requires code rewrite.*

2.  **Bulk WHOIS APIs:**
    *   Services like `WhoisXMLAPI` or `Ipinfo.io`.
    *   You send 1000 domains, they return JSON instantly.
    *   *Cost: ~$30/month.*

## 4. Submission ZIP Verification
Yes, the `.zip` file is generated **automatically** at the very end of the process.

**Execution Flow:**
1.  **Features:** [process_urls](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#143-266) (Completed Phase 1)
2.  **Enrichment:** [run_pipeline](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#378-648) loop (Phase 2 - **Where you are now**)
    *   WHOIS → DNS → Classification
    *   *This must finish for all 967 domains.*
3.  **Filtration:** Filters by date (Oct 1-15, 2025).
4.  **Packaging:** **[package_results()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#652-756)** is called (Lines 721+).
    *   Creates `PS-02_ISS_NLP_Submission.zip`
    *   Contains Excel + Evidence folder.

> [!IMPORTANT]
> Since you interrupted the script (`KeyboardInterrupt`), the ZIP **was not created**. You must let the loop finish, OR we can write a small script to package what you have so far.

## 5. Summary Recommendation
Since you are facing timeouts:
1.  **Do not restart from scratch.** The "Suspected" fallback logic we added handles these shutdowns safely.
2.  **Let it run.** Even with timeouts, it will process ~1-2 domains per second.
3.  **If stuck:** We can add a "resume" feature to skip already-processed domains.
