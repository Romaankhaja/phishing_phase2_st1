# Phishing Pipeline — Debug & Clarification Guide

> **Target audience:** Developers running the pipeline on Kaggle (T4 GPU) or local (RTX 2050).
> Covers the end-to-end flow, domain count filtering logic, known warnings, and error triage.

---

## 1. End-to-End Flow Overview

```
main_controller.py
       │
       ├─ Step 1: Shortlisting (shortlisting.py)
       │    Input : holdout_sets/ Excel files  (e.g. 70,000 newly-registered domains)
       │    Output: output/holdout.csv         (e.g. 1,082 typosquat candidates)
       │
       └─ Step 2: run_pipeline() (pipeline.py)
            │
            ├─ Whitelist filter                ← 1,082 → 268 (only CSE-matched domains)
            │   df_filtered = holdout WHERE "Legitimate Domains" IN ps02_whitelist
            │   Saved to: phishing_pipeline/holdout_temp.csv
            │
            ├─ Phase 1: process_urls()         (60% of overall progress)
            │    ├─ Stage 1: Screenshots + Network features  (15 workers concurrently)
            │    │    └─ Pushes results → asyncio.Queue (max 10 slots)
            │    └─ Stage 2: OCR + Branding + Laplacian     (5 workers on Kaggle T4)
            │         └─ Pops from Queue → GPU inference → appends to all_results
            │   Output: phishing_pipeline/features_enriched.csv (268 rows)
            │
            ├─ Phase 2: WHOIS / RDAP Lookup   (35% of overall progress)
            │    ├─ Pass 1: DNS pre-check (3s timeout) ─ marks dead domains
            │    ├─ Pass 2: RDAP lookup  (HTTP GET, parallel)
            │    ├─ Pass 2.5: DNS Records (MX, NS, A, CNAME parallel batch)
            │    └─ Pass 3: WHOIS fallback (5s timeout, rate-limited 20 req/min)
            │   Output: ⚡ Reg Data progress bar (e.g. 268 domains)
            │
            └─ Phase 3: Export + Package      (5% of overall progress)
                 Output: PS-02_ISS_NLP_Submission.zip
```

---

## 2. Why 268 Domains (Not 1,082)?

This is **expected behaviour** — not a bug.

| Stage | Domain Count | Reason |
|---|---|---|
| Shortlisting input | 70,000 | Raw newly-registered domains from Excel |
| `output/holdout.csv` | ~1,082 | Typosquat / similar-domain candidates |
| `holdout_temp.csv` | **268** | After whitelist filter (only CSE-mapped domains) |
| `features_enriched.csv` | 268 | Phase 1 output |
| `⚡ Reg Data` bar | 268 | Phase 2 input = Phase 1 output |

**The filter line (pipeline.py line ~721):**

```python
df_filtered = df_holdout[
    df_holdout["Legitimate Domains"].isin(ps02_df["Legitimate Domains"])
]
```

Only domains that can be linked back to one of your 26 whitelisted CSE domains pass through.
The remaining ~814 domains are discarded — they are typosquats of domains NOT in your current whitelist set.

---

## 3. Known Warnings & What They Mean

### 3.1 RDAP 429 (Rate Limited)

```
⚠️ RDAP 429 for bankofwi.org
```

**Cause:** The RDAP registry (iana.org) rate-limits bulk lookups.
**Impact:** Domain falls through to WHOIS fallback → slower but still resolved.
**Action needed:** None. The pipeline handles this automatically.

> If you see **many** 429s, the RDAP semaphore (`_get_rdap_semaphore()`) is set too high.
> Reduce `MAX_CONCURRENT_RDAP` in `utils.py`.

---

### 3.2 OCR Reader Reset

```
🔄 OCR reader reset (call #20) to clear VRAM fragmentation
🚀 GPU detected: Tesla T4
✅ EasyOCR initialized successfully (GPU: True)
```

**Cause:** Every `_OCR_RESET_INTERVAL = 20` OCR calls, the EasyOCR model is destroyed and reloaded to clear CUDA VRAM fragmentation.
**Impact:** ~3–5 second pause for that one worker while the model reloads.
**Action needed:** None. This is a built-in safety valve.

> **To change frequency:** Edit `_OCR_RESET_INTERVAL` in `visual_features.py`.
>
> - Lower number = more frequent resets (more pauses, but safer for small VRAM)
> - Higher number = fewer resets (faster, but risk of fragmentation OOM on small GPUs)

---

### 3.3 DNS Name Not Known

```
ERROR - Error trying to connect to socket: closing socket - [Errno -2] Name or service not known
```

**Cause:** Domain is dead — DNS resolution failed (NXDOMAIN or unreachable).
**Impact:** Domain is marked `DEAD` internally, skips RDAP/WHOIS. Still appears in output with `NA` for all WHOIS fields.
**Action needed:** None. Expected for newly-registered (many are parked/inactive).

---

### 3.4 XGBoost Serialization Warning

```
UserWarning: If you are loading a serialized model (like pickle in Python, RDS in R)...
  please export the model by calling `Booster.save_model` from that version first
```

**Cause:** The saved `.pkl` XGBoost model was saved with an older version of XGBoost than what Kaggle has installed.
**Impact:** Model still loads and runs correctly — this is a warning, not an error.
**Fix (optional):** Re-save models using your current XGBoost version:

```python
import pickle, xgboost as xgb
with open("models/model_label.pkl", "rb") as f:
    model = pickle.load(f)
model.save_model("models/model_label.json")  # Use JSON format going forward
```

---

### 3.5 Pandas FutureWarning

```
FutureWarning: Setting an item of incompatible dtype is deprecated...
  df_final_output.fillna("NA", inplace=True)
```

**Cause:** Pandas 2.x deprecated in-place assignment to columns with dtype mismatch.
**Impact:** None in current pandas version, but will raise an Error in a future release.
**Fix:**

```python
# pipeline.py line ~1210
# Change:
df_final_output.fillna("NA", inplace=True)
# To:
df_final_output = df_final_output.fillna("NA")
```

---

### 3.6 PIL Palette Transparency Warning

```
UserWarning: Palette images with Transparency expressed in bytes should be converted to RGBA
```

**Cause:** Some website favicons use a palette-mode PNG with byte-based transparency.
**Impact:** None — PIL still processes the image correctly.
**Action needed:** None.

---

## 4. How to Debug if Phase 1 Outputs Fewer Than 268 Rows

If `features_enriched.csv` has fewer rows than `holdout_temp.csv`, check these in order:

### 4.1 Check the Phase 1 completion log

```
✅ Phase 1 complete: X / 268 domains processed
```

If `X < 268`, some domains failed silently. Enable DEBUG logging to see which:

```python
# In main_controller.py, before run_pipeline():
logging.getLogger().setLevel(logging.DEBUG)
```

### 4.2 Check for Stage 2 OCR errors in the log

```
ERROR - [Stage2] Unexpected error for <domain>: <msg>
```

These mean a domain completed Stage 1 (screenshot) but failed Stage 2 (OCR/branding). The domain is **dropped** from `all_results` and not written to the CSV.

### 4.3 Check for CUDA OOM (should not happen post-fix)

```
⚠️ CUDA OOM during OCR inference (call #N). Clearing cache and retrying...
```

If this appears repeatedly and the retry also fails, the domain is lost. On Kaggle T4 (16GB) this should not happen. If it does, set `_OCR_RESET_INTERVAL = 10` in `visual_features.py`.

---

## 5. Concurrency Settings Reference (Auto-calculated in utils.py)

| Setting | Local RTX 2050 (4GB) | Kaggle T4 (16GB) | Kaggle T4 x2 (32GB) |
|---|---|---|---|
| `MAX_CONCURRENT_OCR` | 3 | 5 | 10 (if multi-GPU wired) |
| `MAX_CONCURRENT_SCREENSHOTS` | 15 | 20 | 20 |
| Queue max size | 6 (OCR×2) | 10 (OCR×2) | 20 (OCR×2) |
| OCR reset interval | every 20 calls | every 20 calls | every 20 calls |
| VRAM gate threshold | 1.5 GB free | 1.5 GB free | 1.5 GB free |

---

## 6. Quick Triage Checklist

```
Pipeline produced fewer results than expected?
  ├─ Check: output/holdout.csv row count           → shortlisting output
  ├─ Check: phishing_pipeline/holdout_temp.csv     → after whitelist filter
  ├─ Check: phishing_pipeline/features_enriched.csv → after Phase 1
  └─ Check: phishing_pipeline/output_file.csv      → final

WHOIS data all "NA"?
  └─ Most domains are newly registered (.ru, .xyz) and RDAP returns 429
     → Check rdap_results / whois_results counts in Phase 2 log summary

Pipeline crashed (no output)?
  ├─ CUDA OOM? → Lower _OCR_RESET_INTERVAL to 10
  ├─ Playwright crash? → Check "Browser context closed" warnings
  └─ Import error? → Check venv has all dependencies (pip install -r requirements.txt)
```

---

## 7. Output Files Reference

| File | Contents | Used by |
|---|---|---|
| `output/holdout.csv` | All shortlisted typosquat candidates | `run_pipeline()` |
| `phishing_pipeline/holdout_temp.csv` | Whitelist-filtered candidates (268) | `process_urls()` |
| `phishing_pipeline/features.csv` | Raw Phase 1 features | Phase 2 |
| `phishing_pipeline/features_enriched.csv` | Phase 1 + GeoIP enrichment | Phase 2 ML |
| `phishing_pipeline/output_file.csv` | Final classified output (268 records) | `package_results()` |
| `PS-02_ISS_NLP_Submission.zip` | Final submission zip | Submission |

---

*Last updated: 2026-02-25 | Pipeline version: two-stage producer-consumer (post-OOM fix)*
