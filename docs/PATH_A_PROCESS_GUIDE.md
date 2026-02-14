# 🚀 Path A: Full Model Training Process Guide

> **Goal:** Take your raw domain list (like `PS02_Stage7_Training_set`) → run it through the phishing pipeline → get a feature-rich dataset → train the XGBoost models.

---

## The Big Picture (30-Second Summary)

```
YOUR RAW DATA                   PHISHING PIPELINE                    MODEL TRAINING
┌──────────────┐     ┌────────────────────────────────────┐     ┌──────────────────┐
│ Domain names │ ──► │ Visit each domain & extract 50+    │ ──► │ Train XGBoost on │
│ + Target CSE │     │ features (URL, SSL, OCR, DNS...)   │     │ the enriched CSV  │
│ + Label      │     │                                    │     │                   │
└──────────────┘     └────────────────────────────────────┘     └──────────────────┘
     Step 1                    Steps 2–3                            Steps 4–5
  (Prepare Data)          (Run Pipeline)                       (Train & Save)
```

---

## Step-by-Step Process

### Step 1: Prepare Your Input Data

Your raw Excel (`PS02_Stage7_Training_set`) has columns like:

| S. No | Phishing/Suspected Domain Name | Target CSE | Phishing/Suspected |
|-------|-------------------------------|------------|-------------------|
| 1 | airasiabetlivezona.christmas | Air India | Suspected |

**What the pipeline expects** is two input files:

1. **Whitelist Excel** (`PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx`)
   - Contains legitimate domain names and their corresponding CSE
   - Columns: `Legitimate Domains`, `Cooresponding CSE`
   - **Purpose:** The pipeline compares suspected domains *against* these legitimate domains

2. **Shortlisting Folder** (`PS-02_hold-out_Set_2/`)
   - Contains `.xlsx` files with suspected/phishing domain names
   - Each file has columns like `Phishing/Suspected Domain Name`, `Target CSE`

> [!IMPORTANT]
> Your raw training Excel needs to be **split into these two formats** before running the pipeline. The whitelist has the legitimate domains, and the shortlisting folder has the suspected phishing domains.

---

### Step 2: Run the Phishing Pipeline

The pipeline is controlled via `main_controller.py`. Here's the command:

```bash
# From the Phishing project root directory
python main_controller.py --whitelist "uploads/PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx" --shortlisting "PS-02_hold-out_Set_2"
```

**What happens under the hood (3 phases):**

#### Phase 1 — Feature Extraction (60% of work)

The pipeline visits **every domain** and extracts features in chunks of 200:

| Feature Category | What It Extracts | Module |
|-----------------|------------------|--------|
| **URL Structure** | URL length, dot count, hyphen count, special chars, entropy | `features.py` → `extract_url_features()` |
| **Subdomain** | Subdomain count, subdomain length, subdomain entropy | `features.py` → `extract_subdomain_features()` |
| **Path** | Path length, path depth, query param count | `features.py` → `extract_path_features()` |
| **Entropy** | Shannon entropy of full URL, domain, subdomain | `features.py` → `entropy_features()` |
| **IP Address** | Resolved IP of the domain | `features.py` → `get_ip_address()` |
| **SSL Certificate** | Has SSL, issuer, expiry days, is valid | `features.py` → `ssl_features()` |
| **Screenshot** | Takes a browser screenshot of the page | `visual_features.py` → `capture_screenshot_async()` |
| **OCR Text** | Reads visible text from screenshot using EasyOCR (GPU) | `visual_features.py` → `_get_ocr_reader()` |
| **Brand Colors** | Extracts dominant colors using K-Means clustering | `visual_features.py` → brand color extraction |
| **Favicon** | Favicon URL, hash, size, colors | `visual_features.py` |
| **GeoIP** | ASN org, country, region, city (from MaxMind DBs) | `geoip_utils.py` / `pipeline.py` → `enrich_with_geoip()` |

**Output:** `phishing_pipeline/blacklist_features.csv` → enriched to `phishing_pipeline/features_enriched.csv`

#### Phase 2 — WHOIS/RDAP & Classification (35% of work)

For each domain, the pipeline:

1. **DNS pre-filter** — Checks if the domain is alive
2. **RDAP lookup** (fast, async) — Gets registration date, registrar, registrant info
3. **WHOIS fallback** — For domains where RDAP fails
4. **Heuristic classification** — Uses `reclassify_label()` which checks registrar reputation, hosting ISP, brand keyword matches in OCR text, etc.
5. **Source detection** — Predicts which sector/category the domain targets (Banking, Government, Telecom, etc.)

**Output:** `phishing_pipeline/output_file.csv` — the complete classified dataset

#### Phase 3 — Evidence & Packaging (5% of work)

- Converts screenshots to PDF evidence files
- Packages everything into a submission zip

---

### Step 3: Collect the Enriched Dataset

After the pipeline finishes, your key output files are:

| File | Location | Purpose |
|------|----------|---------|
| `features_enriched.csv` | `phishing_pipeline/` | **This is what you need for training** — contains all 50+ extracted features |
| `output_file.csv` | `phishing_pipeline/` | Final classified output with WHOIS data, labels, evidence paths |

The `features_enriched.csv` has columns like:

```
url, url_length, dot_count, hyphen_count, subdomain_count, path_depth,
entropy_full_url, entropy_domain, has_ssl, ssl_days_until_expiry,
ssl_issuer, ip_address, ocr_text, brand_colors, favicon_hash,
asn_org, country, region, city, logo_hash, ...
```

> [!NOTE]
> You also need to add your **labels** (`label` and `source_of_detection` columns) to this CSV before training. The `output_file.csv` contains the heuristic labels from `reclassify_label()` and the source predictions — you can use these, or manually label the data if you want ground-truth labels.

---

### Step 4: Format the Dataset for Training

`model_training.py` expects the file `final_training_dataset_with_source.xlsx` with these required columns:

| Required Column | Source |
|----------------|--------|
| All numeric features (url_length, entropy, etc.) | From `features_enriched.csv` |
| `ocr_text` | From `features_enriched.csv` |
| `asn_org` | From `features_enriched.csv` |
| `brand_colors` | From `features_enriched.csv` |
| `ssl_issuer` | From `features_enriched.csv` |
| `label` | "Phishing", "Suspected", or "Legitimate" — from `output_file.csv` or manual annotation |
| `source_of_detection` | "Banking/Financial", "Government", "Telecom", etc. — from `output_file.csv` or manual annotation |

**What to do:**

1. Take `features_enriched.csv` as your base
2. Merge `label` and `source_of_detection` from `output_file.csv` (or add manually)
3. Save as `final_training_dataset_with_source.xlsx`

---

### Step 5: Run Model Training

```bash
# From the Phishing project root directory
python model_training.py
```

This will:

1. Load the enriched Excel dataset
2. Auto-select numeric/boolean features
3. Impute missing values (median)
4. Scale features (StandardScaler)
5. Vectorize text features (TF-IDF on `ocr_text`, `asn_org`, `brand_colors`)
6. Encode target labels
7. Tune hyperparameters (RandomizedSearchCV, 30 iterations)
8. Train 2 XGBoost models (label + source)
9. Save all `.joblib` artifacts

**Output:** 10 `.joblib` files (models, encoders, scaler, imputer, vectorizers, feature list)

---

## Quick Reference: File Flow

```
                     INPUT FILES
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   Whitelist.xlsx   Shortlisting/    GeoLite2 DBs
        │           *.xlsx files      (.mmdb)
        │                │                │
        └───────┬────────┘                │
                ▼                         │
         shortlisting.py                  │
         (typosquatting match)            │
                │                         │
                ▼                         │
           holdout.csv                    │
                │                         │
                ▼                         │
           pipeline.py ◄─────────────────┘
           (3-phase pipeline)
                │
        ┌───────┼───────┐
        ▼       ▼       ▼
  features.py  visual_   geoip_
               features  utils
                .py      .py
                │
                ▼
        features_enriched.csv  ◄── 50+ columns
                │
                ▼
    + Add labels manually or from output_file.csv
                │
                ▼
   final_training_dataset_with_source.xlsx
                │
                ▼
        model_training.py
                │
                ▼
        10 .joblib artifacts
   (models, scaler, imputer, encoders, TF-IDF)
```

---

## Prerequisites Checklist

Before running the pipeline, make sure you have:

- [ ] **Python venv** activated with all dependencies installed (`pip install -r requirements.txt`)
- [ ] **GeoLite2 databases** in project root (`GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb`)
- [ ] **Whitelist Excel** in `uploads/` folder
- [ ] **Shortlisting Excel files** in `PS-02_hold-out_Set_2/` folder
- [ ] **GPU available** (for EasyOCR) — or it will fall back to CPU (slower)
- [ ] **Playwright browser** installed (`playwright install chromium`)

---

## Common Questions

**Q: How long does the pipeline take?**
A: ~2-5 seconds per domain. For 1000 domains, expect ~30-80 minutes depending on network speed and GPU.

**Q: Can I run it without GPU?**
A: Yes, but OCR will be slower. EasyOCR falls back to CPU automatically.

**Q: What if some domains are dead?**
A: The pipeline has DNS pre-filtering — dead domains are skipped quickly (2-3 seconds) instead of timing out.

**Q: Do I need to run the pipeline every time I retrain?**
A: No. Once you have `features_enriched.csv` with labels, you can retrain as many times as you want by just running `model_training.py`. You only need the pipeline again when you have **new domains** to process.
