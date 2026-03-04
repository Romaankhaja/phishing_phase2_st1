# OCR Spatial & Textual-Visual Consistency — Implementation Plan

> **Status: Approved ✅** — [debug_ocr.py](file:///c:/Users/SATWIK/Documents/Phishing/debug_ocr.py) excluded (deleted). A new dedicated training script will be created.

Integrating **spatial OCR zone decomposition** and **Textual-Visual Consistency (TVC)** features into the existing 3-stage phishing detection pipeline. The goal is to shift the model away from purely lexical bias by teaching it **where** brand text appears on the page and **whether** that brand name matches the domain being visited.

## User Review Required

> [!IMPORTANT]
> **Model retraining is required.** Steps 1–4 add new feature columns to the output CSV. These new columns must be included in the training data before retraining `xgb_label_model` and `xgb_source_model`. The existing models will **not** use the new features until they are retrained.
>
> Plan: After implementation, run the pipeline over the existing training dataset ([data/training/training_dataset_features.csv](file:///c:/Users/SATWIK/Documents/Phishing/data/training/training_dataset_features.csv)) to regenerate it with new columns, then run [scripts/model_training.py](file:///c:/Users/SATWIK/Documents/Phishing/scripts/model_training.py).

> [!IMPORTANT]
> **Backward-compatible output.** The original [ocr_text](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#685-692) column will be retained in the output CSV. New columns (`ocr_header_text`, `ocr_body_text`, `ocr_footer_text`, `tvc_brand_spoofed`, etc.) are **additions only** — no existing columns are renamed or removed.

---

## Proposed Changes

### Component 1 — Core OCR Engine ([visual_features.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py))

#### [MODIFY] [visual_features.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py)

**Change 1a — Switch EasyOCR to `detail=1`**

[run_ocr_inference()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#638-683) currently calls `reader.readtext(img_np, detail=0)` which discards bounding box coordinates. Switch to `detail=1` to return [(bbox, text, confidence)](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#756-762) tuples. The raw results list will be stored as an attribute returned from this function so callers can do spatial parsing without a second GPU call.

- Return type changes from [str](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/features.py#204-221) → `tuple[str, list]` (flat text + raw results list)
- Confidence threshold: only keep results with `confidence >= 0.40`
- Zero GPU overhead — bounding boxes are emitted by EasyOCR's detection head at no extra cost

**Change 1b — Add [preprocess_image_for_ocr()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#617-636) enhancements**

Add adaptive thresholding and a mild sharpening kernel **after** the existing grayscale+resize:

```
grayscale → resize → [NEW] adaptive threshold → [NEW] sharpen
```

These are CPU-only, add ~10ms, and improve accuracy on gradient/dark-background pages.

**Change 1c — Add `extract_spatial_ocr_features(img_np, ocr_raw_results, img_height)` (NEW function)**

Post-processes the `ocr_raw_results` list from [run_ocr_inference()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#638-683) to split text into three vertical zones:

- **Header** — top 20% of image height (logo / brand zone)
- **Body** — middle 60% (login form, instructions)
- **Footer** — bottom 20% (copyright / legal / real org name)

Returns a dict: `{ocr_header_text, ocr_body_text, ocr_footer_text, ocr_header_word_count, ocr_footer_word_count, ocr_total_word_count}`.

---

### Component 2 — TVC Feature Engineering ([utils.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py))

#### [MODIFY] [utils.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py)

**Change 2a — Add `extract_tvc_features(url, ocr_header_text, ocr_footer_text)` (NEW function)**

Checks whether the brand name appearing in the header/footer OCR text matches the actual domain:

1. Iterates `BRAND_DOMAIN_MAP` (a dict mapping brand names → list of their known legitimate domains)
2. For each brand found in OCR text, fuzzy-matches the actual domain against the brand's legitimate domains using `rapidfuzz.fuzz.ratio` (already in [requirements.txt](file:///c:/Users/SATWIK/Documents/Phishing/requirements.txt))
3. Returns: `{tvc_brand_detected, tvc_detected_brand, tvc_domain_match, tvc_fuzzy_score, tvc_brand_spoofed}`

`tvc_brand_spoofed = True` when a brand is found visually but the domain is not a legitimate brand domain. This is the primary new ML signal.

**Change 2b — Update existing safe wrappers**

- [_safe_run_ocr()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py#498-508) updated to return [(text, raw_results)](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#756-762) in line with the new [run_ocr_inference()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#638-683) signature
- [_safe_preprocess_image()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py#483-496) unchanged (still returns numpy array)

---

### Component 3 — Pipeline Integration ([pipeline.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py))

#### [MODIFY] [pipeline.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py)

**Change 3 — Update [stage2_worker()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#471-536) to call new functions**

In [stage2_worker()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#471-536) (around line 477), after [_safe_run_ocr()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py#498-508) returns, call:

```
spatial_feats = extract_spatial_ocr_features(img_np, raw_results, img_height)
tvc_feats     = extract_tvc_features(target_url, spatial_feats["ocr_header_text"], spatial_feats["ocr_footer_text"])
```

Merge into the `merged` dict alongside existing keys. [ocr_text](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#685-692) is kept pointing to the full flat text (backward compatible with [reclassify_label()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#635-678) and the existing TF-IDF model).

Also update [reclassify_label()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#635-678) to incorporate `tvc_brand_spoofed` as a direct override:

- If `tvc_brand_spoofed == True` AND registrar is suspicious → return `"Phishing"` immediately
- If `tvc_brand_spoofed == True` AND registrar is unknown → return `"Suspected"`

---

### Component 4 — New Training Script [NEW]

#### [NEW] [train_with_ocr_features.py](file:///c:/Users/SATWIK/Documents/Phishing/scripts/train_with_ocr_features.py)

Create a **new, self-contained training script** based on the existing [model_training.py](file:///c:/Users/SATWIK/Documents/Phishing/scripts/model_training.py) with these targeted additions:

1. **Expanded `exclude_cols`** — adds new text columns: `"ocr_header_text"`, `"ocr_body_text"`, `"ocr_footer_text"`, `"tvc_detected_brand"`

2. **Two new TF-IDF text branches** (in addition to the existing `tfidf_asn`):
   - `tfidf_ocr_header` — fitted on `ocr_header_text` (brand zone), `max_features=200`
   - `tfidf_ocr_footer` — fitted on `ocr_footer_text` (legal zone), `max_features=100`
   - Both concatenated via `scipy.sparse.hstack` and saved as `models/tfidf_ocr_header.joblib` and `models/tfidf_ocr_footer.joblib`

3. **TVC numeric features auto-included** — `tvc_brand_spoofed` (bool), `tvc_domain_match` (bool), `tvc_fuzzy_score` (float), `ocr_header_word_count`, `ocr_footer_word_count`, `ocr_total_word_count` picked up by existing `candidate_features` logic.

4. **Saves updated [feature_columns.joblib](file:///c:/Users/SATWIK/Documents/Phishing/models/feature_columns.joblib)** — ensures pipeline ML inference uses the correct column list.

The existing [model_training.py](file:///c:/Users/SATWIK/Documents/Phishing/scripts/model_training.py) is **left untouched** as a fallback.

---

## Verification Plan

### Automated Tests

A new minimal smoke test script will be created.

**New Test — `scripts/test_ocr_spatial.py`**

This script will:

1. Take a publicly reachable URL (e.g. `https://www.sbi.co.in`)
2. Capture a screenshot using the existing [capture_screenshot_async()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#327-440)
3. Call [preprocess_image_for_ocr()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#617-636) on the saved PNG
4. Call [run_ocr_inference()](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/visual_features.py#638-683) (updated, returning [(text, raw_results)](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py#756-762))
5. Call `extract_spatial_ocr_features()` and print the 3 zone texts
6. Call `extract_tvc_features()` and assert that `tvc_brand_spoofed == False` (SBI on sbi.co.in is NOT spoofed)
7. Repeat with a **mock screenshot** from an existing PNG in `phishing_pipeline/screens/` and assert fields are not empty

**Run command:**

```powershell
cd c:\Users\SATWIK\Documents\Phishing
python -m scripts.test_ocr_spatial
```

**Unit-level check — `run_ocr_inference()` return type:**

```powershell
cd c:\Users\SATWIK\Documents\Phishing
python -c "
from phishing_pipeline.visual_features import preprocess_image_for_ocr, run_ocr_inference
import numpy as np
dummy = np.ones((200, 400), dtype=np.uint8) * 255
text, raw = run_ocr_inference(dummy)
print('text:', repr(text))
print('raw results type:', type(raw), 'len:', len(raw))
assert isinstance(text, str), 'text must be str'
assert isinstance(raw, list), 'raw must be list'
print('PASS')
"
```

**TVC unit check — `extract_tvc_features()`:**

```powershell
cd c:\Users\SATWIK\Documents\Phishing
python -c "
from phishing_pipeline.utils import extract_tvc_features
# Should detect SBI brand but flag as spoofed (wrong domain)
r = extract_tvc_features('http://sbi-login.xyz', 'State Bank of India SBI Login', '')
assert r['tvc_brand_spoofed'] == True, f'Expected spoofed, got {r}'
# Legitimate case — should NOT be spoofed
r2 = extract_tvc_features('https://onlinesbi.com', 'State Bank of India SBI Login', '')
assert r2['tvc_domain_match'] == True, f'Expected match, got {r2}'
print('TVC assertions PASS:', r, r2)
"
```

### Manual Verification

After implementing all changes, run the pipeline on a small batch (5–10 domains) and inspect the output CSV:

1. Open a PowerShell terminal in `c:\Users\SATWIK\Documents\Phishing`
2. Run: `python main_controller.py` (or however the pipeline is invoked on your setup)
3. Open the output CSV at `output/checkpoint_records.csv` or `output/output_file.csv`
4. Confirm these columns now exist: `ocr_header_text`, `ocr_body_text`, `ocr_footer_text`, `tvc_brand_detected`, `tvc_detected_brand`, `tvc_domain_match`, `tvc_fuzzy_score`, `tvc_brand_spoofed`
5. For any domain that was classified as "Phishing", check whether `tvc_brand_spoofed` is `True` — this validates the end-to-end signal is flowing correctly

### Model Retraining Verification

After Steps 1–4 are validated, retrain using the new script:

```powershell
cd c:\Users\SATWIK\Documents\Phishing
python -m scripts.train_with_ocr_features
```

Confirm console output includes the new feature column names in the "Selected N numeric/boolean features" line. Confirm `feature_columns.joblib` now contains `tvc_brand_spoofed`, `tvc_fuzzy_score`, `tfidf_ocr_header` vectors, etc.
