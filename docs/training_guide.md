# Model Training Guide — Stacking Meta-Learner

> Efficient approach to add OCR Spatial + TVC features without losing existing model accuracy.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                Training Data CSV                     │
│  (must contain new columns from updated pipeline)    │
└───────────────┬─────────────────────────────────────┘
                │
    ┌───────────▼───────────┐    ┌─────────────────────┐
    │  Base XGBoost (FROZEN) │    │   New Features       │
    │  xgb_label_model.joblib│    │   • tvc_brand_spoofed│
    │                        │    │   • tvc_fuzzy_score   │
    │  Output:               │    │   • spatial word counts│
    │  P(class_1)...P(class_n)   │   • tfidf(header text)│
    └───────────┬────────────┘    │   • tfidf(footer text)│
                │                 └──────────┬──────────┘
                └──────────┬─────────────────┘
                           │
                ┌──────────▼──────────┐
                │   Meta-Learner       │
                │   (lightweight XGB)  │
                │                      │
                │   Output: Final      │
                │   classification     │
                └──────────────────────┘
```

**Why stacking?**

- Base model stays frozen → zero risk of regression
- Meta-learner is small (fast to train, ~2 min)
- Easy A/B comparison: base model vs base+meta
- New features get learned without disturbing existing patterns

---

## Step-by-Step Training Workflow

### Step 1 — Generate Training Data with New Features

The existing training CSV (`data/training/training_dataset_features.csv`) needs the new columns. Run the **updated pipeline** over a sample of URLs to populate:

```powershell
cd c:\Users\SATWIK\Documents\Phishing
venv\Scripts\python.exe main_controller.py
```

This adds these columns to the output CSV:

| Column | Type | Source |
|---|---|---|
| `ocr_header_text` | string | Top 20% of page (brand zone) |
| `ocr_body_text` | string | Middle 60% |
| `ocr_footer_text` | string | Bottom 20% (legal zone) |
| `ocr_header_word_count` | int | Word count in header zone |
| `ocr_footer_word_count` | int | Word count in footer zone |
| `ocr_total_word_count` | int | Total OCR words |
| `tvc_brand_detected` | bool | Any known brand in OCR text? |
| `tvc_detected_brand` | string | Which brand (e.g., "sbi") |
| `tvc_domain_match` | bool | Domain matches the brand? |
| `tvc_fuzzy_score` | float | Fuzzy similarity score (0–1) |
| `tvc_brand_spoofed` | bool | **Key signal**: brand present but wrong domain |

> [!TIP]
> If you can't re-run the pipeline right now, the training script will zero-fill missing columns and still train. The meta-learner will just rely on base model probs until real data is available.

### Step 2 — Copy Output to Training Folder

After the pipeline finishes, copy or merge the results into the training dataset:

```powershell
# Option A: Replace the training CSV entirely
copy output\checkpoint_records.csv data\training\training_dataset_features.csv

# Option B: Append new rows to existing training data
venv\Scripts\python.exe -c "
import pandas as pd
existing = pd.read_csv('data/training/training_dataset_features.csv')
new_data = pd.read_csv('output/checkpoint_records.csv')
combined = pd.concat([existing, new_data], ignore_index=True).drop_duplicates(subset='url')
combined.to_csv('data/training/training_dataset_features.csv', index=False)
print(f'Combined: {len(combined)} rows')
"
```

### Step 3 — Train the Meta-Learner

```powershell
cd c:\Users\SATWIK\Documents\Phishing
venv\Scripts\python.exe -m scripts.train_with_ocr_features
```

The script will:

1. **Load frozen base models** — no modification to existing `.joblib` files
2. **Generate base predictions** — get probability outputs from the frozen XGBoost
3. **Build meta-features** — combine base probs + TVC numerics + OCR TF-IDF vectors
4. **Train meta-learner** — RandomizedSearchCV with 20 iterations, F1-macro scoring
5. **Save to `models/meta/`** — separate directory, base models untouched

**Expected output:**

```
🧱 STAGE 1: Loading frozen base models
  ✅ Base label model loaded (N classes)
  
📂 STAGE 2: Loading training data
  Loaded X rows × Y columns

🔮 STAGE 3: Generating base model predictions (frozen)
  ✅ Base predictions generated

🏗️  STAGE 4: Building meta-feature matrix
  📊 Base model probs: N features
  📊 New numeric features: 7
  📊 OCR Header TF-IDF: 200 features
  📊 OCR Footer TF-IDF: 100 features

🚀 STAGE 6: Training meta-learner
  ✅ CV F1 Macro: 0.XXXX

📊 STAGE 7: Feature importance (top 15)
  1. tvc_brand_spoofed    importance=0.XXXX
  ...

💾 STAGE 8: Saving meta-learner artifacts
  ✅ Saved to: models/meta/
```

### Step 4 — Verify Results

Check that the meta-learner artifacts exist:

```powershell
dir models\meta\
```

Expected files:

| File | Purpose |
|---|---|
| `meta_label_model.joblib` | The meta-learner XGBoost model |
| `meta_imputer.joblib` | Imputer for meta-feature NaN handling |
| `meta_scaler.joblib` | StandardScaler for meta-features |
| `meta_feature_names.joblib` | Ordered list of feature names |
| `tfidf_ocr_header_text.joblib` | TF-IDF vectorizer for header OCR text |
| `tfidf_ocr_footer_text.joblib` | TF-IDF vectorizer for footer OCR text |

---

## Using the Meta-Learner in Production

To use the meta-learner during pipeline inference, the prediction flow becomes:

```python
# 1. Run base model (existing code — unchanged)
base_probs = base_label_model.predict_proba(X_base)

# 2. Build meta-features
meta_feats = np.hstack([
    base_probs,
    tvc_numeric_features,         # tvc_brand_spoofed, tvc_fuzzy_score, etc.
    tfidf_header.transform([header_text]).toarray(),
    tfidf_footer.transform([footer_text]).toarray(),
])

# 3. Impute + scale
meta_feats = meta_scaler.transform(meta_imputer.transform(meta_feats))

# 4. Predict
final_label = meta_model.predict(meta_feats)
```

> [!IMPORTANT]
> The `reclassify_label()` heuristic in `pipeline.py` already uses `tvc_brand_spoofed` as a rule-based override. The meta-learner is an **additional** ML-based signal that can be used alongside or instead of the heuristic.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| "Missing columns" warning during training | Re-run the pipeline over training URLs first (Step 1) |
| Low F1 score | Need more training data with actual TVC features (not zero-filled) |
| `ModuleNotFoundError: rapidfuzz` | `pip install rapidfuzz` (should already be in requirements.txt) |
| CUDA OOM during base model prediction | Reduce training CSV size or switch to CPU: `CUDA_VISIBLE_DEVICES="" python -m scripts.train_with_ocr_features` |
