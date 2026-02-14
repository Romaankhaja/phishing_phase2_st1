# 📊 Model Evaluation Metrics Guide

> **Goal:** Evaluate the present XGBoost models (`xgb_label_model.joblib` & `xgb_source_model.joblib`) before retraining, to understand how well they perform and establish a baseline.

---

## 1. Current State: What We Already Know

Your `model_training.py` currently reports **only one metric** during training:

```
✅ Label CV F1 Macro: 0.XXXX
✅ Source of Detection CV F1 Macro: 0.XXXX
```

This is the **cross-validated F1 macro score** from `RandomizedSearchCV`. While useful, it's just one number — we need a complete evaluation picture.

> [!IMPORTANT]
> **Problem:** The current training code trains on the **entire dataset** (no train/test split). The CV score is from internal cross-validation folds during hyperparameter tuning — it's not a proper held-out evaluation. We need to either re-run with a held-out test set, or use cross-validation to compute all metrics.

---

## 2. Which Metrics Matter (and Why)

For a **phishing detection model**, not all metrics are equally important:

### The Metrics You Need

| Metric | What It Measures | Why It Matters for Phishing |
|--------|------------------|---------------------------|
| **Accuracy** | Overall correct predictions / total | Gives a general sense, but **misleading if classes are imbalanced** |
| **Precision** | Of predicted phishing, how many are actually phishing? | High precision = fewer false alarms (legitimate sites wrongly flagged) |
| **Recall (Sensitivity)** | Of actual phishing sites, how many did we catch? | **MOST CRITICAL** — a missed phishing site = real-world damage |
| **F1-Score** | Harmonic mean of Precision & Recall | Balanced single metric when you care about both |
| **F1-Macro** | Average F1 across all classes (equal weight) | Fair evaluation when classes are imbalanced |
| **Confusion Matrix** | Full breakdown of TP, FP, TN, FN | Shows exactly where the model makes mistakes |
| **Classification Report** | Per-class Precision, Recall, F1, Support | Reveals if the model is weak on specific classes |
| **ROC-AUC** | Area under ROC curve | Measures discrimination ability across all thresholds |
| **Cohen's Kappa** | Agreement beyond chance | True performance accounting for class distribution |

### 🏆 Which Metric Is "The Best"?

For phishing detection, the priority order is:

```
1. Recall (Sensitivity)     → "Did we catch all phishing sites?"
2. F1-Macro                 → "Balanced performance across all classes"
3. Precision                → "Are our phishing alerts reliable?"
4. Confusion Matrix         → "Where exactly do we fail?"
5. ROC-AUC                  → "Overall discrimination quality"
6. Accuracy                 → "General correctness" (least important alone)
```

> [!CAUTION]
> **Never rely on Accuracy alone.** If 90% of your data is "Suspected" and the model predicts everything as "Suspected", accuracy = 90% but the model is useless. Always check **Recall per class** and **F1-Macro**.

---

## 3. How To Evaluate: Two Approaches

### Approach A: Cross-Validation on Existing Data (Recommended First Step)

Since you don't have a separate test set, use **Stratified K-Fold Cross-Validation** on your training data. This uses the same data but evaluates on different held-out folds each time.

**Advantage:** Uses all data, statistically robust.
**Disadvantage:** Not a "real" held-out test — but best we can do with current data.

### Approach B: Train/Test Split

Split your data 80/20 (stratified), train on 80%, evaluate on 20%.

**Advantage:** Proper held-out evaluation.
**Disadvantage:** Loses 20% of training data, results depend on which 20% was chosen.

---

## 4. Evaluation Script: Step-by-Step Process

Below is the **complete evaluation script** you should run. It covers both approaches and generates all metrics.

```python
# evaluate_model.py
# Run from the Phishing project root: python evaluate_model.py

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score,
    cohen_kappa_score
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
from xgboost import XGBClassifier

# ==========================
# 1. Load same dataset that was used for training
# ==========================
file_path = "final_training_dataset_with_source.xlsx"
data = pd.read_excel(file_path, sheet_name="final_training_dataset_with_sou")
print(f"✅ Loaded dataset: {len(data)} rows, {data.shape[1]} columns")

# ==========================
# 2. Replicate EXACT same preprocessing as model_training.py
# ==========================
exclude_cols = [
    "url", "ip_address", "ssl_issuer", "brand_colors", "logo_hash",
    "favicon_url", "favicon_size", "favicon_hash", "favicon_colors",
    "ocr_text", "asn_org", "country", "region", "city",
    "label", "source_of_detection"
]

candidate_features = [
    col for col in data.columns
    if col not in exclude_cols and (
        pd.api.types.is_numeric_dtype(data[col]) or 
        pd.api.types.is_bool_dtype(data[col])
    )
]

X_num = data[candidate_features]

if "ssl_issuer" in data.columns:
    ssl_issuer_dummies = pd.get_dummies(data["ssl_issuer"], prefix="ssl_issuer")
    X_num = pd.concat([X_num, ssl_issuer_dummies], axis=1)

imputer = SimpleImputer(strategy="median")
X_num_imputed = imputer.fit_transform(X_num)

scaler = StandardScaler()
X_num_scaled = scaler.fit_transform(X_num_imputed)

# TF-IDF text features
text_features = []
if "ocr_text" in data.columns:
    data["ocr_text"] = data["ocr_text"].fillna("")
    tfidf_ocr = TfidfVectorizer(max_features=300)
    X_ocr = tfidf_ocr.fit_transform(data["ocr_text"])
    text_features.append(X_ocr)

if "asn_org" in data.columns:
    data["asn_org"] = data["asn_org"].fillna("")
    tfidf_asn = TfidfVectorizer(max_features=100)
    X_asn = tfidf_asn.fit_transform(data["asn_org"])
    text_features.append(X_asn)

if "brand_colors" in data.columns:
    data["brand_colors"] = data["brand_colors"].astype(str).fillna("")
    tfidf_colors = TfidfVectorizer(max_features=100)
    X_colors = tfidf_colors.fit_transform(data["brand_colors"])
    text_features.append(X_colors)

if text_features:
    X_all = hstack([X_num_scaled] + text_features).tocsr()
else:
    X_all = X_num_scaled

# Targets
le_label = LabelEncoder()
y_label = le_label.fit_transform(data["label"])

y_source, source_classes = pd.factorize(data["source_of_detection"])

print(f"✅ Features: {X_all.shape}")
print(f"🎯 Label classes: {list(le_label.classes_)}")
print(f"🌍 Source classes: {list(source_classes)}")

# ==========================
# 3. CROSS-VALIDATED EVALUATION (Approach A)
# ==========================
def evaluate_with_cv(X, y, class_names, task_name, n_splits=5):
    """Full cross-validated evaluation with all metrics."""
    
    print(f"\n{'='*70}")
    print(f"📊 EVALUATION: {task_name}")
    print(f"{'='*70}")
    
    min_class = pd.Series(y).value_counts().min()
    actual_splits = min(n_splits, min_class)
    if actual_splits < n_splits:
        print(f"⚠️ Reduced folds from {n_splits} to {actual_splits} (smallest class has {min_class} samples)")
    
    cv = StratifiedKFold(n_splits=actual_splits, shuffle=True, random_state=42)
    
    # Determine objective
    n_classes = len(np.unique(y))
    is_binary = n_classes == 2
    
    xgb = XGBClassifier(
        objective="binary:logistic" if is_binary else "multi:softprob",
        eval_metric="mlogloss",
        random_state=42,
        use_label_encoder=False,
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05
    )
    
    # Get cross-validated predictions
    y_pred = cross_val_predict(xgb, X, y, cv=cv, n_jobs=-1)
    
    # If we need probabilities for ROC-AUC
    try:
        y_proba = cross_val_predict(xgb, X, y, cv=cv, method='predict_proba', n_jobs=-1)
    except:
        y_proba = None
    
    # --- METRICS ---
    acc = accuracy_score(y, y_pred)
    prec_macro = precision_score(y, y_pred, average='macro', zero_division=0)
    rec_macro = recall_score(y, y_pred, average='macro', zero_division=0)
    f1_mac = f1_score(y, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y, y_pred, average='weighted', zero_division=0)
    kappa = cohen_kappa_score(y, y_pred)
    
    print(f"\n📈 OVERALL METRICS:")
    print(f"   Accuracy:         {acc:.4f}  ({acc*100:.2f}%)")
    print(f"   Precision (macro): {prec_macro:.4f}")
    print(f"   Recall (macro):    {rec_macro:.4f}")
    print(f"   F1-Score (macro):  {f1_mac:.4f}")
    print(f"   F1-Score (weighted): {f1_weighted:.4f}")
    print(f"   Cohen's Kappa:    {kappa:.4f}")
    
    # ROC-AUC
    if y_proba is not None:
        try:
            if is_binary:
                auc = roc_auc_score(y, y_proba[:, 1])
            else:
                auc = roc_auc_score(y, y_proba, multi_class='ovr', average='macro')
            print(f"   ROC-AUC (macro):  {auc:.4f}")
        except Exception as e:
            print(f"   ROC-AUC: Could not compute ({e})")
    
    # Per-class report
    print(f"\n📋 PER-CLASS CLASSIFICATION REPORT:")
    print(classification_report(y, y_pred, target_names=class_names, zero_division=0))
    
    # Confusion Matrix
    cm = confusion_matrix(y, y_pred)
    print(f"🔢 CONFUSION MATRIX:")
    print(f"   (rows = actual, columns = predicted)")
    
    # Header
    header = "            " + "  ".join(f"{c:>12}" for c in class_names)
    print(header)
    for i, row in enumerate(cm):
        row_str = f"   {class_names[i]:>8}  " + "  ".join(f"{v:>12}" for v in row)
        print(row_str)
    
    print()
    return {
        "accuracy": acc, "precision_macro": prec_macro,
        "recall_macro": rec_macro, "f1_macro": f1_mac,
        "f1_weighted": f1_weighted, "kappa": kappa
    }

# ==========================
# 4. Run Evaluation for BOTH Models
# ==========================
print("\n" + "🔹"*35)
label_metrics = evaluate_with_cv(
    X_all, y_label, 
    class_names=list(le_label.classes_), 
    task_name="LABEL MODEL (Phishing vs Legitimate)"
)

print("\n" + "🔹"*35)
source_metrics = evaluate_with_cv(
    X_all, y_source, 
    class_names=list(source_classes), 
    task_name="SOURCE OF DETECTION MODEL"
)

# ==========================
# 5. Summary & Recommendations
# ==========================
print("\n" + "="*70)
print("📊 EVALUATION SUMMARY")
print("="*70)
print(f"\n   LABEL MODEL:")
print(f"   ├── Accuracy:    {label_metrics['accuracy']*100:.2f}%")
print(f"   ├── F1-Macro:    {label_metrics['f1_macro']:.4f}")
print(f"   ├── Recall:      {label_metrics['recall_macro']:.4f}")
print(f"   └── Kappa:       {label_metrics['kappa']:.4f}")
print(f"\n   SOURCE MODEL:")
print(f"   ├── Accuracy:    {source_metrics['accuracy']*100:.2f}%")
print(f"   ├── F1-Macro:    {source_metrics['f1_macro']:.4f}")
print(f"   ├── Recall:      {source_metrics['recall_macro']:.4f}")
print(f"   └── Kappa:       {source_metrics['kappa']:.4f}")
print("="*70)
```

---

## 5. What "Good Numbers" Look Like

### Benchmark Targets for Phishing Detection

| Metric | Poor | Acceptable | Good | Excellent |
|--------|------|------------|------|-----------|
| **Accuracy** | < 70% | 70–85% | 85–95% | > 95% |
| **Recall (macro)** | < 60% | 60–75% | 75–90% | > 90% |
| **Precision (macro)** | < 60% | 60–75% | 75–90% | > 90% |
| **F1-Macro** | < 0.60 | 0.60–0.75 | 0.75–0.90 | > 0.90 |
| **ROC-AUC** | < 0.70 | 0.70–0.85 | 0.85–0.95 | > 0.95 |
| **Cohen's Kappa** | < 0.40 | 0.40–0.60 | 0.60–0.80 | > 0.80 |

### Reading the Confusion Matrix

```
                  Predicted
                  Legitimate  Phishing  Suspected
Actual Legitimate     45          2         3        ← Row total = actual count
       Phishing        1         38         1
       Suspected       4          3        53

Key things to look for:
• Diagonal = correct predictions (should be HIGH)
• Off-diagonal = errors (should be LOW)
• Phishing row, non-Phishing columns = MISSED phishing (MOST DANGEROUS)
• Non-Phishing rows, Phishing column = FALSE ALARMS (annoying but safe)
```

---

## 6. Steps To Execute

| Step | Action | Command |
|------|--------|---------|
| 1 | Activate your venv | `.\venv\Scripts\activate` |
| 2 | Ensure training dataset exists | Check `final_training_dataset_with_source.xlsx` is present |
| 3 | Run the evaluation script | `python evaluate_model.py` |
| 4 | Review metrics output | Look at all numbers printed in terminal |
| 5 | Identify weak points | Check confusion matrix for error patterns |
| 6 | Decide on retraining | If numbers are below "Acceptable" thresholds → retrain with Path A |

---

## 7. Interpreting Results — Decision Framework

After you run the script, use this decision tree:

```
F1-Macro ≥ 0.85 AND Recall ≥ 0.80?
├── YES → Model is solid. Retraining with new data is optional.
│         Focus on maintaining and monitoring.
│
└── NO → Check confusion matrix:
         ├── Phishing recall < 0.70?
         │   → CRITICAL: Model misses too many phishing sites.
         │     Priority: Retrain with more phishing examples (Path A).
         │
         ├── Source model F1 < 0.60?
         │   → Source classification is weak.
         │     Consider: More balanced source data, or simplify categories.
         │
         └── Overall accuracy < 0.75?
             → Fundamental model issue.
             → Consider: Feature engineering improvements, more data,
                or try different algorithms (LightGBM, Random Forest).
```
