import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV, cross_val_predict
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
import joblib

# ==========================
# 1. Load Dataset
# ==========================
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(ROOT, "models")
os.makedirs(MODELS_DIR, exist_ok=True)
file_path = os.path.join(ROOT, "data", "training", "final_training_dataset_with_source.xlsx")
data = pd.read_excel(file_path, sheet_name="final_training_dataset_with_sou")
print(f"✅ Loaded dataset with {len(data)} rows and {data.shape[1]} columns")

# ==========================
# 2. Auto Feature Selection
# ==========================
exclude_cols = [
    "url", "ip_address", "ssl_issuer", "brand_colors", "logo_hash",
    "favicon_url", "favicon_size", "favicon_hash", "favicon_colors",
    "ocr_text", "asn_org", "country", "region", "city",
    "label", "source_of_detection"
]

# Keep numeric + boolean features
candidate_features = [
    col for col in data.columns
    if col not in exclude_cols and (pd.api.types.is_numeric_dtype(data[col]) or pd.api.types.is_bool_dtype(data[col]))
]

X_num = data[candidate_features]
print(f"🔍 Selected {len(candidate_features)} numeric/boolean features: {candidate_features}")

# One-hot encode SSL issuer separately if needed
if "ssl_issuer" in data.columns:
    ssl_issuer_dummies = pd.get_dummies(data["ssl_issuer"], prefix="ssl_issuer")
    X_num = pd.concat([X_num, ssl_issuer_dummies], axis=1)

# ==========================
# 3. Handle Missing Values
# ==========================
imputer = SimpleImputer(strategy="median")
X_num_imputed = imputer.fit_transform(X_num)

# ==========================
# 4. Scale Numeric Features
# ==========================
scaler = StandardScaler()
X_num_scaled = scaler.fit_transform(X_num_imputed)

# ==========================
# 5. Optional Text Features with TF-IDF
# ==========================
text_features = []

# OCR Text
if "ocr_text" in data.columns:
    data["ocr_text"] = data["ocr_text"].fillna("")
    tfidf_ocr = TfidfVectorizer(max_features=300)  # limit features
    X_ocr = tfidf_ocr.fit_transform(data["ocr_text"])
    text_features.append(X_ocr)
    joblib.dump(tfidf_ocr, os.path.join(MODELS_DIR, "tfidf_ocr.joblib"))
    print("📝 Added OCR text features (300 TF-IDF dims)")

# ASN Org
if "asn_org" in data.columns:
    data["asn_org"] = data["asn_org"].fillna("")
    tfidf_asn = TfidfVectorizer(max_features=100)  # smaller vocab
    X_asn = tfidf_asn.fit_transform(data["asn_org"])
    text_features.append(X_asn)
    joblib.dump(tfidf_asn, os.path.join(MODELS_DIR, "tfidf_asn.joblib"))
    print("🌐 Added ASN Org text features (100 TF-IDF dims)")

# Brand Colors (stringified) if you want to try
if "brand_colors" in data.columns:
    data["brand_colors"] = data["brand_colors"].astype(str).fillna("")
    tfidf_colors = TfidfVectorizer(max_features=100)
    X_colors = tfidf_colors.fit_transform(data["brand_colors"])
    text_features.append(X_colors)
    joblib.dump(tfidf_colors, os.path.join(MODELS_DIR, "tfidf_colors.joblib"))
    print("🎨 Added Brand Colors text features (100 TF-IDF dims)")

# Merge numeric + text
if text_features:
    X_all = hstack([X_num_scaled] + text_features).tocsr()
else:
    X_all = X_num_scaled

print(f"✅ Final feature matrix shape: {X_all.shape}")

# ==========================
# 6. Prepare Targets
# ==========================
le_label = LabelEncoder()
y_label = le_label.fit_transform(data["label"])
print(f"🎯 Label Classes: {list(le_label.classes_)}")

y_source, source_classes = pd.factorize(data["source_of_detection"])
print(f"🌍 Source Classes: {list(source_classes)}")
print("📊 Source Distribution:\n", pd.Series(y_source).value_counts())

# ==========================
# 7. Hyperparameter Tuning Function
# ==========================
def tune_xgb(y, task_name):
    class_counts = pd.Series(y).value_counts()
    n_classes = len(class_counts)
    
    if n_classes < 2:
        print(f"❌ {task_name} SKIPPED: Only 1 class found {list(class_counts.index)}. Need at least 2 classes (e.g. Phishing vs Legitimate) to train.")
        return None

    if n_classes == 2:  
        scale_pos_weight = class_counts[0] / class_counts[1]
    else:
        scale_pos_weight = 1.0

    param_grid = {
        "n_estimators": [100, 200, 300],
        "max_depth": [4, 6, 8],
        "learning_rate": [0.01, 0.05, 0.1],
        "subsample": [0.7, 0.8, 1.0],
        "colsample_bytree": [0.7, 0.8, 1.0],
        "min_child_weight": [1, 5, 10],
        "gamma": [0, 0.1, 0.3],
        "reg_lambda": [1, 5, 10],
        "reg_alpha": [0, 0.1, 1]
    }

    # Remove scale_pos_weight for multiclass to avoid warnings
    xgb_params = {
        "objective": "multi:softprob" if len(pd.unique(y)) > 2 else "binary:logistic",
        "eval_metric": "mlogloss",
        "random_state": 42,
    }
    
    # Only add scale_pos_weight if binary
    if len(pd.unique(y)) == 2:
        xgb_params["scale_pos_weight"] = scale_pos_weight

    xgb = XGBClassifier(**xgb_params)

    min_class_count = class_counts.min()
    n_splits = 5 if min_class_count >= 5 else 3
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    search = RandomizedSearchCV(
        estimator=xgb,
        param_distributions=param_grid,
        n_iter=30,
        scoring="f1_macro",
        n_jobs=-1,
        cv=cv,
        verbose=1,
        random_state=42
    )

    search.fit(X_all, y)
    print(f"🏆 {task_name} Best Params: {search.best_params_}")
    print(f"✅ {task_name} CV F1 Macro: {search.best_score_:.4f}")
    return search.best_estimator_

# ==========================
# 8. Evaluation Function (Approach A)
# ==========================
def evaluate_with_cv(model, X, y, class_names, task_name, n_splits=5):
    """Full cross-validated evaluation with all metrics."""
    
    print(f"\n{'='*70}")
    print(f"📊 EVALUATION: {task_name}")
    print(f"{'='*70}")
    
    min_class = pd.Series(y).value_counts().min()
    actual_splits = min(n_splits, min_class)
    if actual_splits < n_splits:
        print(f"⚠️ Reduced folds from {n_splits} to {actual_splits} (smallest class has {min_class} samples)")
    
    cv = StratifiedKFold(n_splits=actual_splits, shuffle=True, random_state=42)
    
    # Get cross-validated predictions
    # Note: cross_val_predict clones the estimator, so we use the best params from input model
    y_pred = cross_val_predict(model, X, y, cv=cv, n_jobs=-1)
    
    # If we need probabilities for ROC-AUC
    try:
        y_proba = cross_val_predict(model, X, y, cv=cv, method='predict_proba', n_jobs=-1)
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
            n_classes = len(np.unique(y))
            if n_classes == 2:
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
# 9. Train Both Models & Evaluate
# ==========================
print("\n🔹 Training Label Model...")
best_model_label = tune_xgb(y_label, "Label")
if best_model_label:
    evaluate_with_cv(
        best_model_label, X_all, y_label, 
        class_names=list(le_label.classes_), 
        task_name="LABEL MODEL (Phishing vs Legitimate)"
    )

print("\n🔹 Training Source Model...")
best_model_source = tune_xgb(y_source, "Source of Detection")
if best_model_source:
    evaluate_with_cv(
        best_model_source, X_all, y_source, 
        class_names=list(source_classes), 
        task_name="SOURCE OF DETECTION MODEL"
    )

# ==========================
# 10. Save Everything
# ==========================
MODELS_DIR = os.path.join(ROOT, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

joblib.dump(best_model_label, os.path.join(MODELS_DIR, "xgb_label_model.joblib"))
joblib.dump(best_model_source, os.path.join(MODELS_DIR, "xgb_source_model.joblib"))
joblib.dump(le_label, os.path.join(MODELS_DIR, "label_encoder_label.joblib"))
joblib.dump(source_classes.tolist(), os.path.join(MODELS_DIR, "source_classes.joblib"))
joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"))
joblib.dump(imputer, os.path.join(MODELS_DIR, "imputer.joblib"))
joblib.dump(candidate_features, os.path.join(MODELS_DIR, "numeric_feature_columns.joblib"))

print("✅ Saved models, encoders, scaler, imputer & features.")