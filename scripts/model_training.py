import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV
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
    if len(class_counts) == 2:  
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

    xgb = XGBClassifier(
        objective="multi:softprob" if len(np.unique(y)) > 2 else "binary:logistic",
        eval_metric="mlogloss",
        random_state=42,
        scale_pos_weight=scale_pos_weight,
        use_label_encoder=False
    )

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
# 8. Train Both Models
# ==========================
print("\n🔹 Training Label Model...")
best_model_label = tune_xgb(y_label, "Label")

print("\n🔹 Training Source Model...")
best_model_source = tune_xgb(y_source, "Source of Detection")

# ==========================
# 9. Save Everything
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