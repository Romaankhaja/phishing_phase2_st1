import os
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
# Paths
# ==========================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR     = os.path.dirname(SCRIPT_DIR)
DATA_DIR     = os.path.join(ROOT_DIR, "data", "training")
MODELS_DIR   = os.path.join(ROOT_DIR, "models")

os.makedirs(MODELS_DIR, exist_ok=True)

file_path = os.path.join(DATA_DIR, "training_dataset_features.csv")

# ==========================
# 1. Load Dataset
# ==========================
data = pd.read_csv(file_path)
print(f"✅ Loaded dataset with {len(data)} rows and {data.shape[1]} columns")

# ==========================
# 2. Auto Feature Selection
# ==========================
# Columns to exclude from numeric features
exclude_cols = [
    "url", "ip_address", "ssl_issuer",
    "favicon_url", "favicon_size", "favicon_hash", "favicon_colors",
    "ocr_text", "screenshot_path", "visual_hash",
    "asn_org", "country", "region", "city",
    "Cooresponding CSE", "Legitimate Domains",
]

# Keep numeric + boolean features
candidate_features = [
    col for col in data.columns
    if col not in exclude_cols
    and (pd.api.types.is_numeric_dtype(data[col]) or pd.api.types.is_bool_dtype(data[col]))
]

X_num = data[candidate_features]
print(f"🔍 Selected {len(candidate_features)} numeric/boolean features: {candidate_features}")

# One-hot encode SSL issuer if present
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

# ASN Org  (partially available)
if "asn_org" in data.columns and data["asn_org"].notna().sum() > 0:
    data["asn_org"] = data["asn_org"].fillna("")
    tfidf_asn = TfidfVectorizer(max_features=100)
    X_asn = tfidf_asn.fit_transform(data["asn_org"])
    text_features.append(X_asn)
    joblib.dump(tfidf_asn, os.path.join(MODELS_DIR, "tfidf_asn.joblib"))
    print("🌐 Added ASN Org text features (100 TF-IDF dims)")

# Merge numeric + text
if text_features:
    X_all = hstack([X_num_scaled] + text_features).tocsr()
else:
    X_all = X_num_scaled

print(f"✅ Final feature matrix shape: {X_all.shape}")

# ==========================
# 6. Prepare Targets
# ==========================
# --- Label model: predict brand / organisation (Cooresponding CSE) ---
le_label = LabelEncoder()
y_label = le_label.fit_transform(data["Cooresponding CSE"])
print(f"🎯 Label (brand) classes ({len(le_label.classes_)}): {list(le_label.classes_)}")

# --- Source model: predict phishing domain (Legitimate Domains) ---
# Keep only domains that appear >= 5 times so the model can learn meaningful patterns
domain_counts = data["Legitimate Domains"].value_counts()
frequent_domains = domain_counts[domain_counts >= 5].index
data_source = data[data["Legitimate Domains"].isin(frequent_domains)].copy()
X_source = X_all[data["Legitimate Domains"].isin(frequent_domains).values]

y_source, source_classes = pd.factorize(data_source["Legitimate Domains"])
print(f"🌍 Source (domain) classes ({len(source_classes)}): showing top 10 → {list(source_classes[:10])}")
print(f"📊 Source model trained on {len(data_source)} rows (domains with >= 5 occurrences)")

# ==========================
# 7. Hyperparameter Tuning Function
# ==========================
def tune_xgb(X, y, task_name):
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
        "reg_alpha": [0, 0.1, 1],
    }

    xgb = XGBClassifier(
        objective="multi:softprob" if len(np.unique(y)) > 2 else "binary:logistic",
        eval_metric="mlogloss",
        random_state=42,
        scale_pos_weight=scale_pos_weight,
        use_label_encoder=False,
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
        random_state=42,
    )

    search.fit(X, y)
    print(f"🏆 {task_name} Best Params: {search.best_params_}")
    print(f"✅ {task_name} CV F1 Macro: {search.best_score_:.4f}")
    return search.best_estimator_

# ==========================
# 8. Train Both Models
# ==========================
print("\n🔹 Training Label (Brand) Model...")
best_model_label = tune_xgb(X_all, y_label, "Label (Brand)")

print("\n🔹 Training Source (Domain) Model...")
best_model_source = tune_xgb(X_source, y_source, "Source (Domain)")

# ==========================
# 9. Save Everything
# ==========================
joblib.dump(best_model_label,  os.path.join(MODELS_DIR, "xgb_label_model.joblib"))
joblib.dump(best_model_source, os.path.join(MODELS_DIR, "xgb_source_model.joblib"))
joblib.dump(le_label,          os.path.join(MODELS_DIR, "label_encoder_label.joblib"))
joblib.dump(source_classes.tolist(), os.path.join(MODELS_DIR, "source_classes.joblib"))
joblib.dump(scaler,            os.path.join(MODELS_DIR, "scaler.joblib"))
joblib.dump(imputer,           os.path.join(MODELS_DIR, "imputer.joblib"))
joblib.dump(candidate_features, os.path.join(MODELS_DIR, "feature_columns.joblib"))
# Also keep backward-compat copy
joblib.dump(candidate_features, os.path.join(MODELS_DIR, "numeric_feature_columns.joblib"))

print(f"\n✅ Saved all artifacts to {MODELS_DIR}")
print("   Models:       xgb_label_model.joblib, xgb_source_model.joblib")
print("   Encoders:     label_encoder_label.joblib, source_classes.joblib")
print("   Preprocessors: scaler.joblib, imputer.joblib")
print("   Features:     feature_columns.joblib, numeric_feature_columns.joblib")
if "asn_org" in data.columns and data["asn_org"].notna().sum() > 0:
    print("   TF-IDF:       tfidf_asn.joblib")