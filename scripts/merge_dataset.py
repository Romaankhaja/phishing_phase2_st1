# merge_dataset.py
# Merges features_enriched.csv + labels from PS-02_ISS_NLP_Holdout_Submission_Set.xlsx
# into final_training_dataset_with_source.xlsx

import pandas as pd
import re
import os

# ==========================
# 1. Load Files
# ==========================
FEATURES_PATH = r"C:\Users\SATWIK\Downloads\features_enriched (6).csv"
LABELS_PATH = r"C:\Users\SATWIK\Downloads\PS-02_ISS_NLP_Submission (5)\PS-02_ISS_NLP_Submission\PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
OUTPUT_PATH = r"final_training_dataset_with_source.xlsx"

features = pd.read_csv(FEATURES_PATH)
labels = pd.read_excel(LABELS_PATH)

print(f"✅ Features loaded: {len(features)} rows, {features.shape[1]} columns")
print(f"✅ Labels loaded: {len(labels)} rows, {labels.shape[1]} columns")

# ==========================
# 2. Check Label File Sheets (might have multiple)
# ==========================
xls = pd.ExcelFile(LABELS_PATH)
print(f"📄 Sheet names in labels file: {xls.sheet_names}")
for sheet in xls.sheet_names:
    df_sheet = pd.read_excel(xls, sheet_name=sheet)
    print(f"   Sheet '{sheet}': {len(df_sheet)} rows")

# If the first sheet has very few rows, try all sheets
if len(labels) < 10:
    all_sheets = []
    for sheet in xls.sheet_names:
        df_sheet = pd.read_excel(xls, sheet_name=sheet)
        if len(df_sheet) > 0:
            all_sheets.append(df_sheet)
    if len(all_sheets) > 1:
        labels = pd.concat(all_sheets, ignore_index=True)
        print(f"📦 Combined all sheets: {len(labels)} rows total")

print(f"\n📊 Labels columns: {list(labels.columns)}")

# ==========================
# 3. Normalize Domain Names for Matching
# ==========================
def extract_domain(url_or_domain):
    """Extract clean domain from URL or raw domain string."""
    s = str(url_or_domain).strip().lower()
    # Remove protocol
    s = re.sub(r'^https?://', '', s)
    # Remove trailing slashes and paths
    s = s.split('/')[0]
    # Remove www.
    s = re.sub(r'^www\.', '', s)
    # Remove port
    s = s.split(':')[0]
    return s

# Create normalized keys for matching
features['_merge_key'] = features['url'].apply(extract_domain)
labels['_merge_key'] = labels['Identified Phishing/Suspected Domain Name'].apply(extract_domain)

# ==========================
# 4. Check Match Quality
# ==========================
features_keys = set(features['_merge_key'])
labels_keys = set(labels['_merge_key'])
matched = features_keys & labels_keys
only_features = features_keys - labels_keys
only_labels = labels_keys - features_keys

print(f"\n🔍 MERGE ANALYSIS:")
print(f"   Features domains: {len(features_keys)}")
print(f"   Labels domains:   {len(labels_keys)}")
print(f"   ✅ Matched:       {len(matched)}")
print(f"   ⚠️  Only in features (no label): {len(only_features)}")
print(f"   ⚠️  Only in labels (no features): {len(only_labels)}")

if len(only_features) > 0:
    print(f"\n   Sample unmatched feature domains: {list(only_features)[:5]}")
if len(only_labels) > 0:
    print(f"   Sample unmatched label domains: {list(only_labels)[:5]}")

# ==========================
# 5. Merge
# ==========================
# Map label columns: 
#   "Phishing/Suspected Domains (i.e. Class Label)" -> "label"
#   "Source of detection" -> "source_of_detection"

label_map = labels[['_merge_key', 
                     'Phishing/Suspected Domains (i.e. Class Label)', 
                     'Source of detection']].copy()
label_map.columns = ['_merge_key', 'label', 'source_of_detection']

# Drop duplicates (keep first if multiple entries per domain)
label_map = label_map.drop_duplicates(subset='_merge_key', keep='first')

# Left join: keep all features, attach labels where available
merged = features.merge(label_map, on='_merge_key', how='left')

# ==========================
# 6. Handle Unmatched Rows
# ==========================
n_with_labels = merged['label'].notna().sum()
n_without_labels = merged['label'].isna().sum()

print(f"\n📊 MERGE RESULT:")
print(f"   Total rows: {len(merged)}")
print(f"   With labels:    {n_with_labels}")
print(f"   Without labels: {n_without_labels}")

if n_without_labels > 0:
    print(f"\n⚠️  {n_without_labels} rows have NO labels.")
    print(f"   These domains exist in features but not in the labels file.")
    print(f"   They will be filled with 'Suspected' (label) and 'Unknown' (source).")
    merged['label'] = merged['label'].fillna('Suspected')
    merged['source_of_detection'] = merged['source_of_detection'].fillna('Unknown')

# Clean up merge key
merged = merged.drop(columns=['_merge_key'])

# ==========================
# 7. Final Summary
# ==========================
print(f"\n📊 FINAL DATASET:")
print(f"   Shape: {merged.shape}")
print(f"\n   Label distribution:")
print(f"   {merged['label'].value_counts().to_string()}")
print(f"\n   Source distribution:")
print(f"   {merged['source_of_detection'].value_counts().to_string()}")

# ==========================
# 8. Save
# ==========================
# Sheet name truncated to 31 chars (Excel limit)
sheet_name = "final_training_dataset_with_sou"
merged.to_excel(OUTPUT_PATH, sheet_name=sheet_name, index=False)
print(f"\n✅ Saved to: {os.path.abspath(OUTPUT_PATH)}")
print(f"   Sheet name: '{sheet_name}'")
print(f"   {len(merged)} rows × {merged.shape[1]} columns")
print(f"\n🎯 Ready to run: python model_training.py")
