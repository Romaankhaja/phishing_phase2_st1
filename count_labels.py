import pandas as pd
import sys

# ========== PASTE YOUR FILE PATH HERE ==========
FILE_PATH = r"C:\Users\SATWIK\Downloads\PS-02_ISS_NLP_Submission_Unlabelled_Data_2026-03-03\PS-02_ISS_NLP_Submission\PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"

# ================================================

def count_labels(filepath):
    col = "Phishing/Suspected Domains (i.e. Class Label)"
    df = pd.read_excel(filepath)

    if col not in df.columns:
        print(f"Error: Column '{col}' not found.")
        print(f"Available columns: {list(df.columns)}")
        return

    counts = df[col].value_counts()
    print(f"\nTotal rows: {len(df)}\n")
    print("Label Counts:")
    print("-" * 35)
    for label, count in counts.items():
        print(f"  {label}: {count}")

    # Show numeric mapping
    print("\nNumeric Label Mapping:")
    print("-" * 35)
    for i, label in enumerate(counts.index):
        print(f"  {i} -> {label} ({counts[label]})")

if __name__ == "__main__":
    # Uses CLI argument if provided, otherwise uses FILE_PATH variable above
    path = sys.argv[1] if len(sys.argv) > 1 else FILE_PATH
    count_labels(path)
