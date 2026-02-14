# Project Reorganization Walkthrough

Everything has been moved into a clean, modular structure.

## 📂 New Directory Structure

| Directory | Contents |
|-----------|----------|
| `models/` | All 7 [.joblib](file:///c:/Users/SATWIK/Documents/Phishing/scaler.joblib) model files (moved from root) |
| `data/geolite/` | GeoIP databases (`.mmdb`) |
| `data/whitelists/` | Source whitelist Excel files |
| `data/holdout_sets/` | Input folders like `PS-02_hold-out_Set_2` |
| `data/training/` | Training datasets |
| `scripts/` | `model_training.py`, `merge_dataset.py`, etc. |
| `docs/` | All documentation (`.md`) files |
| `output/` | Runtime outputs (`merge.txt`, `holdout.csv`, zips) |
| `phishing_pipeline/` | (Unchanged) Core pipeline logic |

## 🚀 How to Run Commands Now

The commands are exactly the same, but you might need to specify the script location if running manual scripts.

### 1. Run the Main Pipeline (Unchanged)
The CLI defaults have been updated, so you can just run:
```powershell
python main_controller.py
```
*It automatically looks in `data/whitelists/` and `data/holdout_sets/` now.*

### 2. Run Model Training
Since the script moved to `scripts/`:
```powershell
python scripts/model_training.py
```

### 3. Run Speed Tests
```powershell
python scripts/test_whois_speed.py
```

## ✅ Verification
- Ran `main_controller.py` → Successfully found inputs and wrote to `output/`.
- Ran `scripts/model_training.py` → Successfully loaded data from `data/training/` and saved models to `models/`.
