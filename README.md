# Phishing Detection Pipeline

A comprehensive machine learning pipeline for detecting phishing domains. This project automates the process of fetching daily domain feeds, extracting network and visual features, and classifying domains using XGBoost models.

## 📂 Project Structure

The project is organized into modular directories for clarity and scalability:

```
Phishing/
├── main_controller.py          # 🚀 Main entry point for the pipeline
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── models/                     # 🤖 Trained ML models & preprocessors
│   ├── xgb_label_model.joblib
│   ├── xgb_source_model.joblib
│   └── (encoders, scalers, imputers...)
│
├── data/                       # 💾 Data storage
│   ├── geolite/                # MaxMind GeoIP databases (.mmdb)
│   ├── whitelists/             # Legitimate domain whitelists
│   ├── holdout_sets/           # Daily feed of newly registered domains
│   ├── training/               # Training datasets
│   └── archive/                # Processed output backups
│
├── scripts/                    # 🛠️ Utility scripts
│   ├── model_training.py       # Script to retrain models
│   ├── merge_dataset.py        # Helper to merge features + labels
│   ├── check_gpu.py            # Diagnostic for GPU availability
│   └── test_whois_speed.py     # Benchmark for WHOIS/RDAP lookups
│
├── phishing_pipeline/          # 🧠 Core pipeline logic
│   ├── pipeline.py             # Orchestrator
│   ├── features.py             # URL/Network feature extraction
│   ├── visual_features.py      # Screenshot & OCR (Playwright/EasyOCR)
│   ├── shortlisting.py         # Domain whitelist filtering
│   ├── config.py               # Central configuration
│   └── ...
│
├── docs/                       # 📚 Detailed documentation
│   ├── code_documentation.md   # Deep dive into code modules
│   └── ...
│
└── output/                     # 📤 Runtime outputs (gitignored)
    ├── holdout.csv             # Filtered suspicious domains
    └── merge.txt               # Combined URL list
```

## 🛠️ Setup & Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/kuchurisatwik/phishing_ml.git
    cd phishing_ml
    ```

2. **Create a Virtual Environment**:

    ```bash
    python -m venv venv
    # Windows:
    .\venv\Scripts\Activate.ps1
    # Linux/Mac:
    source venv/bin/activate
    ```

3. **Install Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

4. **Install Playwright Browsers** (for visual features):

    ```bash
    playwright install chromium
    ```

## 🚀 Usage

### 1. Running the Detection Pipeline

The main controller orchestrates the entire flow: fetching domains, shortlisting, feature extraction, and classification.

```bash
python main_controller.py
```

*By default, it looks for whitelist files in `data/whitelists/` and feed inputs in `data/holdout_sets/`.*

**Key Arguments:**

* `--limit <N>`: Process only the first N domains (useful for testing).
* `--whitelist <path>`: Specify a custom whitelist file.
* `--shortlisting <folder>`: Specify a custom folder for domain feeds.

### 2. Retraining the Models

If you have new labeled data in `data/training/final_training_dataset_with_source.xlsx`:

```bash
python scripts/model_training.py
```

*This will train new XGBoost models and save all artifacts (models, scalers, vectorizers) to the `models/` directory automatically.*

### 3. Benchmarking

To test the speed of the WHOIS/RDAP lookup modules:

```bash
python scripts/test_whois_speed.py
```

## 🧠 Key Modules

* **`phishing_pipeline.pipeline`**: The heart of the system. Manages the async event loop, resource locking (semaphores), and the 2-stage (Network -> Visual) extraction process.
* **`phishing_pipeline.visual_features`**: Uses `Playwright` for high-fidelity screenshots and `EasyOCR` for text extraction. Includes logic for logo detection and color analysis.
* **`phishing_pipeline.shortlisting`**: Implements fuzzy matching (Jaro-Winkler) to identify domains that visually look like whitelisted brands (e.g., `sbi-verify.com` vs `sbi.co.in`).
* **`phishing_pipeline.resource_manager`**: Monitors CPU, RAM, and GPU usage to pause execution if the system is under heavy load, preventing crashes.

For detailed API documentation, see [docs/code_documentation.md](docs/code_documentation.md).
