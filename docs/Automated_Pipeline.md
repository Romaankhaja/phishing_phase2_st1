# Automation Pipeline Implementation Plan

## Goal

Automate the execution of the phishing detection pipeline whenever a new dataset is uploaded to the dashboard.

## Context

- The dashboard saves files in `C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_INPUTS`.
- The pipeline needs to run using the daily folder inside `PHISHING_INPUTS` as the holdout dataset.
- The pipeline results should be zipped and moved to `C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_OUTPUTS`.

## Proposed Solution: Directory Watcher

We will create a Python script `watcher.py` using the `watchdog` library.
This script will:
1. Monitor `C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_INPUTS`.
2. Detect creation of new directories (expected to be named `YYYY-MM-DD`).
3. Wait for file transfers to complete (debounce activity on the folder).
4. Trigger `pipeline.py` with `holdout_folder=<path_to_new_folder>`.
5. After the pipeline finishes, zip the results (evidence + CSVs) and move the zip to `PHISHING_OUTPUTS`.

## User Review Required

- **Target Directory**: Need to confirm the exact absolute path where the dashboard saves files.
- **Concurrency**: What if multiple files are uploaded? Should it queue them?
- **Output**: Where should the results go?

## Proposed Changes

### [phishing_pipeline]

#### [NEW] [watcher.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/watcher.py)

- Implements `Watchdog` observer.
- Calls `pipeline.main()` or `subprocess.run(['python', 'pipeline.py', ...])`.

#### [MODIFY] [pipeline.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py)

- Ensure it can be imported and run as a function, or triggered via CLI with arguments.

## Verification Plan

### Automated Tests

- Create a test script that writes a dummy CSV/folder to the watched directory and asserts that the pipeline starts (logs output).

### Manual Verification

- Run `python watcher.py`
- Manually copy a dataset into the folder.
- Observe pipeline execution.
