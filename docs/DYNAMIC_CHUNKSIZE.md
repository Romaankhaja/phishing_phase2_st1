# Walkthrough - Dynamic Chunk Size Implementation

I have reinforced the dynamic resource allocation by making the `CHUNK_SIZE` in the pipeline dynamic as well.

## Changes

### 1. Dynamic Calculation in [utils.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py)

I updated [utils.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/utils.py) to calculate `CHUNK_SIZE` based on the available RAM (via `MAX_CONCURRENT_SCREENSHOTS`).

```python
# utils.py

# A good heuristic is 5x the screenshot concurrency
CHUNK_SIZE = MAX_CONCURRENT_SCREENSHOTS * 5
```

### 2. Pipeline Integration

I updated [pipeline.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py) to import this dynamic value instead of using a hardcoded constant.

```python
# pipeline.py

from .utils import CHUNK_SIZE
# CHUNK_SIZE = 100  <-- Removed hardcoded value
```

## Verification Results

I verified the calculation logic on your system:

- **System RAM:** ~8 GB
- **Detected Screenshot Concurrency:** 15
- **Calculated Chunk Size:** 75 (15 * 5)

This ensures the pipeline adapts its batch size to your hardware capabilities, preventing memory overloads on smaller systems while scaling up on larger ones.
