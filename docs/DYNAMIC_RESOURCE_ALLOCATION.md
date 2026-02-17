# Dynamic Resource Allocation Strategy

## Overview

This document outlines the strategy for dynamically adjusting concurrency limits in the phishing detection pipeline based on available system resources (CPU, RAM, and GPU).

## Objectives

- **Maximize Throughput**: Utilize available hardware efficiently.
- **Prevent Crashing**: Avoid Out-Of-Memory (OOM) errors, especially on systems with limited GPU VRAM (e.g., RTX 2050 4GB).
- **Adaptability**: Run optimally on both high-end servers and consumer laptops without manual configuration.

## Resource Detection

We will use the following Python libraries:

- `os`: For CPU core count.
- `psutil`: For system RAM.
- `torch`: For NVIDIA GPU VRAM detection (if available).

## Logic & Formulas

### 1. Optical Character Recognition (OCR)

**Constraint**: GPU VRAM (highest priority) or CPU (fallback).

- **GPU Mode**: Each OCR process (EasyOCR) loads a model into VRAM.
  - _Formula_: `max(1, int(TOTAL_VRAM_GB / 3.0))` (If VRAM < 6GB, forced to 1)
  - _Rationale_: A standard EasyOCR model + overhead takes ~1-1.5GB, but fragmentation on 4GB cards is severe. Therefore, we enforce stricter limits: 1 process for <6GB, scaling up only on 8GB+ cards.
- **CPU Mode**: Compute heavy.
  - _Formula_: `max(1, int(CPU_CORES / 2))`

### 2. Screenshots (Headless Browser)

**Constraint**: System RAM.

- **Browser**: Each headless Chrome instance consumes ~300MB - 500MB RAM.
- _Formula_: `max(1, int(AVAILABLE_RAM_GB / 0.5))`
- _Cap_: Capped at 20-30 to prevent simple CPU context switching overhead from becoming the bottleneck.

### 3. Image Processing (Laplacian/Branding)

**Constraint**: CPU & RAM (light).

- _Formula_: `CPU_CORES * 2`

### 4. Network Tasks (RDAP, WHOIS, DNS)

**Constraint**: Network Bandwidth & External Rate Limits.

- **DNS**: Very lightweight. `Count = 200` (Safe default).
- **RDAP**: Moderate. `Count = 10` (To be polite to registries).
- **WHOIS**: Strict rate limits. `Count = 1` (Global lock is usually required for Port 43).

## Implementation Plan

1. Create a `get_system_resources()` helper in `utils.py`.
2. Update `utils.py` to initialize semaphores using these calculated values instead of hardcoded constants.
3. Add logging to inform the user of the detected config at startup.
