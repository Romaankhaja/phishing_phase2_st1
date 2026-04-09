# Implementation Plan: Fix Pipeline Failures from `fixed_run.log`

## Root Cause Analysis

I've thoroughly analyzed the 69,758-line `fixed_run.log`. The pipeline ran from **01:15 → 04:12** (approximately 3 hours) and **never completed** — it was killed by Ray's GCS (Global Control Store) crashing. Here are the **5 distinct bugs** that cascaded into the failure:

---

### Bug 1: OLD CODE Was Deployed (Critical)

**Evidence:** Line 21 of the log says:
```
🚀 Initializing 45 Stateful Playwright Scrapers & 1 Hot-VRAM GPU Processor...
```

But our latest local `comparison.py` says:
```
🚀 Initializing 24 Stateful Playwright Scrapers & 4 Concurrent GPU Processors...
```

> [!CAUTION]
> The server was running the **OLD version** of `comparison.py` — not the latest fixes. The FileZilla sync step was likely missed or the file wasn't uploaded to the correct directory. This single issue means NONE of our recent optimizations (24 actors, 4 GPU actors, vision_model bypass, semaphore reduction) were active.

---

### Bug 2: Legacy Screenshot Model `'BaseModelOutputWithPooling' has no attribute 'norm'`

**Evidence:** Appears **repeatedly** throughout the log (lines 899, 900, 3920, 3921, 4029, 4783, 5964, 9725-9727, 9832).

**Root Cause:** The old code used `m.get_image_features(**inputs)` which, in the version of `transformers` on the server, returns a `BaseModelOutputWithPooling` wrapper object instead of a raw tensor. When `score_batch` later calls `.norm()` on this object, it crashes.

**Fix (already in local code but not deployed):** Bypass the unreliable API:
```python
# OLD (broken)
features = m.get_image_features(**inputs)

# NEW (robust)
vision_out = m.vision_model(pixel_values=inputs["pixel_values"])
pooler = vision_out.pooler_output if hasattr(vision_out, "pooler_output") else vision_out[1]
features = m.visual_projection(pooler)
```

---

### Bug 3: Chrome Deadlocking — 720 Concurrent Pages

**Evidence:** `⚠ CRITICAL: Chrome headless deadlocked. Rebooting worker and skipping chunk...` appears **~50+ times** across the entire run, often `[repeated 4x-11x across cluster]`.

**Root Cause:** The old code ran `45 actors × 16 semaphore = 720 concurrent Chromium pages`. This crushes the 48-core CPU (load average hit 291!), causing widespread deadlocks.

**Fix:** Reduce to `24 actors × 6 semaphore = 144 concurrent pages` (3 per core — the sweet spot).

---

### Bug 4: Ray GCS Crash — The Kill Shot

**Evidence:** The very last line of the log (line 69757):
```
[2026-03-29 04:12:24,228 E 2180 5313] rpc_client.h:203: Failed to connect to GCS within 60 seconds.
GCS may have been killed... The program will terminate.
```

**Root Cause:** Ray's Global Control Store (GCS) is a single-threaded daemon that manages the entire cluster. When 45 actors + 720 Chrome tabs + constant deadlock reboots overwhelm the system, GCS's heartbeat monitoring falls behind. After 60 seconds of missed heartbeats, GCS self-terminates, killing the entire Ray cluster. However, the orphaned Chrome processes and ScraperActors **continued running as zombies** because `nohup` kept them alive.

**Fix:** Lower concurrency (addressed by Bug 3 fix) + add `ray.shutdown()` in a `finally` block in `main_controller.py`.

---

### Bug 5: `page.close()` Not Called on Exception Path

**Evidence:** Line 69696: `Unclosed client session` + many `TargetClosedError` messages.

**Root Cause:** In `fetch_features()`, when the `_grab()` coroutine raises a `TimeoutError`, we jump to the `except` block but **`page.close()` is never called** because it's placed *after* the try block. The page handle leaks, and eventually Chromium runs out of handles.

**Fix:** Move `page.close()` into a `finally` block.

---

## Proposed Changes

### [MODIFY] [comparison.py](file:///c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/comparison.py)

1. **Fix `fetch_features` page leak** — wrap `page.close()` in `finally` so it always runs
2. **Confirm legacy screenshot-model bypass** — already fixed locally with `vision_model` + `visual_projection`
3. **Confirm concurrency** — already fixed locally (24 actors, Semaphore(6), 4 GPU actors)
4. **Add graceful aiohttp session closure** in `ScraperActor` destructor

### [MODIFY] [main_controller.py](file:///c:/Users/SATWIK/Documents/Phishing/main_controller.py)

1. **Add `ray.shutdown()` in a finally block** — ensures Ray GCS is cleaned up even on crash
2. **Add zombie process cleanup** — kill orphaned `chrome-headless` on exit

---

## User Review Required

> [!IMPORTANT]
> The **#1 action item** is ensuring the updated `comparison.py` actually gets deployed to the server. The previous run was using OLD code. After I apply these fixes, you need to:
> 1. Upload via FileZilla (`sftp://103.42.50.245`, port `2231`, user `user7`)
> 2. Overwrite `/home/user7/new_code/phishing_ml/phishing_pipeline/comparison.py`  
> 3. Also upload the updated `main_controller.py`
> 4. Kill any zombie processes: `pkill -9 -f ray; pkill -9 -f chrome; pkill -9 -f python`
> 5. Re-launch: `nohup python3 -u main_controller.py > logs/fixed_run2.log 2>&1 &`

---

## Verification Plan

### Automated (in logs)
- Log should print `🚀 Initializing 24 Stateful Playwright Scrapers & 4 Concurrent GPU Processors...` (NOT 45/1)
- No `'BaseModelOutputWithPooling' has no attribute 'norm'` errors
- Minimal `CRITICAL: Chrome headless deadlocked` messages (< 5 total)
- Pipeline should reach `⏱ Ray Actor Pool Processing completed cleanly` without dying

### Manual (on server)
- `htop`: `us` should be ~70%+, `sy` should be < 15%, load average < 100
- `nvidia-smi`: GPU-Util should spike periodically, 4 `GPUInferenceActor` processes visible
- Log should NOT end with `Failed to connect to GCS` — it should end with `Finished Step 2`
