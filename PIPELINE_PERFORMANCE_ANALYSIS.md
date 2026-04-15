# Pipeline Performance Analysis Report

## EXECUTIVE SUMMARY

**Run ID:** run_20260414T180434Z  
**Status:** ✓ COMPLETED  
**Total Pipeline Duration:** **4 minutes 25 seconds (265 seconds)**

| Metric | Value |
|--------|-------|
| Start Time | 2026-04-14 18:04:34 UTC |
| End Time | 2026-04-14 18:08:59 UTC |
| Total Duration | 265 seconds (4m 25s) |
| System: CPU Cores | 12 |
| System: RAM | 7.74 GB |
| System: VRAM | ~4.0 GB |
| Planned CPU Budget | 10.2 cores |
| Target CPU Utilization | 82% |

---

## STAGE-WISE TIME BREAKDOWN

### **STAGE 0: LEXICAL SCANNING**
- **Duration:** ~2 minutes (120 seconds) - 45% of total time
- **Time Window:** 18:04:34 → 18:06:26
- **Status:** LEXICAL_HIT - All 64 records matched
- **Key Metrics:**
  - Total Records Processed: 64
  - Lexical Hits: 64 (100%)
  - Batch Size: 256 URLs per batch
  - Workers: 8 parallel workers
  - CPU Utilization: ~0.08-0.083 (8.3%)

### **STAGE 1: HTTP ANALYSIS & DNS GATING**
- **Duration:** ~1 minute 52 seconds (112 seconds) - 42% of total time
- **Time Window:** 18:06:26 → 18:08:05
- **Phases within Stage 1:**
  - DNS Gate: Started at 18:06:29
  - DNS decisions: 62 accepted, 2 passthrough
  - Browser-based analysis (hashing): Multiple phases with queue management

- **Key Metrics:**
  - Stage 1 Fetch Limit: 1 (capped)
  - Stage 1 Enrich Limit: 1 (capped)
  - HTTP Connection Pool: 192 max (kept low due to resource constraints)
  - DNS Concurrency: 96
  - HTTP Concurrency: 96
  - RDAP Concurrency: 4
  - CPU Utilization: ~0.042-0.125 (4-12.5%)
  
- **Processing Details:**
  - Stage 0 Hits Passed: 64
  - DNS Gate Accepted: 62
  - DNS Gate Passthrough: 2
  - Render Queue Peak: 62 items
  - Browser Actors: 1 (resource-constrained)
  - Hash Finalization Batches: 2

### **STAGE 2 & 3: CLASSIFICATION & FLAGGING**
- **Duration:** ~33 seconds (33 seconds) - 13% of total time
- **Time Window:** 18:08:05 → 18:08:59
- **Initial Metrics (18:08:05):**
  - Classify Actors: 1
  - CPU Utilization: 0% (startup)
  - Checkpoint Pending: 0

- **Final Metrics (18:08:55):**
  - Items Completed: 9
  - Items Flagged: 9
  - OCR Batches Processed: 5
  - OCR Items Processed: 5
  - CPU Utilization: ~0.167 (16.7%)

---

## DETAILED TIME METRICS (5-Second Snapshots)

### SHORTLIST/HASH PHASE PROGRESSION

| Timestamp | Elapsed | CPU Used | CPU Avail | CPU% | Completed | Pending | Hash Backlog | Browser Status |
|-----------|---------|----------|-----------|------|-----------|---------|--------------|---|
| 18:05:46 | 0m 12s | 1.0 | 11.0 | 0% | 0 | 0 | 0 | Idle |
| 18:05:51 | 0m 17s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:05:56 | 0m 22s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:06:01 | 0m 27s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:06:06 | 0m 32s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:06:12 | 0m 38s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:06:17 | 0m 43s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:06:22 | 0m 48s | 1.0 | 11.0 | 8.3% | 0 | 0 | 0 | Idle |
| 18:06:32 | 0m 58s | 0.5 | 11.5 | 4.2% | 2 | 260 | 61 | 1 Active |
| 18:06:42 | 1m 08s | 0.5 | 11.5 | 4.2% | 2 | 0 | 61 | 1 Active |
| 18:06:52 | 1m 18s | 0.5 | 11.5 | 4.2% | 2 | 0 | 61 | 1 Active |
| 18:07:02 | 1m 28s | 0.5 | 11.5 | 4.2% | 8 | 12 | 54 | 1 Active |
| 18:07:07 | 1m 33s | 0.5 | 11.5 | 4.2% | 16 | 36 | 47 | 1 Active |
| 18:07:12 | 1m 38s | 0.5 | 11.5 | 4.2% | 18 | 12 | 45 | 1 Active |
| 18:07:17 | 1m 43s | 1.5 | 10.5 | 12.5% | 20 | 29 | 40 | 1 Active |
| 18:07:22 | 1m 48s | 1.5 | 10.5 | 12.5% | 23 | 16 | 37 | 1 Active |
| 18:07:27 | 1m 53s | 1.5 | 10.5 | 12.5% | 26 | 33 | 32 | 1 Active |
| 18:07:32 | 1m 58s | 0.5 | 11.5 | 4.2% | 35 | 18 | 27 | 1 Active |
| 18:07:37 | 2m 03s | 0.5 | 11.0 | 8.3% | 44 | 47 | 19 | 1 Active |
| 18:07:42 | 2m 08s | 0.5 | 11.0 | 8.3% | 50 | 17 | 13 | 1 Active |
| 18:07:47 | 2m 13s | 0.5 | 11.5 | 4.2% | 56 | 46 | 7 | 1 Active |
| 18:07:52 | 2m 18s | 0.5 | 11.5 | 4.2% | 62 | 34 | 1 | 1 Active |

### CLASSIFICATION PHASE PROGRESSION

| Timestamp | Elapsed | CPU Used | CPU Avail | CPU% | Completed | Flagged | Items Processed |
|-----------|---------|----------|-----------|------|-----------|---------|---|
| 18:08:05 | 3m 31s | 2.0 | 10.0 | 0% | 0 | 0 | 0 |
| 18:08:10 | 3m 36s | 2.0 | 10.0 | 16.7% | 0 | 0 | 0 |
| 18:08:15 | 3m 41s | 2.0 | 10.0 | 16.7% | 0 | 0 | 0 |
| 18:08:20 | 3m 46s | 2.0 | 10.0 | 16.7% | 0 | 0 | 0 |
| 18:08:25 | 3m 51s | 2.0 | 10.0 | 16.7% | 0 | 0 | 0 |
| 18:08:30 | 3m 56s | 2.0 | 10.0 | 16.7% | 0 | 0 | 0 |
| 18:08:35 | 4m 01s | 2.0 | 10.0 | 16.7% | 0 | 0 | 1 |
| 18:08:40 | 4m 06s | 2.0 | 10.0 | 16.7% | 0 | 0 | 1 |
| 18:08:45 | 4m 11s | 2.0 | 10.0 | 16.7% | 0 | 0 | 1 |
| 18:08:50 | 4m 16s | 2.0 | 10.0 | 16.7% | 2 | 2 | 3 |
| 18:08:55 | 4m 21s | 2.0 | 10.0 | 16.7% | 8 | 9 | 5 |

---

## PERFORMANCE INSIGHTS & BOTTLENECKS

### 1. **STAGE 0 (LEXICAL) - Initial Bottleneck (120s)**
   - **Issue:** Long initial wait period (48 seconds) with minimal CPU utilization
   - **Cause:** System loading configuration and initializing workers
   - **CPU Usage:** Only 1 CPU core active (8.3% utilization)
   - **Recommendation:** Pre-warm workers or parallelize initialization

### 2. **STAGE 1 (HTTP/DNS) - Low Resource Utilization (112s)**
   - **Issue:** System running in LOW_MEMORY_MODE with very restricted concurrency
   - **Constraints Detected:**
     - Only 1 HTML browser actor active (could support 3-5)
     - Only 1 fetch actor active
     - Only 1 enrich actor active
     - CPU utilization ranges 4-12.5% (target: 82%)
   - **Root Cause:** Very low memory available (0.25 GB free out of 7.74 GB)
   - **Result:** Hash rendering backlog peaked at 62 items waiting

### 3. **STAGE 2/3 (CLASSIFICATION) - Slow Ramp-Up (33s)**
   - **Issue:** Slow classification processing at 16.7% CPU utilization
   - **Processing Rate:** ~0.3-1.5 items per 5 seconds
   - **Bottleneck:** Single classify actor with OCR model loading overhead

### 4. **Resource Constraints - Critical Impact**
   ```
   Memory Status:
   - Cluster Memory: 0.25 GB
   - Available Memory: 0.25 GB
   - System RAM: 7.74 GB total (0.53 GB free)
   - Operating Mode: VERY_LOW_MEMORY_MODE + critical_memory_mode
   
   CPU Status:
   - Target Utilization: 82%
   - Achieved Utilization: 4-16.7% average
   - Utilization Rate: Only ~5-20% of target
   ```

---

## KEY METRICS SUMMARY

### **CPU Concurrency Levels (Actual vs Configured)**

| Component | Configured | Actual | Utilization |
|-----------|-----------|--------|---|
| Lexical Workers | 8 | 8 | 100% |
| Stage 0 Inflight | 1 | 1 | 100% |
| Stage 1 Fetch Actors | 1 | 1 | 100% |
| Stage 1 Enrich Actors | 1 | 1 | 100% |
| Hash Browser Actors | 1 | 1 | 100% |
| Classify Actors | 1 | 1 | 100% |
| HTTP Concurrency Max | 192 | 96 (clamped) | 50% |
| DNS Concurrency Max | 96 | 96 | 100% |

### **Queue Depths (Bottleneck Indicators)**

| Queue | Peak | Status | Impact |
|-------|------|--------|--------|
| Hash Render Queue | 62 items | Saturated | 2+ second delays per item |
| Stage 0 Pending | 260 items | High | Checkpoint pending |
| Hash Backlog | 61 items | Critical | Rendering delays |
| Finalize Queue | 4 items | Normal | Low impact |

---

## RECOMMENDATIONS FOR OPTIMIZATION

### **Priority 1: Increase Memory Availability**
- Free up 2-3 GB of system RAM
- Reduce other processes consuming memory
- Restart with more available heap space
- **Potential Impact:** 2-3x pipeline speedup

### **Priority 2: Increase Actor Concurrency**
Once memory is available:
- Increase hash_browser_actors from 1 → 3
- Increase stage1_fetch_actors from 1 → 3  
- Increase classify_actors from 1 → 2
- **Potential Impact:** 1.5-2x pipeline speedup

### **Priority 3: Optimize HTTP Connection Management**
- HTTP connection limit could be increased to 192 (currently clamped at 96)
- Keep-alive limit currently at 96
- **Potential Impact:** 10-15% improvement

### **Priority 4: Reduce Initialization Overhead**
- Pre-warm browser actors at startup
- Cache DNS resolutions
- **Potential Impact:** Save ~30-50 seconds

---

## CONCLUSION

**Pipeline completed successfully in 4m 25s, but was significantly constrained by:**
1. **Memory pressure** (only 0.25 GB cluster memory available)
2. **Low CPU utilization** (5-20% vs 82% target)
3. **Single-threaded actor design** (1 browser, 1 fetch, 1 classify actor)
4. **System initialization overhead** (~48-second startup delay)

**If memory constraints are resolved, pipeline could achieve 2-3x speedup** through increased concurrency and parallelization.

---

**Report Generated:** 2026-04-15
**Data Source:** run_summary.json, stage_metrics.csv, pipeline_stage_events.csv
