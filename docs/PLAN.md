# Unified Pipeline Monitor (2-Artifact Design)

## Summary
- Replace the current telemetry/reliability artifact set with exactly two monitoring artifacts per run:
  - `output/runs/<run_id>/monitor/pipeline_monitor.log`
  - `output/runs/<run_id>/monitor/pipeline_monitor.csv`
- Mirror only those two files to `output/latest/monitor/`. Do not create root-level legacy monitor copies such as `checkpoints.csv`, `pipeline_stage_events.csv`, `run_manifest.*`, `run_summary.json`, `stage_metrics.csv`, `stall_events.csv`, `worker_heartbeats.csv`, `hashing_shortlist.log`, or `stage1_deep_analysis_candidates.csv`.
- Keep business outputs unchanged (`holdout.csv`, final output CSVs, packaging artifacts, and debug outputs not explicitly retired).
- Remove cross-run resume as a feature. A new run always starts clean; monitoring is for live analysis and post-run bottleneck diagnosis only.

## Key Changes
- In `phishing_pipeline.reliability`, keep the in-process store abstraction but repurpose it from checkpoint export to monitor export.
  - `RunContext` gains canonical monitor paths (`monitor_log_path`, `monitor_csv_path`) and drops legacy telemetry exports from the artifact map.
  - `CheckpointStore` keeps its current call surface for minimal code churn, but its methods now normalize into one unified monitor stream instead of many files.
- Define a single structured CSV contract with fixed columns:
  - `run_id`, `emitted_at`, `stage`, `substage`, `event_kind`, `status`, `worker_id`, `record_key`, `stage_elapsed_ms`, `interval_ms`, `items_total`, `items_completed`, `items_failed`, `items_skipped`, `items_pending`, `queue_depth`, `inflight`, `rate_per_sec`, `avg_latency_ms`, `max_latency_ms`, `cpu_percent`, `process_cpu_percent`, `rss_mb`, `ram_percent`, `used_cpu_cores`, `available_cpu_cores`, `bottleneck`, `message`, `details_json`
  - `stage` values: `run`, `stage0`, `stage1`, `hash`, `classify`, `finalize`
  - `substage` values come from existing runtime signals such as `lexical`, `fetch`, `parse`, `score`, `enrich`, `render`, `finalize`, `ocr`, `model`
  - `event_kind` values: `run_start`, `stage_start`, `progress`, `warning`, `stall`, `stage_end`, `run_end`, `debug_worker`
- Build the human log from the same monitor pipeline.
  - Attach one unified file handler at controller start so controller, shortlist, hash, classify, and watchdog logs all land in `pipeline_monitor.log`.
  - Replace `_configure_hashing_log`/`_close_hashing_log` so hash-stage messages route into the unified log instead of `hashing_shortlist.log`.
  - Standardize progress lines to always include elapsed time, rate, CPU, RAM, inflight, queue/backlog, and the current bottleneck reason.
- Emit monitor rows from existing stage telemetry rather than inventing parallel tracking.
  - Ray shortlist: periodic rows from `_log_metrics_periodically`, including Ray CPU availability plus existing stage0/stage1/hash counters and queue depths.
  - Legacy shortlist/stage1: reuse existing `comparison.py` telemetry (`cpu_backlog_s`, queue pressure, wait times, timeout ratio, fetch limit, queue depths).
  - Classify: emit periodic rows with inflight count, review/output counts, OCR queue stats, model throughput, and host/process CPU.
  - Watchdog/stall conditions become `warning`/`stall` rows in the same CSV and log.
- Replace standalone deep-analysis and heartbeat artifacts with aggregated monitor output.
  - `stage1_deep_analysis_candidates.csv` is retired; stage1 end/progress rows include candidate counts, excluded counts, review-queue counts, and optional sampled examples in `details_json`.
  - Worker heartbeats are no longer a standalone file. In `sampled` and `full`, export only aggregate worker/inflight counts; in `debug`, also emit `debug_worker` rows into the same CSV.
- Controller/runtime behavior changes:
  - Remove manifest-based resume lookup and checkpoint-file reuse from `main_controller.py`.
  - Keep `--telemetry-mode`; it changes row density only, not artifact count.
  - Keep `--resume` and `--force-reprocess` as deprecated no-op flags for compatibility, with a warning at startup.

## Test Plan
- Update reliability contract tests to assert:
  - only `pipeline_monitor.log` and `pipeline_monitor.csv` are created under `runs/<run_id>/monitor/` and `latest/monitor/`
  - retired telemetry files are not created
  - CSV rows contain the required columns and end with a `run_end` bottleneck summary
- Update resume-related tests to expect clean-start behavior and deprecation warnings instead of manifest/checkpoint reuse.
- Add focused runtime tests for shortlist and classify that verify monitor rows contain:
  - stage/substage names
  - elapsed time and `rate_per_sec`
  - CPU/memory snapshots
  - queue depth / inflight counts
  - stall or warning rows when watchdog conditions trigger
- Add one end-to-end smoke test that validates the final log clearly identifies the slowest stage/substage and its share of total runtime.

## Assumptions
- `output/` is the canonical runtime artifact root; `server_output/` is treated as a downstream mirror outside the core code path and should be updated separately if it copies monitor artifacts.
- Host/process CPU comes from `psutil`; Ray rows also include cluster CPU availability. Bottleneck detection is based on elapsed time, backlog, throughput, and resource snapshots, not false per-substage CPU attribution.
- Final deliverables remain unchanged; this plan only collapses the monitoring/reliability artifact footprint into the two-file monitor contract.
