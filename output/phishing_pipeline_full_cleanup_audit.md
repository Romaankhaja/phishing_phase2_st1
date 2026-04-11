# `phishing_pipeline` Full Cleanup Audit

Scope baseline: controller-centric workflow (`main_controller.py` plus the package code it drives)

Cleanup marker for this pass: `# UNUSED_IN_CURRENT_WORKFLOW: <reason>`

Existing narrower markers such as `UNUSED_IN_PROD_RAY_FLOW` remain valid.

## File Inventory

| File | Module Status | Preserved Entrypoints / Public Surface | Private/Internal Candidate Unused Symbols | Proof Basis | Risk | Action |
| --- | --- | --- | --- | --- | --- | --- |
| `__init__.py` | `public_compat_surface` | `run_pipeline`, `package_results` lazy wrappers | none | package import surface; imported externally even if lightly referenced in-repo | Low | Preserve |
| `blacklist_features.csv` | `non_code_artifact` | artifact placeholder only | n/a | non-code file referenced by config path constants | Low | No change |
| `comparison.py` | `live_controller_path` | `run_hashing_shortlist*`, shortlist helpers used by `pipeline.py` and Ray runtime, standalone CLI block | `_read_env_int_alias`, `_write_hashing_log_messages`, `_write_stage1_methods_csv`, `_write_stage1_deep_analysis_candidates_csv`, `_log_stage1_method_summary`, `_best_matching_entity_domain`, `_compute_typosquat_scores`; `_compute_legacy_fuzzy_metrics` already commented in prior pass | repo-wide reference scan found definition-only occurrences; direct caller review confirmed no workflow use; no lazy or test references for these symbols | Medium | Comment only those private helpers |
| `config.py` | `live_controller_path` | exported config constants and resolver API | none proven safe | every top-level private helper still used by resolver flow | Low | Preserve |
| `features.py` | `live_controller_path` | feature extraction helpers consumed via `utils.py` | none proven safe | all exported functions are used through `utils.py` | Low | Preserve |
| `geoip_utils.py` | `live_controller_path` | `enrich_with_geoip` | none | directly imported by pipeline and Ray classify/runtime | Low | Preserve |
| `hashing_legit_domains.py` | `standalone_utility` | `generate_hashes()` script behavior and its internal worker path | none proven safe | not imported by package runtime, but internally self-contained utility; private helpers are used within script flow | Low | Preserve |
| `model_utils.py` | `live_controller_path` | `load_models_and_preproc` | none | directly imported by pipeline and Ray runtime | Low | Preserve |
| `pipeline.py` | `live_controller_path` + `public_compat_surface` | `run_pipeline`, `package_results`, CLI `__main__`, current precision-first classification path | `_is_suspicious_infra`, `_is_trusted_infra`; shadowed first `reclassify_label` already commented in prior pass | repo-wide scan shows definition-only occurrences; logic review confirms current pipeline inlines these checks elsewhere | Medium | Comment those two private helpers only |
| `progress_display.py` | `live_controller_path` | progress mode and Ray progress helpers | none | imported by Ray shortlist/classify runtime | Low | Preserve |
| `rate_limiter.py` | `live_controller_path` | `RateLimiter` | none | directly used by `pipeline.py` | Low | Preserve |
| `ray_classify_runtime.py` | `live_controller_path` | full Ray classify orchestration | none proven safe | all private helpers are referenced by orchestration, telemetry, or tests | High | Preserve |
| `ray_runtime.py` | `live_controller_path` | Ray actor/runtime primitives and wrappers | none proven safe | private helpers and actor impls are all referenced by runtime or wrappers | High | Preserve |
| `ray_shortlist_runtime.py` | `live_controller_path` | full Ray shortlist orchestration | none proven safe | all private helpers are part of active orchestration or telemetry | High | Preserve |
| `rdap_utils.py` | `live_controller_path` | RDAP lookup/state helpers | none proven safe | all private helpers are part of lookup flow | Low | Preserve |
| `reliability.py` | `live_controller_path` | run context, checkpoints, manifests, artifacts | `_copy_csv_atomic` | definition-only occurrence; not used by current artifact writers or sync helpers | Medium | Comment private helper |
| `resource_manager.py` | `live_controller_path` | `ResourceMonitor` | none | imported via `utils.py` | Low | Preserve |
| `shortlisting.py` | `public_compat_surface` | `load_url_records_from_excel_folder`, public loaders, compatibility wrappers | none proven safe | controller uses loader; compat wrappers preserved intentionally | Medium | Preserve |
| `similarity_hashing.py` | `live_controller_path` | simhash/phash helpers | none | used by `comparison.py` and standalone hashing utility | Low | Preserve |
| `stage1_http_analyzer.py` | `live_controller_path` | Stage 1 fetch/parse/enrich/score API | none proven safe | private helpers all participate in HTML parsing or enrich flow | Medium | Preserve |
| `utils.py` | `live_controller_path` | feature extraction helpers, concurrency limits, OCR/TVC helpers | none proven safe | private helpers are used within extraction/TVC flow | Medium | Preserve |
| `visual_features.py` | `live_controller_path` | browser, screenshot, OCR, favicon helpers | none proven safe | imported by pipeline, utils, and Ray runtime | Medium | Preserve |
| `watcher.py` | `standalone_utility` | `check_and_run`, `watch_with_watchdog`, CLI `__main__` | none proven safe | standalone operator utility, not part of controller workflow but intentionally preserved | Low | Preserve |

## Proof Notes

- Reverse dependency scan:
  - controller/runtime path centers on `comparison.py`, `pipeline.py`, `ray_runtime.py`, `ray_shortlist_runtime.py`, `ray_classify_runtime.py`, `config.py`, `reliability.py`, `stage1_http_analyzer.py`, `utils.py`, and their direct dependencies.
  - `watcher.py` and `hashing_legit_domains.py` have no package imports but are preserved as standalone utilities.
- CLI entrypoints inside `phishing_pipeline`:
  - `comparison.py`
  - `pipeline.py`
  - `watcher.py`
- Zero-caller private helpers verified by repo-wide search:
  - `comparison.py`: `_read_env_int_alias`, `_write_hashing_log_messages`, `_write_stage1_methods_csv`, `_write_stage1_deep_analysis_candidates_csv`, `_log_stage1_method_summary`, `_best_matching_entity_domain`, `_compute_typosquat_scores`
  - `pipeline.py`: `_is_suspicious_infra`, `_is_trusted_infra`
  - `reliability.py`: `_copy_csv_atomic`
- Shadowed duplicate already present from prior pass:
  - first `pipeline.py::reclassify_label`

## Cleanup Performed In This Pass

- Comment out the verified zero-caller private helpers in `comparison.py`
- Comment out the two zero-caller private helpers in `pipeline.py`
- Comment out `_copy_csv_atomic` in `reliability.py`
- Preserve all standalone utilities, CLI entrypoints, public wrappers, and compatibility surfaces

## Explicitly Deferred

- Any cleanup inside `ray_runtime.py`, `ray_shortlist_runtime.py`, or `ray_classify_runtime.py`
- Public wrappers in `shortlisting.py` and `__init__.py`
- Standalone utility modules `watcher.py` and `hashing_legit_domains.py`
- Non-code artifact cleanup such as `blacklist_features.csv`
