# Production Ray Cleanup Audit

Scope: `main_controller.py` -> `pipeline_mode=hash_only` -> Ray shortlist/classify -> packaging/output

Comment marker: `# UNUSED_IN_PROD_RAY_FLOW: <reason>`

## File Inventory

| File | Status | Live Symbols / Role | Non-Prod / Compat Notes | Candidate Unused Symbols | Risk | Proposed Action |
| --- | --- | --- | --- | --- | --- | --- |
| `main_controller.py` | `live_prod` | CLI entrypoint, runtime resolution, shortlist orchestration, packaging handoff | retains legacy backend selection and resume/packaging compatibility | `_resolve_auto_runtime_profile`, `_apply_stage1_http_runtime_profile`, `_apply_reliability_runtime_profile` | Low | Comment out three unreferenced internal wrappers |
| `phishing_pipeline/config.py` | `live_prod` | canonical runtime/stage config resolution | none for this pass | none | Low | No change |
| `phishing_pipeline/comparison.py` | `live_prod` | lexical shortlist, stage1 admission, hash/render scoring, Ray/legacy shortlist dispatch | contains legacy helpers and env probing still used by shortlist runtime | `_compute_legacy_fuzzy_metrics` | Low | Comment out single unreferenced internal helper |
| `phishing_pipeline/ray_runtime.py` | `live_prod` | Ray actor/runtime primitives, shortlist/classify wrappers | some helpers are debug-only but still referenced | none proven safe this pass | Medium | No change |
| `phishing_pipeline/ray_shortlist_runtime.py` | `live_prod` | production Ray shortlist orchestration | none | none proven safe this pass | Medium | No change |
| `phishing_pipeline/ray_classify_runtime.py` | `live_prod` | production Ray classify orchestration | none | none proven safe this pass | Medium | No change |
| `phishing_pipeline/pipeline.py` | `live_prod` + `fallback_or_compat` | production hash-only classify path, packaging, output shaping | legacy OCR path and CLI remain out of scope for this pass | first `reclassify_label` definition at import time is shadowed by the second definition | Low | Comment out shadowed duplicate definition only |
| `phishing_pipeline/stage1_http_analyzer.py` | `live_prod` | cheap HTTP fetch/parse/enrich/score | none | none | Medium | No change |
| `phishing_pipeline/utils.py` | `live_prod` | network/visual feature extraction helpers and runtime limits | also carries older helper surface | none proven safe this pass | Medium | No change |
| `phishing_pipeline/visual_features.py` | `live_prod` | browser/screenshot/OCR/favicons | none | none | Medium | No change |
| `phishing_pipeline/geoip_utils.py` | `live_prod` | GeoIP enrichment | none | none | Low | No change |
| `phishing_pipeline/model_utils.py` | `live_prod` | model loading | none | none | Low | No change |
| `phishing_pipeline/rdap_utils.py` | `live_prod` | RDAP lookup and metrics | none | none | Low | No change |
| `phishing_pipeline/progress_display.py` | `live_prod` | progress mode resolution and Ray progress rendering | none | none | Low | No change |
| `phishing_pipeline/rate_limiter.py` | `live_prod` | WHOIS throttling | none | none | Low | No change |
| `phishing_pipeline/resource_manager.py` | `live_prod` | resource probing used by utils | none | none | Low | No change |
| `phishing_pipeline/similarity_hashing.py` | `live_prod` | simhash/phash helpers | none | none | Low | No change |
| `phishing_pipeline/features.py` | `live_prod` | URL/entropy/SSL feature helpers used through utils | none | none | Low | No change |
| `phishing_pipeline/reliability.py` | `live_prod` | run context, checkpoints, manifests, artifacts | none | none | Medium | No change |
| `phishing_pipeline/shortlisting.py` | `fallback_or_compat` | `load_url_records_from_excel_folder()` is live; rest is compatibility surface | `run_shortlisting_process()` and `generate_shortlisted_csv()` preserved intentionally | none in first pass | Medium | No change |
| `phishing_pipeline/__init__.py` | `fallback_or_compat` | lightweight lazy package wrappers | public import surface | none | Low | No change |
| `phishing_pipeline/hashing_legit_domains.py` | `tooling_or_training` | entity DB generation support | not in production execution path | out of scope | Low | No change |
| `phishing_pipeline/watcher.py` | `tooling_or_training` | standalone filesystem watcher | explicitly out of scope | out of scope | Low | No change |
| `scripts/*` | `tooling_or_training` | model training / experiments | explicitly out of scope | out of scope | Low | No change |
| `docs/*` | `tooling_or_training` | documentation | explicitly out of scope | out of scope | Low | No change |
| `tests/*` | `tooling_or_training` | regression coverage | must remain for validation | out of scope | Low | No change |

## Proof Notes

- `main_controller.py`
  - `_resolve_auto_runtime_profile` has no callers in the repo after config centralization.
  - `_apply_stage1_http_runtime_profile` has no callers in the repo.
  - `_apply_reliability_runtime_profile` has no callers in the repo.
- `phishing_pipeline/comparison.py`
  - `_compute_legacy_fuzzy_metrics` has no callers in the repo.
- `phishing_pipeline/pipeline.py`
  - `reclassify_label` is defined twice at module scope.
  - The second definition replaces the first during import, so the first body is unreachable in runtime.

## Cleanup Performed In This Pass

- Comment out the three dead internal wrappers in `main_controller.py`
- Comment out `_compute_legacy_fuzzy_metrics` in `comparison.py`
- Comment out the shadowed first `reclassify_label` definition in `pipeline.py`

## Explicitly Deferred

- Legacy CLI / `legacy_ocr` behavior in `phishing_pipeline/pipeline.py`
- Shortlisting compatibility wrappers in `phishing_pipeline/shortlisting.py`
- Tooling and standalone modules such as `watcher.py` and `hashing_legit_domains.py`
- Any symbol that is debug-only, lazy-imported, or compatibility-facing but still referenced
