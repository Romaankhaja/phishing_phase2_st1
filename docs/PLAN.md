# Auto-Safe Runtime Defaults and RDAP Backpressure Without Changing Classification Logic

## Summary
- Change controller default behavior so plain `python main_controller.py` auto-selects a safer runtime profile from the current machine instead of leaving hash/Stage 1 networking at the current fixed-high defaults.
- Keep all scoring, thresholds, Stage 1 suspicion math, fetch-failure handling, and final `Phishing` / `Suspected` / `Legitimate` rules unchanged.
- Fix the RDAP flood operationally, not semantically: reduce request pressure, dedupe repeated exact-domain lookups within a run, and add bounded backoff/retry for `429` and transient transport failures.
- Do not include Windows Proactor warning cleanup in this change set. That is out of scope for this plan.

## Key Changes
- In [main_controller.py](c:/Users/SATWIK/Documents/Phishing/main_controller.py), make runtime profile selection machine-aware by default.
  - Add `auto` as the preferred profile mode.
  - Keep `default` as a backward-compatible alias to `auto`.
  - Manual profiles remain `cpu-safe`, `cpu-recall`, and `cpu-fast`.
  - Log both `requested_profile` and `resolved_profile`.
- Resolve profiles with explicit rules:
  - Small Windows/laptop class: resolve to `cpu-safe`.
    Chosen when any of: `cpu_cores <= 16`, `ram_gb < 16`, or `0 < vram_gb <= 6`.
  - Large server-class CPU-only host: resolve to `cpu-recall`.
    Chosen when `cpu_cores >= 32` and `ram_gb >= 96`.
  - Mid-tier host: resolve to `cpu-fast`.
  - Explicit CLI profile always overrides auto selection.
- Keep profile changes concurrency-only:
  - Hash shortlist env caps
  - Stage 1 HTTP concurrency caps
  - Stage 1 ancillary network caps
  - No profile is allowed to change scoring weights, lexical thresholds, Stage 1 score thresholds, recall passthrough flags, or failed-fetch rescue thresholds.
- In [phishing_pipeline/rdap_utils.py](c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/rdap_utils.py), add RDAP backpressure and clearer failure handling.
  - Reuse the shared caller client when provided; do not create extra clients per request path.
  - Add exact-domain in-run cache keyed by the queried domain string so repeated identical lookups return the same parsed result without another outbound call.
  - Add bounded retry for RDAP `429` and transient request exceptions only.
    Use short exponential backoff with jitter and a small retry cap.
  - Improve exception logging so empty exception text becomes a useful message with exception type.
  - Keep RDAP query target unchanged as the current `final_domain` string.
    Do not switch to apex/registrable-domain lookup in this change because that can change Stage 1 age-derived evidence and downstream outcomes.
- In [phishing_pipeline/stage1_http_analyzer.py](c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/stage1_http_analyzer.py), keep the Stage 1 call graph unchanged except for using the hardened RDAP helper behavior.
  - No change to `score_stage1_http_signals()`
  - No change to `brand_score`, `credential_score`, `infra_score`, `evasion_score`
  - No change to escalation rules
- Update controller/runtime logging to make operational diagnosis easier.
  - Log resolved concurrency values after profile auto-selection.
  - Log RDAP retry/backoff events at debug or info level, and keep 429s as warnings.
  - Add summary counters for RDAP `success`, `429`, `retry_success`, `retry_exhausted`, `exception`, and `cache_hit` in the hashing log if feasible without widening existing CSV schemas.

## Public Interfaces
- `--runtime-profile` should support: `auto`, `default`, `cpu-safe`, `cpu-recall`, `cpu-fast`
- Default CLI behavior should be `auto`.
- `default` remains accepted but maps to `auto`.
- No changes to classification-related CLI flags or output schemas are required.

## Test Plan
- Add controller tests for profile resolution:
  - current laptop-like host mock `12 CPU / 7.7 GB RAM / 4 GB VRAM / Windows` resolves to `cpu-safe`
  - large CPU-only server mock `48 CPU / 250 GB RAM / 0 VRAM` resolves to `cpu-recall`
  - explicit `cpu-fast` bypasses auto selection
- Add regression tests ensuring profile application only mutates concurrency fields:
  - Stage 1 score thresholds remain unchanged
  - recall passthrough flags remain unchanged
  - failed-fetch thresholds remain unchanged
- Add RDAP helper tests:
  - repeated exact-domain lookup in one run hits cache after first success
  - repeated exact-domain lookup in one run hits cache after first empty/failure result if failure caching is enabled
  - `429` triggers bounded retry/backoff and preserves the same output schema
  - empty exception message logs a non-empty diagnostic string
  - non-429 hard failures do not loop indefinitely
- Add end-to-end smoke assertions for current Windows-sized fixture behavior:
  - plain controller run logs `resolved_profile=cpu-safe`
  - Stage 1 effective concurrency is lower than current `200/200/200/10/32`
  - hash shortlist effective network pressure is lower than current `24 pages / 96 HTTP / 48 aux net`
  - output classification rows for the same small regression fixture remain unchanged

## Acceptance Criteria
- Running plain `python main_controller.py` on the current machine no longer uses the current high default networking behavior.
- RDAP 429 frequency drops materially on the same dataset because request pressure is reduced and retries are paced.
- The pipeline still completes with the same scoring formulas and the same classification decision code path.
- No changes are made to:
  - hash score weights
  - lexical thresholds
  - Stage 1 escalation thresholds unless the user explicitly passes those flags
  - failed-fetch routing logic
  - final label rules
- Windows run output remains valid:
  - `output_file.csv` still packages correctly
  - `output_file_filtered.csv` behavior remains unchanged
  - final labels are not redefined by this work

## Assumptions
- The user wants the RDAP problem solved operationally, not by changing how Stage 1 interprets RDAP-derived evidence.
- Registered-domain normalization for RDAP is intentionally excluded because it can change `rdap_age_days` and therefore Stage 1 outcomes.
- Windows Proactor `ResourceWarning` cleanup is a separate follow-up item and should not be bundled into this runtime/RDAP change.
