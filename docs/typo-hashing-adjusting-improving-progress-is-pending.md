## Empty Output Root-Cause + Stagewise Debug/Repair Plan

### Summary
- Current run is empty because Stage 1 produced zero shortlisted rows, so downstream files stayed header-only.
- Measured from your artifacts:
1. `223` input URLs started (`output/hashing_shortlist.log`).
2. DNS gate accepted `171`, rejected `52` (`output/dns_gate_audit.csv`).
3. Of accepted URLs, `44` timed out in fetch and `127` were scored, but `0` crossed shortlist threshold `65` (`output/hashing_shortlist.log`).
4. Exclusion audit confirms all non-DNS accepted rows were grouped as `below_threshold_or_fetch_failed` (`output/hashing_shortlist_excluded_urls.csv`).
- For your injected typo set specifically, only `4/25` resolved; `21/25` were DNS-rejected. This matches your decision to keep DNS gate unchanged and drop DNS failures.

### Key Changes To Implement
- **Stage 1 shortlist logic (`phishing_pipeline/comparison.py`)**
1. Keep DNS gate behavior unchanged.
2. Split exclusion reason into two explicit reasons:
   - `fetch_timeout_or_fetch_failed`
   - `below_score_threshold`
3. Add a dual inclusion rule for holdout rows:
   - keep current rule: `best_score > hashing_threshold`
   - add lexical pass rule: `lexical_rule_hit=True` and `lexical_score >= 0.85` (even if hash score below threshold)
4. Add per-row scoring debug fields in holdout/excluded outputs:
   - `best_score`, `lexical_score`, `clip_similarity`, `domain_component`, `hash_component`, `whois_ready_flag`
- **Stage 2 classification (`phishing_pipeline/pipeline.py`)**
1. Process all holdout candidates (including lexical-pass rows).
2. Use WHOIS/RDAP as corroboration exactly as you requested:
   - `Phishing`: strong lexical + strong visual/hash + suspicious infra/registrant signals
   - `Suspected`: strong lexical + moderate hash/clip or WHOIS presence mismatch
   - `Legitimate`: weak lexical or no corroborating evidence
3. Keep phishing strict (rare), move borderline typo cases to suspected instead of dropping.
- **Output hygiene**
1. Clean stale submission folder before packaging so old evidence does not appear as current run output.
2. Keep final submission schema unchanged, but ensure rows reflect 3-way class values.

### Public Interface / Output Additions
- Add optional debug CLI switches in `main_controller.py`:
1. `--lexical-pass-min-score` (default `0.85`)
2. `--shortlist-debug-csv` (path for per-stage diagnostics)
3. `--stage-smoke-test` (`dns|fetch|lexical|score|classify|all`)
- Add new debug columns to holdout and excluded CSVs (no change to submission `.xlsx` column contract).

### Individual Stage Test Plan (Bug Isolation)
1. **Input + normalization stage**
   - Verify row count and normalized host extraction from `data/holdout_sets/urls.xlsx`.
   - Acceptance: all rows map to deterministic normalized URLs and hostnames.
2. **DNS gate stage**
   - Run DNS gate only, write audit, and compute status distribution.
   - Acceptance: exact accepted/rejected counts reproducible; rejected rows clearly explain `dns_error/no_records/resolver_error/timeout`.
3. **Fetch stage**
   - Run fetch/screenshot only for DNS-accepted URLs with timeout metrics.
   - Acceptance: timeout rate reported separately; no silent drops.
4. **Lexical stage**
   - Run lexical matcher only on fetched URLs and compare against known typo samples.
   - Acceptance: known typos (for resolvable domains) show high lexical scores and `lexical_rule_hit=True`.
5. **Scoring gate stage**
   - Run scorer without final threshold filtering and log component contributions.
   - Acceptance: each URL has explainable component-level score breakdown.
6. **Classification stage**
   - Run WHOIS/RDAP + final class rules on holdout.
   - Acceptance: phishing remains strict; typo-like rows with weaker corroboration become suspected, not dropped.
7. **Packaging stage**
   - Regenerate submission artifacts after clearing stale folder.
   - Acceptance: output reflects only current run rows and current evidence files.

### Assumptions / Defaults Locked
- DNS gateway remains unchanged.
- DNS-failed URLs are dropped from final output.
- WHOIS/RDAP is used as post-shortlist corroboration.
- Phishing remains high-precision; recall improvements target suspected capture, not phishing inflation.
