## Empty Output Root-Cause + Stagewise Debug/Repair Plan

### Summary
- Current run is empty because Stage 1 produced zero shortlisted rows, so downstream files stayed header-only.
- Measured from your artifacts:
1. `223` input URLs started (`output/hashing_shortlist.log`).
2. Stage 0 lexical admission kept the candidate typo-like URLs for Stage 1 fetch and scoring.
3. Of routed URLs, `44` timed out in fetch and `127` were scored, but `0` crossed shortlist threshold `65` (`output/hashing_shortlist.log`).
4. Exclusion audit confirms all routed rows were grouped as `below_threshold_or_fetch_failed` (`output/hashing_shortlist_excluded_urls.csv`).
- For your injected typo set specifically, weak fetch or weak corroboration was the loss point; the shortlist no longer drops lexical hits behind a DNS prefilter.

### Key Changes To Implement
- **Stage 1 shortlist logic (`phishing_pipeline/comparison.py`)**
1. Route lexical candidates directly into fetch and shortlist scoring.
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
3. `--stage-smoke-test` (`fetch|lexical|score|classify|all`)
- Add new debug columns to holdout and excluded CSVs (no change to submission `.xlsx` column contract).

### Individual Stage Test Plan (Bug Isolation)
1. **Input + normalization stage**
   - Verify row count and normalized host extraction from `data/holdout_sets/urls.xlsx`.
   - Acceptance: all rows map to deterministic normalized URLs and hostnames.
2. **Fetch stage**
   - Run fetch/screenshot for routed lexical candidates with timeout metrics.
   - Acceptance: timeout rate reported separately; no silent drops.
3. **Lexical stage**
   - Run lexical matcher only on fetched URLs and compare against known typo samples.
   - Acceptance: known typos (for resolvable domains) show high lexical scores and `lexical_rule_hit=True`.
4. **Scoring gate stage**
   - Run scorer without final threshold filtering and log component contributions.
   - Acceptance: each URL has explainable component-level score breakdown.
5. **Classification stage**
   - Run WHOIS/RDAP + final class rules on holdout.
   - Acceptance: phishing remains strict; typo-like rows with weaker corroboration become suspected, not dropped.
6. **Packaging stage**
   - Regenerate submission artifacts after clearing stale folder.
   - Acceptance: output reflects only current run rows and current evidence files.

### Assumptions / Defaults Locked
- Lexical candidates are no longer dropped by a Stage 1 hostname prefilter.
- DNS evidence remains enrichment-only rather than a prefilter.
- WHOIS/RDAP is used as post-shortlist corroboration.
- Phishing remains high-precision; recall improvements target suspected capture, not phishing inflation.
