# DNS-Gated Hashing Shortlist

## Summary
- The hashing shortlist no longer uses the removed URL prefilter module.
- `phishing_pipeline/dns_gate.py` is the only gate before Ray/Playwright hashing.
- Shortlist outputs stay unchanged: accepted matches still produce the same holdout rows.

## Current Flow
- Load candidate URLs from the holdout input.
- Run the DNS gate and write `output/dns_gate_audit.csv`.
- Send only DNS-resolving hostnames into the Ray hashing shortlist.
- Build the final holdout DataFrame from matches whose score is above the hashing threshold.

## Public Entry Points
- `run_hashing_shortlist_ray(url_list, threshold=65)`
- `run_hashing_shortlist(url_list, threshold=65)`
- `run_hashing_shortlist_async(url_list, threshold=65)`

## Runtime Notes
- Progress metrics report:
  - `processed`
  - `passed_dns_gate`
  - `hashed_success`
  - `fetch_failed`
  - `chunk_skipped`
  - `final_matches_above_threshold`
- Actor recovery replaces failed scraper actors and retries a failed chunk once before skipping it.
