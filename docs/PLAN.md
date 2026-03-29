# Pre-Hash URL Similarity Gate

## Summary
- Add a lightweight URL prefilter before the current Ray/Playwright/hash shortlist.
- Recommended method: normalized lexical URL similarity using character `n`-gram TF-IDF plus cosine similarity on hostname-first canonical strings.
- Decision rule: for each target URL, compute the best similarity score against all legitimate CSE URLs already used by hashing. If `best_score >= 10.0`, send it to the existing hashing shortlist; otherwise drop it before any screenshot/hash work.

## Implementation Changes
- Create a pure-function prefilter module, e.g. `phishing_pipeline/url_prefilter.py`.
- Build a cached legit index once from `entity_hash_db.json` so the prefilter uses the same CSE URL inventory as the hashing stage.
- Canonicalize each legit URL and target URL with the same pipeline:
  - lower-case, add scheme if missing, parse with `urlparse` + `tldextract`
  - drop `www`, ports, and pure TLD/generic tokens: `com`, `co`, `in`, `org`, `net`, `gov`
  - strip common phishing affixes from the start/end of host labels: `online`, `my`, `login`, `secure`, `auth`, `portal`, `corp`, `app`, `web`, `mail`, `pay`
  - keep 2-character labels only when they are the legit registered label, so brands like `vi` survive
  - if affix stripping empties the host, fall back to the longest non-TLD host label
- Build the canonical string as:
  - `brand_core brand_core host_tokens host_tokens path_tokens`
  - this makes the hostname dominate while still allowing path help when present
- Fit `TfidfVectorizer(analyzer="char", ngram_range=(2,5))` on all legit canonical strings and cache the sparse matrix.
- Score a target URL by transforming its canonical string and taking the maximum cosine similarity against the legit matrix; convert to percent with `score = cosine * 100`.
- If a target normalizes to no informative host signal, return `0` immediately.
- Integrate the gate at the top of `run_hashing_shortlist_ray` so rejected URLs never start Ray actors, browser pages, favicon fetches, screenshots, or CLIP/hash work.
- Keep the existing `holdout.csv` row format unchanged.
- Write an audit file `output/prefilter_audit.csv` with `target_url`, `best_entity`, `best_legit_domain`, `prefilter_score`, and `decision`.

## Interface Changes
- Extend the shortlist entrypoints with optional prefilter controls:
  - `run_hashing_shortlist_ray(url_list, threshold=65, prefilter_threshold=10.0, enable_prefilter=True)`
  - `run_hashing_shortlist(url_list, threshold=65, prefilter_threshold=10.0, enable_prefilter=True)`
  - `run_hashing_shortlist_async(url_list, threshold=65, prefilter_threshold=10.0, enable_prefilter=True)`
- Do not change downstream CSV columns or pipeline inputs.

## Test Plan
- Pass cases:
  - typosquats and affix variants such as `onlinesbi...`, `myvi...`, `airtel-secure...`
  - short-brand matches where the useful signal is only 2-3 characters
- Fail cases:
  - unrelated domains sharing only generic suffix/service text, such as `crumbsonline` vs `camsonline`
  - domains sharing only weak generic prefixes, such as `onlineslot...` vs `onlinesbi...`
  - empty/noisy inputs that normalize to no meaningful host signal
- Integration checks:
  - prefilter reduces candidate count before hashing
  - accepted URLs still produce the same post-hash output schema
  - `enable_prefilter=False` reproduces current behavior

## Assumptions
- The 10% rule applies to the single best legit-URL match for each target URL.
- Hostname similarity is primary; path only helps and never drives the match alone.
- The existing post-hash threshold of `65` stays as-is.
- The goal of this stage is high-recall pruning of obviously unrelated URLs, not final phishing classification.
