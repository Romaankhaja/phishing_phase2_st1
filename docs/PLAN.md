## Hybrid Typo-Squat Shortlisting With 3-Way Final Labels

### Summary
Rework the pipeline so typo-squat discovery is lexical-first and validation is evidence-first. The old shortlist logic becomes the candidate generator, the current hash/CLIP system becomes the validation layer, and the final output becomes truly 3-way: `Phishing`, `Suspected`, `Legitimate`.

This addresses the current failure mode visible in [output/holdout.csv](/c:/Users/SATWIK/Documents/Phishing/output/holdout.csv) and [output/output_file.csv](/c:/Users/SATWIK/Documents/Phishing/output/output_file.csv): screenshot similarity is dominating candidate selection, typo recall is weak, and `hash_only` cannot currently emit `Legitimate` at all.

### Key Changes
1. **Replace current typo candidate generation with a hybrid lexical shortlist**
- In [phishing_pipeline/comparison.py](/c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/comparison.py), stop using only the current single `typosquat_similarity()` top-k mask as the shortlist gate.
- Reuse the old shortlist ideas from [phishing_pipeline/shortlisting.py](/c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/shortlisting.py):
- NFKC normalization and homoglyph/leetspeak folding
- primary-domain extraction
- Jaro-Winkler thresholding
- token-set ratio thresholding
- Extend this into a new lexical score block per legitimate domain:
- `jw_primary`
- `token_set_primary`
- `skeleton_similarity`
- optional `host_similarity`
- Build a candidate mask from hybrid lexical rules instead of plain top-k:
- accept candidate entity if any lexical rule crosses its threshold
- always include exact brand-token containment matches
- still allow exact favicon/SSL/HTML/domain-hash hits to bypass lexical gating
- Keep multiple candidate CSEs for a URL until later scoring; do not collapse to one brand at shortlist time.

2. **Rearrange score flow so lexical similarity leads, visual/hash evidence validates**
- Change pipeline flow in `comparison.py` from:
- `typo top-k -> CPU/hash features -> CLIP dominates final score`
- to:
- `hybrid lexical shortlist -> CPU/hash/keyword/domain scoring -> CLIP as validation signal`
- Introduce explicit evidence groups in shortlist rows:
- lexical evidence
- visual evidence
- hash evidence
- infra evidence
- Rebalance weights so CLIP is not the main reason unrelated domains are shortlisted:
- lexical/domain family stronger than now
- screenshot materially reduced from current dominance
- keywords only counted when tied to the shortlisted CSE candidate
- exact hash matches stay high-confidence but not enough alone to force phishing without brand agreement
- Replace the current `top_k=10` typo gate with rule-based candidate admission plus a fallback `top_k` only when no lexical rule fires.
- Add per-row telemetry to `holdout.csv`:
- `lexical_score`
- `jw_primary`
- `token_set_primary`
- `skeleton_similarity`
- `candidate_generation_reason`
- `dominant_signal_family`

3. **Make final labeling truly 3-way**
- In [phishing_pipeline/pipeline.py](/c:/Users/SATWIK/Documents/Phishing/phishing_pipeline/pipeline.py), replace the current hash-only rule that effectively maps everything to `Phishing` or `Suspected`.
- Final label semantics:
- `Phishing`: shortlisted URL with very strong evidence only
- `Suspected`: shortlisted URL with meaningful lexical similarity to a CSE plus weak-to-medium supporting evidence
- `Legitimate`: shortlisted URL that fails CSE similarity validation or has only weak/non-brand-aligned evidence
- Use a strict phishing bar:
- require either multiple strong signal families, or one decisive brand-spoof signal plus suspicious infrastructure
- do not classify `High` score alone as phishing
- Reuse and adapt the existing `reclassify_label()` / trusted-vs-suspicious infra heuristics instead of maintaining separate classification logic.
- Keep output schema column name as `Phishing/Suspected Domains (i.e. Class Label)` for compatibility, but values become `Phishing`, `Suspected`, or `Legitimate`.

4. **Fix whitelist/CSE matching bias**
- Ensure scoring is tied to the best legitimate-domain candidate only after lexical candidate generation, not by letting CLIP choose a CSE from all entities.
- Add a downgrade rule:
- if lexical similarity to the selected CSE is below the candidate threshold, the row cannot be `Phishing` or `Suspected`; force `Legitimate`
- This is the key guard against unrelated pages visually matching generic layouts.

### Interface Changes
- `output/holdout.csv` gains lexical telemetry columns and a clear candidate-generation reason.
- `output/output_file.csv` retains the current schema but the class label column now legitimately supports `Legitimate`.
- CLI surface can stay mostly unchanged, but defaults should move from “hash-heavy shortlist” to “hybrid lexical shortlist + strict phishing validation”.
- Existing `legacy_ocr` mode can remain, but `hash_only` should be renamed internally in behavior to a hybrid lexical/hash path even if the CLI name is preserved for compatibility.

### Test Plan
1. Run the pipeline on the current holdout input and verify `holdout.csv` contains lexical telemetry and non-trivial lexical candidate reasons.
2. Validate that shortlisted rows are no longer overwhelmingly screenshot-only; report counts for lexical-only, visual-only, hash-only, and mixed evidence.
3. Confirm `output_file.csv` contains all three labels: `Phishing`, `Suspected`, `Legitimate`.
4. Manually inspect top 20 shortlisted rows:
- unrelated visually similar domains should downgrade to `Legitimate`
- typo-like domains with weak corroboration should become `Suspected`
- phishing should remain rare and require very strong evidence
5. Regression-check known old lexical positives from the prior shortlist logic and ensure they still enter the hybrid shortlist.
6. Confirm that rows with low lexical similarity cannot become `Phishing` purely from CLIP score.

### Assumptions
- `Legitimate` should be assigned only to shortlisted rows that are weakly evidenced and not sufficiently similar to a CSE domain, not to every raw input URL.
- `Phishing` must be rare and require very strong evidence.
- The old OCR-content-matching approach should not be restored as a primary driver; visual hashing/CLIP stays as validation, not as the first shortlist gate.
- Backward compatibility matters for output filenames and most CSV column names, but adding new shortlist telemetry columns is acceptable.
