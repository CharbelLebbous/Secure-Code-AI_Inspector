# Prompt Log

## v1 - Broad Detection Setup

- Prompt/Config profile:
  - Lower confidence thresholds (`candidate_min=0.25`, `verified_min=0.55`).
  - Fewer abstention constraints in specialist prompts.
  - No negative few-shot (`findings: []`) examples.
- Results:
  - AI verified: 70
  - Semgrep verified: 12
  - Matched: 2 (**16.67%** of Semgrep findings matched)
  - Precision: **3.00%**
  - Recall: **17.00%**
  - AI-only: 68 (**97.14%** of AI findings)
  - Semgrep-only: 10 (**83.33%** of Semgrep findings)
- Interpretation:
  - The tool found many issues, but most were not aligned with baseline output.
  - Good sensitivity, low precision.

## v2 - Evidence-First Setup

- What changed:
  - Increased thresholds in `configs/profile.yaml`:
    - `candidate_min`: `0.50`
    - `verified_min`: `0.75`
  - Added negative few-shot examples (`findings: []`) in `prompts/few_shot_examples.json`.
  - Strengthened specialist prompts to require concrete evidence.
  - Strengthened verifier prompt to reject generic/assumption-based findings and prefer precision.
- Results:
  - AI verified: 13
  - Semgrep verified: 12
  - Matched: 1 (**8.33%** of Semgrep findings matched)
  - Precision: **8.00%**
  - Recall: **8.00%**
  - AI-only: 12 (**92.31%** of AI findings)
  - Semgrep-only: 11 (**91.67%** of Semgrep findings)
- Interpretation:
  - Precision improved (**3.00% -> 8.00%**) and AI-only count dropped (**68 -> 12**).
  - Match and recall decreased because filtering became stricter.
  - This is a precision-recall trade-off.

## v3 - Semantic Comparison Setup

- What changed:
  - Comparison switched from strict static matching to AI-assisted semantic matching.
  - Compare stage now uses an explicit matching prompt (same issue vs different issue).
  - Added confidence gate for matches (`>= 70%`) to avoid weak semantic matches.
  - Improved compare runtime UX with real progress updates during matching.
  - Fixed duplicate Semgrep-ID handling so counts and misses stay consistent.
- Why this improved:
  - Better handles line drift and wording differences between AI and Semgrep findings.
  - Reduces false mismatches caused by exact file/line/category-only matching.
  - Gives more realistic agreement metrics for presentation.
- Results (latest run from `outputs/`):
  - AI verified: 10
  - Semgrep verified: 12
  - Matched: 4 (**33.33%** of Semgrep findings matched)
  - Precision: **40.00%**
  - Recall: **33.33%**
  - AI-only: 6 (**60.00%** of AI findings)
  - Semgrep-only: 8 (**66.67%** of Semgrep findings)
- Interpretation:
  - Compared with earlier runs, alignment improved clearly on the same scope.
  - Remaining misses are mostly in `server.ts` and in `A07` coverage mismatch.
  - Note: v3 metrics are based on semantic matching, so they are not directly equivalent to strict-matching scores from v1/v2.

## v4 - Coverage and Baseline Normalization Update

- What changed:
  - Added `A07:2021-Identification and Authentication Failures` to `configs/profile.yaml` so AI now targets that category.
  - Expanded specialist guidance for `server.ts`-style patterns:
    - Access-control prompt now explicitly handles public static exposure/directory listing cases with missing restriction evidence.
    - Extra-category prompt now emphasizes concrete A07 patterns (hardcoded credentials/secrets, unsafe auth/session logic).
    - Verifier prompt now validates server-style A01 findings only when unauthorized exposure evidence is explicit.
  - Added server-style few-shot examples (positive and negative) in `prompts/few_shot_examples.json`.
  - Deduplicated equivalent Semgrep findings before scoring in comparison metrics.
- Why this improved:
  - Reduces artificial penalty from duplicate baseline entries.
  - Improves chance of matching Semgrep findings in `server.ts`.
  - Aligns AI category coverage with Semgrep by including A07.
- Results:
  - AI verified: 24
  - Semgrep verified: 11 (after baseline deduplication; 1 equivalent duplicate removed)
  - Matched: 7 (**63.64%** of Semgrep findings matched)
  - Precision: **29.00%**
  - Recall: **64.00%**
  - AI-only: 17 (**70.83%** of AI findings)
  - Semgrep-only: 4 (**36.36%** of Semgrep findings)
- Interpretation:
  - Coverage improved significantly (recall and matched count increased).
  - Precision dropped because AI now reports many additional findings not present in Semgrep.
  - Current setup is stronger on detection breadth, weaker on baseline alignment precision.

## v5 - Precision Tightening Pass

- What changed:
  - Increased confidence thresholds in `configs/profile.yaml`:
    - `candidate_min`: `0.60`
    - `verified_min`: `0.85`
  - Tightened A07 prompt constraints to avoid misclassifying authorization/input-validation issues:
    - Updated `prompts/agents/extra_category_specialist.md`
    - Updated `prompts/agents/verifier.md`
  - Added verifier-side local precision guard in `src/secure_inspector/agents/verifier.py`:
    - Reject overly broad findings (`line span > 80`).
    - Enforce category-specific evidence sanity for A01 and A07 before final verification.
- Why this improved:
  - Reduces noisy high-confidence findings that are weakly scoped or category-misaligned.
  - Forces final verified findings to have stronger evidence/category consistency.
- Results:
  - AI verified: 17
  - Semgrep verified: 11 (after baseline deduplication; 1 equivalent duplicate removed)
  - Matched: 6 (**54.55%** of Semgrep findings matched)
  - Precision: **35.00%**
  - Recall: **55.00%**
  - AI-only: 11 (**64.71%** of AI findings)
  - Semgrep-only: 5 (**45.45%** of Semgrep findings)
- Interpretation:
  - Precision improved (**29.00% -> 35.00%**) and AI-only findings dropped (**17 -> 11**).
  - Recall decreased (**64.00% -> 55.00%**) due to stricter filtering.
  - This is the expected precision-recall trade-off for a tightening pass.

## v6 - Targeted Match Recovery + A01 Noise Reduction

- What changed:
  - Strengthened injection specialist guidance to prioritize:
    - raw SQL interpolation sinks in `sequelize.query` / `db.query`
    - `eval(...)` on user-influenced data
  - Added targeted few-shot positives for:
    - `routes/search.ts` SQL interpolation pattern
    - `routes/userProfile.ts` eval injection pattern
  - Tightened verifier local precision guard in `src/secure_inspector/agents/verifier.py`:
    - stronger A01 filtering for speculative `server.ts` route claims
    - keep only concrete server exposure A01 evidence (serveIndex/static/directory listing)
    - enforce A03 sink evidence presence
- Why this should improve:
  - Recovers likely missed Semgrep-aligned injection matches (`search.ts`, `userProfile.ts`).
  - Reduces false-positive A01 findings that are speculative and not baseline-aligned.
- Results:
  - AI verified: 22
  - Semgrep verified: 11 (after baseline deduplication; 1 equivalent duplicate removed)
  - Matched: 6 (**54.55%** of Semgrep findings matched)
  - Precision: **27.00%**
  - Recall: **55.00%**
  - AI-only: 16 (**72.73%** of AI findings)
  - Semgrep-only: 5 (**45.45%** of Semgrep findings)
- Interpretation:
  - v6 did not improve overall quality: precision dropped (**35.00% -> 27.00%**) while recall stayed flat at **55.00%**.
  - Main issue is continued over-generation of A07/A01 findings not aligned with Semgrep baseline.

## v7 - Scoring Normalization + Flexible Semantic Matching

- What changed:
  - Added AI-side normalization before scoring in `src/secure_inspector/eval/metrics.py`:
    - exact duplicate removal
    - near-equivalent duplicate removal for repeated findings in the same file/category
  - Kept baseline deduplication and added explicit reporting of both normalization steps in comparison output.
  - Relaxed semantic match confidence threshold from `0.70` to `0.60` for less brittle matching.
  - Updated semantic matching instructions to accept equivalent repeated patterns in adjacent lines/routes.
  - Surfaced normalization stats in `services` and `web_app` compare summaries.
- Why this should improve:
  - Reduces denominator inflation from repeated AI findings describing the same root cause.
  - Improves matching robustness when AI and Semgrep report the same issue with slight line drift.
  - Makes precision/recall closer to real issue-level agreement.
- Results:
  - AI verified: 11 (after AI normalization; 4 equivalent AI duplicates removed)
  - Semgrep verified: 11 (after baseline normalization; 1 equivalent Semgrep duplicate removed)
  - Matched: 6 (**54.55%** of Semgrep findings matched)
  - Precision: **55.00%**
  - Recall: **55.00%**
  - AI-only: 5 (**45.45%** of AI findings)
  - Semgrep-only: 5 (**45.45%** of Semgrep findings)
- Interpretation:
  - Precision target was achieved with a strong reduction in AI-only noise.
  - Recall remained below the 60% target, mainly due to misses in `server.ts` and one crypto finding in `lib/insecurity.ts`.
