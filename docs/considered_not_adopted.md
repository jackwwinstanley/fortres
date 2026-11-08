# Considered, not adopted

Ideas we tested and decided **not** to use in the final model (v5, 20-seed LightGBM bag, frozen). They're here so
nobody re-tries them blind, and so judges can see we looked. LOW POWER throughout: 27 (2024) + 48 (2025) = 75 CVEs added
to CISA KEV in the two practice years. "Forward" = train 2024 → test 2025; "stability" = train 2025 → test 2024.
Reference: v5 bag 12 + 9 = 21; best simple rule (public exploit, then EPSS) 13 + 6 = 19 (`outputs/headline.json`).

## 1. Track-record priors (Person B, `src/b/priors.py`, `outputs/b_priors_eval.md`)
Time-safe extra columns: `knn_kev_rate` (share of the 50 most similar earlier CVEs, by Granite embedding, on KEV by the
cutoff) and `product_kev_count_max` / `product_kev_12m_max` (past-KEV counts for products named in the description).
Tested in the exact v5 setup, added as within-pool percentile ranks.

| variant | forward | stability | pooled bag | single seeds: mean (min–max) | vs v5, 90% paired bootstrap |
|---|---|---|---|---|---|
| v5 | 12 | 9 | 21 | 21.75 (17–25) | |
| v5 + knn | 14 | 9 | 23 | 20.95 (18–26) | +2 [−1, +5] |
| v5 + product | 12 | 9 | 21 | 21.15 (18–24) | +0 [0, 0] |
| v5 + both | 15 | 9 | 24 | 21.6 (17–24) | +3 [+1, +7] |

**Why not adopted:**
- Four variants were tried after the forward results were known.
- Single-seed means don't move (21.6 vs 21.75), so the bag gain may be seed luck, which the CVE-level bootstrap doesn't capture.
- `knn_kev_rate` drifts in 2026: it is non-zero for 57% of scoreboard CVEs vs about 41% in the practice years.
- The columns are **not** in `text_features.parquet`.

## 2. 50/50 blend of the v5 bag with the simple rule (Person B, `src/b/error_analysis.py`, `outputs/b_error_analysis.md`)
The average of the bag's within-pool percentile and the simple rule's within-pool percentile, weight fixed at 0.5.

| | v5 bag | blend | single-seed mean v5 → blend | blend − v5, 90% paired bootstrap |
|---|---|---|---|---|
| forward | 12 | 15 | 12.6 → 15.3 | [−1, +7] |
| stability | 9 | 9 | 9.15 → 8.45 | [−2, +2] |

**Why not adopted:** the idea came from reading the forward-test errors, so its forward gain is optimistic. The cleaner
check is the stability direction, which shows no gain. What we keep is the *finding*: the two rankings make opposite
mistakes. The rule catches high-EPSS flagged CVEs from vendors rarely on KEV; the model catches enterprise and edge
CVEs with KEV-like descriptions.

## 3. Two-channel allocation (Person A, `outputs/v2_report.md`)
Top *s* from the simple rule, the rest from a no-fit mix of four prior scores.

| variant | forward | stability | pooled |
|---|---|---|---|
| two-channel, s chosen on the other replica | 13 | 6 | 19 |
| two-channel, best pooled s (80% of k; optimistic) | 13 | 7 | 20 |

**Why not adopted:** no better than the simple rule when *s* is chosen honestly (19 vs 19). The best-*s* version is
chosen on the same data it's scored on.

## 4. Logistic regression on the v5 features (Person A, `outputs/v5_report.md`, `outputs/runlog.csv`)
| | forward | stability | pooled |
|---|---|---|---|
| v5 logistic regression | 14 | 11 | 25 |
| v5 LightGBM bag (final) | 12 | 9 | 21 |

**Why not adopted:**
- The pre-declared rule names the bag as the final model and the logistic regression as a robustness line only,
  decided before any test result.
- Switching after seeing 25 vs 21 would be choosing on test results.
- It's a single deterministic model with a wide interval (forward +1 [−5, +6]).
- Reported here so the comparison is visible, not hidden.

## 5. Granite fact extraction as model inputs (Person B, `src/b/extract.py`)
`outputs/extracted_features.parquet` (product type, login needed, network reachable, main impact) comes from a **small
local model and is noisy: the consistency guard corrected 21% of rows**. It stays **descriptive only**. Its CVE selection
is label-blind, but the extra labels on exploited practice CVEs (for the blind-spot profile, **small groups**) exist only in
the cache, and v5 was already frozen.
