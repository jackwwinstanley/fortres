# Considered, not adopted

Ideas we tested and decided **not** to use in the final model (v6: a 20-seed LightGBM bag on the v5 features with
regularised settings). They're here so nobody re-tries them blind, and so judges can see we looked. LOW POWER throughout:
27 (2024) + 48 (2025) = 75 CVEs added to CISA KEV in the two practice years. "Forward" = train 2024 → test 2025;
"stability" = train 2025 → test 2024. Reference: v6 bag 18 + 9 = 27, best simple rule (public exploit, then EPSS)
13 + 6 = 19 (`outputs/headline.json`); sections 1-5 were measured against the previous model, v5 (12 + 9 = 21).

## 0. The previous model, v5, and how v6 replaced it
v5 (`outputs/top500_v5.csv`, `outputs/v5_report.md`, `headline.json` → `previous`) was the headline model until 2026-11-08.
v6 was chosen from seven declared variants by a rule fixed before any result (`outputs/rank_report.md`):
forward ≥ v5, stability ≥ v5, and a pooled gain of at least 2 and at least the noise floor of 4 (the spread of v5's own
pooled hits over three new seed sets, 21 to 25). Ties go to the earliest of H, I, F, D, E, J, K.

| variant (20-seed bag, settings by CV inside the training year) | forward | stability | pooled | result |
|---|---|---|---|---|
| v5 (previous) | 12 | 9 | 21 | reference |
| H monotone in EPSS rank and the four exploit flags only | 13 | 9 | 22 | gain below 4 |
| **I regularised (became v6)** | **18** | **9** | **27** | **qualified** |
| F positive weighting (scale_pos_weight by CV) | 14 | 9 | 23 | gain below 4 |
| D lambdarank (one query per month; one per pool exceeds LightGBM's 10,000-row limit) | 13 | 9 | 22 | gain below 4 |
| E rank_xendcg | 4 | 7 | 11 | worse |
| J rank-average of v5, D, F and H | 12 | 9 | 21 | no gain |
| K XGBoost rank:ndcg | | | | skipped (not installed) |

Outside data, tested separately (`outputs/outside_report.md`, `outputs/outside2_report.md` on branches b/outside and
b/outside2): VulnCheck KEV was rejected because its dates are hindsight; CISA Vulnrichment flags 1 practice CVE and none
in 2026; GitHub PoC creation dates plus the monthly EPSS change scored 18 instead of 21 for v5. None was adopted.
Caveats on v6 itself: on matched seeds it beats v5 by only +2 to +5 (`outputs/v6_seed_spread.csv`), and a vendor-grouped
diagnostic on v5 halves its 2025 in-year hits (19 → 10, `outputs/rank_vendor_cv.csv`).

## 0b. Eleven more methods tested against v6 (the "method zoo", branch b/zoo)
Every method ran through one evaluation harness, frozen in its own commit before any method ran, on the frozen v5
features ([summary](https://github.com/jackwwinstanley/ibm-breach/blob/b/zoo/outputs/zoo_summary.md)). The screening rule was fixed before any result: at least v6's forward and stability, and a
pooled gain of at least 2 (v6's own spread over four seed sets is 2). Each method was tried standalone, blended with v6,
and, where it makes a feature, as an extra v6 feature. Best variant of each, forward / stability / pooled, against v6's
18 / 9 / 27:

| method | best variant | forward / stability / pooled | result |
|---|---|---|---|
| m01 elastic-net logistic regression | blend with v6 | 18 / 9 / 27 | no gain |
| m02 CWE empirical-Bayes rate | extra feature | 16 / 9 / 25 | worse |
| m03 Cox survival model | blend with v6 | 18 / 9 / 27 | no gain |
| m06 seed-bag mean minus spread | standalone | 18 / 9 / 27 | no gain |
| m07 extra trees | blend with v6 | 15 / 10 / 25 | worse forward |
| m08 isolation-forest anomaly score | blend with v6 | 16 / 8 / 24 | worse |
| m09 KEV prototypes | extra feature | 18 / 8 / 26 | worse stability |
| m11 regex exploit/PoC words | extra feature | 18 / 10 / 28 | +1, below the bar of 2 |
| m12 TF-IDF logistic regression | extra feature | 18 / 9 / 27 | no gain |
| m18 balanced bagging | blend with v6 | 7 / 3 / 10 | much worse |
| m19 adversarial "looks like 2026" score | extra feature | 18 / 9 / 27 | no gain |

No method passed screening, so nothing was confirmed or adopted, and v6 stays.

m11's +1 got a separate consistency check, with rules written down before any new result and the bar admittedly set after
seeing the +1 ([check](https://github.com/jackwwinstanley/ibm-breach/blob/b/zoo/outputs/zoo/m11_consistency.md)). Across 10 seed sets, 6 of them fresh, the mean gain is +0.1 (90% interval −0.1 to +0.4). It
falls below v6 on 3 sets, and 4 of 5 shuffled-feature placebos gain the same +1. So it is luck, not signal.

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
