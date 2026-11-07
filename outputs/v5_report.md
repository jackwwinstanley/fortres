# v5 report: drift treatment fixed by PSI, 20-seed bag

> **LOW POWER.** 27 (2024) and 48 (2025) positives. **The forward direction (train 2024 -> test 2025) is reported first; train 2025 -> test 2024 is a stability check, not forward in time.** Headline numbers are the 20-seed bag or multi-seed means; earlier versions are superseded.

## Decision record (declared before the numbers)

- Step 3d replaced scale features by within-pool percentile ranks and, for tie-heavy features, **raised** PSI (days_to_cutoff 1.03 -> 2.33, assigner_kev_count 1.17 -> 2.66, assigner_kev_12m 0.78 -> 2.77).
- **This is the last feature-set change. v5 becomes the final model and the primary list regardless of its hits** (it replaces v4; v5 minus v4 is reported honestly below).
- Rule, decided before running and based on drift only: for each of days_to_cutoff, assigner_prior_cves, assigner_kev_count, assigner_kev_12m, assigner_kev_rate_smooth, vendor_kev_count_max and vendor_kev_12m_max choose among (a) raw, (b) within-pool percentile rank, (c) a scale-free share (share of all CVEs published / all KEV entries added by the history cutoff, or in the 12 months before it; vendor equivalents analogously, zero denominators guarded) the transformation with the **lowest PSI** between the pooled replicas and the 2026 scoreboard; ties go to raw. Raw epss stays removed; epss_rank_in_month and epss_missing are unchanged.

## Headline

**Forward direction (train 2024 -> test 2025):** the v5 20-seed bag found **12** exploited CVEs in the top 243 against the baseline's **13** (-1; 90% interval [-6, +3] CVE-level, [-7, +4] event-clustered).

**Pooled over both directions:** 21 vs 19 (+2; [-4, +8] CVE-level, [-4, +8] event-clustered). Stability check (train 2025 -> test 2024): 9 vs 6 (+3; [+0, +7] / [+0, +7]). Single seeds average 21.8 pooled hits (min 17, max 25, 20 seeds).

## PSI of every candidate transformation (pooled replicas vs 2026 scoreboard)

Spike-aware PSI with 10 bins from the replicas (`src/features/drift_fix.py`); ranks are computed within each pool; > 0.25 is a large shift.

| feature | transform | column | PSI | chosen |
|---|---|---|---|---|
| days_to_cutoff | raw | days_to_cutoff | 1.028 | **yes** |
| days_to_cutoff | rank | days_to_cutoff_pctrank | 2.333 |  |
| assigner_prior_cves | raw | assigner_prior_cves | 1.886 |  |
| assigner_prior_cves | rank | assigner_prior_cves_pctrank | 0.855 | **yes** |
| assigner_prior_cves | share | assigner_cve_share | 2.343 |  |
| assigner_kev_count | raw | assigner_kev_count | 1.172 |  |
| assigner_kev_count | rank | assigner_kev_count_pctrank | 2.658 |  |
| assigner_kev_count | share | assigner_kev_share | 0.658 | **yes** |
| assigner_kev_12m | raw | assigner_kev_12m | 0.779 |  |
| assigner_kev_12m | rank | assigner_kev_12m_pctrank | 2.767 |  |
| assigner_kev_12m | share | assigner_kev_12m_share | 0.390 | **yes** |
| assigner_kev_rate_smooth | raw | assigner_kev_rate_smooth | 0.739 |  |
| assigner_kev_rate_smooth | rank | assigner_kev_rate_smooth_pctrank | 0.446 | **yes** |
| vendor_kev_count_max | raw | vendor_kev_count_max | 0.094 | **yes** |
| vendor_kev_count_max | rank | vendor_kev_count_max_pctrank | 4.034 |  |
| vendor_kev_count_max | share | vendor_kev_share_max | 0.423 |  |
| vendor_kev_12m_max | raw | vendor_kev_12m_max | 0.234 | **yes** |
| vendor_kev_12m_max | rank | vendor_kev_12m_max_pctrank | 4.698 |  |
| vendor_kev_12m_max | share | vendor_kev_12m_share_max | 0.287 |  |

### PSI of every final feature

| feature | PSI |  |
|---|---|---|
| epss_missing | 0.075 |  |
| epss_rank_in_month | 0.145 |  |
| exploitdb | 0.001 |  |
| metasploit | 0.000 |  |
| nuclei | 0.000 |  |
| poc_github | 0.000 |  |
| n_flags | 0.000 |  |
| any_exploit | 0.000 |  |
| days_to_snapshot | 0.048 |  |
| days_to_cutoff | 1.028 | **above 0.25** |
| assigner_prior_cves_pctrank | 0.855 | **above 0.25** |
| assigner_kev_share | 0.658 | **above 0.25** |
| assigner_kev_12m_share | 0.390 | **above 0.25** |
| assigner_kev_rate_smooth_pctrank | 0.446 | **above 0.25** |
| n_vendors_mentioned | 0.006 |  |
| vendor_kev_count_max | 0.094 |  |
| vendor_kev_12m_max | 0.234 |  |
| kev_text_score | 0.156 |  |
| nearest_kev_sim | 0.100 |  |
| txt_rce | 0.003 |  |
| txt_unauth | 0.056 |  |
| txt_auth_bypass | 0.000 |  |
| txt_cmd_injection | 0.000 |  |
| txt_deserialization | 0.000 |  |
| txt_path_traversal | 0.001 |  |
| txt_sqli | 0.020 |  |
| txt_priv_esc | 0.001 |  |
| txt_memory | 0.003 |  |
| txt_edge_device | 0.001 |  |
| txt_enterprise | 0.003 |  |
| txt_browser | 0.051 |  |
| txt_wordpress | 0.013 |  |
| txt_xss | 0.095 |  |

Final features above 0.25 and why:

- `days_to_cutoff` (1.03): a pure function of the snapshot month (days from month end to Nov 4); the 2026 scoreboard has most of its CVEs in July to September, so its month mix differs from the replicas by construction.
- `assigner_prior_cves_pctrank` (0.85): assigner history is measured to a later cutoff (2025-12-31 vs 2023-12-31 and 2024-12-31) and the 2026 pool has a different assigner mix, so counts, shares and ranks of history differ by construction (see the assigner-mix table).
- `assigner_kev_share` (0.66): assigner history is measured to a later cutoff (2025-12-31 vs 2023-12-31 and 2024-12-31) and the 2026 pool has a different assigner mix, so counts, shares and ranks of history differ by construction (see the assigner-mix table).
- `assigner_kev_12m_share` (0.39): assigner history is measured to a later cutoff (2025-12-31 vs 2023-12-31 and 2024-12-31) and the 2026 pool has a different assigner mix, so counts, shares and ranks of history differ by construction (see the assigner-mix table).
- `assigner_kev_rate_smooth_pctrank` (0.45): assigner history is measured to a later cutoff (2025-12-31 vs 2023-12-31 and 2024-12-31) and the 2026 pool has a different assigner mix, so counts, shares and ranks of history differ by construction (see the assigner-mix table).

No text-flag feature is above 0.25 (the largest `txt_` PSI is 0.095), so there is no categorical content shift to explain; `epss_rank_in_month` is 0.145 and `epss_missing` 0.075. The remaining shift is concentrated in the assigner-history features and `days_to_cutoff`, which the rule could not reduce further. The 2026 pool's assigner mix:

| pool | distinct assigners | share of CVEs from the 5 busiest assigners | assigner has zero history |
|---|---|---|---|
| replica 2024 | 277 | 52.1% | 12.3% |
| replica 2025 | 338 | 57.5% | 0.8% |
| 2026 scoreboard | 382 | 47.1% | 1.2% |

The rule was applied as written; no further adjustment was made after seeing these numbers or any hits.

## Hyper-parameters (same pre-set rule: pooled OOF AP on the training replica)

| training replica | pooled OOF AP (LightGBM) | chosen parameters |
|---|---|---|
| 2024 | 0.0258 | `{"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10}` |
| 2025 | 0.0969 | `{"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10}` |

## Results

### Forward direction: train 2024 -> test 2025 (forward in time), test 2025, k = 243

| ranking | hits in top k | diff vs baseline (90% CVE-level / event-clustered) |
|---|---|---|
| Exploit code, then EPSS (baseline) | 13 |  |
| **v5 20-seed bag** | **12** | -1  [-6, +3] / [-7, +4] |
| v5 single seeds 0-19, mean | 12.6 | -0.4 |
| v4 20-seed bag (superseded) | 12 | -1 |
| v5 minus v4 (bags) | +0 | [-4, +0] / [-3, +0] |
| v5 logistic regression (robustness only, not for selection) | 14 | +1  [-5, +6] / [-6, +8] |

### Stability check: train 2025 -> test 2024 (stability check, NOT forward in time), test 2024, k = 198

| ranking | hits in top k | diff vs baseline (90% CVE-level / event-clustered) |
|---|---|---|
| Exploit code, then EPSS (baseline) | 6 |  |
| **v5 20-seed bag** | **9** | +3  [+0, +7] / [+0, +7] |
| v5 single seeds 0-19, mean | 9.2 | +3.2 |
| v4 20-seed bag (superseded) | 9 | +3 |
| v5 minus v4 (bags) | +0 | [-3, +3] / [-3, +2] |
| v5 logistic regression (robustness only, not for selection) | 11 | +5  [+1, +9] / [+1, +9] |

### Pooled over both directions

| ranking | pooled hits | diff vs baseline (90% CVE-level / event-clustered) |
|---|---|---|
| baseline | 19 |  |
| **v5 20-seed bag** | **21** | +2  [-4, +8] / [-4, +8] |
| v5 single seeds, mean / min / max | 21.8 / 17 / 25 |  |
| v4 20-seed bag (superseded) | 21 | +2 |
| v5 minus v4 (bags) | +0 | [-5, +2] / [-5, +2] |
| v5 logistic regression (robustness only) | 25 | +6 |

Hits are counted in the top k of each replica (ties by score, epss_rank_in_month, cve_id). The event-clustered bootstrap treats positives added to KEV by the same vendor on the same date as one event.

## Placebo, like-for-like

30 real 5-seed bags (disjoint seeds, v5 features) against 30 within-month shuffles of the 16 text columns, each trained as a 5-seed bag; pooled hits over both directions.

| distribution | mean | sd | min | median | 95th pct | max |
|---|---|---|---|---|---|---|
| real bags | 22.33 | 1.73 | 20 | 22 | 25 | 26 |
| shuffled-text bags | 19.90 | 1.86 | 13 | 20 | 22 | 22 |

Difference in means (real minus shuffled): **+2.43** hits, 90% bootstrap interval [+1.70, +3.20] (10,000 resamples of each group); one-sided bootstrap p-value (share of resampled differences <= 0) = **< 0.001**. Counts of pooled hits, real: 20: 5, 21: 7, 22: 3, 23: 8, 24: 3, 25: 3, 26: 1; shuffled: 13: 1, 17: 2, 18: 1, 19: 5, 20: 8, 21: 9, 22: 4.

## Leakage audit (same pre-declared rules, v5 feature list)

| check | result | flagged |
|---|---|---|
| feature names pass the allowed/banned guard | OK | no |
| description scan: post-attack phrases left after stripping (must be 0) | positives 0.0% vs negatives 0.00% | no |
| description scan: ransomware | positives 0.0% vs negatives 0.02% | no |
| description scan: botnet | positives 0.0% vs negatives 0.01% | no |
| description scan: threat actor | positives 0.0% vs negatives 0.12% | no |
| description scan: in the wild | positives 1.3% vs negatives 0.02% | no |
| description scan: CISA / KEV / known exploited | positives 0.0% vs negatives 0.01% | no |
| description scan: exploitation wording (mass/active/ongoing exploitation, widely exploited) | positives 0.0% vs negatives 0.30% | no |
| univariate AUC of every text feature within [0.05, 0.95] on both replicas | yes | no |

Limit: the Granite embeddings are not available locally, so `kev_text_score` and `nearest_kev_sim` were not recomputed; their time-safety rests on Person B's code. All history features, including the new shares, use KEV rows and CVEs dated on or before December 31 of the year before the pool.

## Final list: `outputs/top500_v5.csv`

| item | value |
|---|---|
| model | 20-seed LightGBM bag on both replicas, v5 features, parameters from the pooled-AP selection |
| parameters | `{"num_leaves": 4, "min_child_samples": 30, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 1}` |
| pooled OOF AP of the selection | 0.0583 |
| ranking rule | bag score, then epss_rank_in_month, then cve_id |
| overlap with top500_v4 | 479 |
| overlap with top500_v3 | 409 |
| overlap with the baseline top 500 | 190 |
| CVEs with an exploit flag: v5 list vs baseline list | 431 vs 500 |
| status | **primary list; replaces v4 regardless of hits** |
| contributions | `outputs/v5_top500_contrib.parquet` (LightGBM pred_contrib averaged over the 20 seeds, one column per feature) |

## How strong is the evidence?

**WEAK.** The forward direction shows 12 vs 13 (-1, event-clustered [-7, +4]); pooled it is 21 vs 19 (+2, event-clustered [-4, +8]). Single seeds range 17-25 pooled hits. v5 minus v4 is +0 pooled hits (event-clustered [-5, +2]), i.e. the drift-treatment change did not hurt in this sample. The like-for-like placebo gap is +2.43 hits (p < 0.001). With 75 positives from a few dozen KEV events, any gain over the baseline is uncertain, and the remaining PSI in the assigner-history features means the replicas are an imperfect guide to 2026.
