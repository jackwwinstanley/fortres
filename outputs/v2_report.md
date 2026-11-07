# v2 report: Granite text features, depth curves and two-channel allocation

> **LOW POWER.** 27 (2024) and 48 (2025) positives, 75 in total. All numbers are noisy; differences of a few hits are within noise. Nothing was tuned on a test replica. KEV history uses the fixed prior-December-31 cutoff; no 2026 KEV information is used.

## Rule for the final list (decided before running)

Final 2026 list = the two-channel allocation (top s CVEs of the exploit-then-EPSS order, rest from Channel B, a no-fit blend of four prior scores) with the highest pooled hits across both replicas; ties go to the larger s. If nothing beats the best baseline's pooled expected hits, the list still uses that rule (larger s on ties) and this report says so.

## Depth curves: where the hits come from (LOW POWER)

Cumulative tie-aware expected hits at list depths 10, 25, 50, 100, k/2, k, 1.5k and 2k (full table: `outputs/depth_curves.csv`; figure: `docs/figures/depth_curves.png`). v1 curves use predictions from the model trained on the other replica. Score-only rankings are not fitted.

all CVEs, replica 2024 (k = 198, 27 positives in the subset):

| ranking | 10 | 25 | 50 | 100 | k/2 | k | 1.5k | 2k |
|---|---|---|---|---|---|---|---|---|
| Exploit code, then EPSS (baseline) | 1.0 | 3.0 | 3.0 | 5.0 | 5.0 | 6.0 | 6.0 | 8.3 |
| v1 LightGBM | 3.0 | 4.0 | 4.0 | 5.0 | 5.0 | 6.0 | 7.0 | 8.0 |
| v1 logistic regression | 1.0 | 4.0 | 4.0 | 6.0 | 6.0 | 7.0 | 8.0 | 8.0 |
| kev_text_score | 0.0 | 0.0 | 0.0 | 2.0 | 2.0 | 2.0 | 3.0 | 4.0 |
| nearest_kev_sim | 0.0 | 1.1 | 2.0 | 3.0 | 3.0 | 3.0 | 4.0 | 4.0 |
| assigner_kev_rate_smooth | 0.0 | 0.7 | 1.0 | 1.0 | 1.0 | 1.6 | 3.1 | 3.6 |
| vendor_kev_count_max | 0.0 | 0.1 | 0.2 | 0.3 | 0.3 | 0.6 | 1.0 | 1.0 |

all CVEs, replica 2025 (k = 243, 48 positives in the subset):

| ranking | 10 | 25 | 50 | 100 | k/2 | k | 1.5k | 2k |
|---|---|---|---|---|---|---|---|---|
| Exploit code, then EPSS (baseline) | 2.0 | 2.0 | 4.0 | 8.0 | 8.0 | 13.0 | 16.0 | 17.2 |
| v1 LightGBM | 1.0 | 4.0 | 6.0 | 8.0 | 8.0 | 11.0 | 12.0 | 12.0 |
| v1 logistic regression | 4.0 | 7.0 | 8.0 | 8.0 | 8.0 | 9.0 | 12.0 | 17.0 |
| kev_text_score | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 2.0 | 3.0 | 6.0 |
| nearest_kev_sim | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | 2.0 | 6.0 | 6.0 |
| assigner_kev_rate_smooth | 0.9 | 1.3 | 1.8 | 3.2 | 3.5 | 5.3 | 7.1 | 8.9 |
| vendor_kev_count_max | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 1.6 |

blind-spot CVEs, replica 2024 (k = 198, 17 positives in the subset):

| ranking | 10 | 25 | 50 | 100 | k/2 | k | 1.5k | 2k |
|---|---|---|---|---|---|---|---|---|
| Exploit code, then EPSS (baseline) | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| v1 LightGBM | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| v1 logistic regression | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| kev_text_score | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | 1.0 | 2.0 | 3.0 |
| nearest_kev_sim | 0.0 | 0.7 | 1.0 | 2.0 | 2.0 | 2.0 | 3.0 | 3.0 |
| assigner_kev_rate_smooth | 0.0 | 0.7 | 1.0 | 1.0 | 1.0 | 1.7 | 3.1 | 3.5 |
| vendor_kev_count_max | 0.0 | 0.1 | 0.2 | 0.3 | 0.3 | 0.7 | 1.0 | 1.0 |

blind-spot CVEs, replica 2025 (k = 243, 27 positives in the subset):

| ranking | 10 | 25 | 50 | 100 | k/2 | k | 1.5k | 2k |
|---|---|---|---|---|---|---|---|---|
| Exploit code, then EPSS (baseline) | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| v1 LightGBM | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 2.0 | 2.0 | 2.0 |
| v1 logistic regression | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 4.8 | 6.0 | 7.0 |
| kev_text_score | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 2.0 | 4.0 |
| nearest_kev_sim | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 | 1.0 | 5.0 | 5.0 |
| assigner_kev_rate_smooth | 0.0 | 0.3 | 0.8 | 2.1 | 2.2 | 2.8 | 3.5 | 4.9 |
| vendor_kev_count_max | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1.0 | 1.0 |

Where the baseline stops adding hits (marginal hits per 25 slots, arbitrary tie order, whole pool): replica 2024: first window under 1 hit/25 slots ends at depth 50 (cumulative 3 hits); replica 2025: first window under 1 hit/25 slots ends at depth 125 (cumulative 8 hits).

## Models

### Model comparison: v1 vs v2 (+ Granite text features)

> **LOW POWER** (75 positives in total). Same selection rule and the same two directions as v1.

Text features added: `kev_text_score`, `nearest_kev_sim`, `txt_rce`, `txt_unauth`, `txt_auth_bypass`, `txt_cmd_injection`, `txt_deserialization`, `txt_path_traversal`, `txt_sqli`, `txt_priv_esc`, `txt_memory`, `txt_edge_device`, `txt_enterprise`, `txt_browser`, `txt_wordpress`, `txt_xss`.

Hyper-parameter selection and model choice (OOF AP on the training replica; within 10% -> logreg):

| features | training replica | OOF AP logreg | OOF AP LightGBM | gap | decision | LightGBM params |
|---|---|---|---|---|---|---|
| v1 | 2024 | 0.0170 | 0.0177 | 4% | **logreg** | {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 400, "reg_lambda": 1, "scale_pos_weight": 10} |
| v1 | 2025 | 0.0706 | 0.1202 | 41% | **lgbm** | {"num_leaves": 4, "min_child_samples": 30, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10} |
| v2 | 2024 | 0.0567 | 0.0298 | 47% | **logreg** | {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10} |
| v2 | 2025 | 0.0591 | 0.1019 | 42% | **lgbm** | {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10} |

Pooled over both directions (train 2024 -> test 2025 plus train 2025 -> test 2024). Best baseline: **Exploit code, then EPSS**. Intervals are 90% paired bootstraps (1000 resamples within each replica, seed 0, same resample for both rankings).

| ranking | pooled hits | pooled expected hits | diff vs Exploit code, then EPSS | diff vs same model on v1 |  |
|---|---|---|---|---|---|
| CVSS 3 first | 5 | 5.4 |  |  |  |
| EPSS first | 11 | 11.0 |  |  |  |
| Exploit code, then EPSS | 19 | 19.0 |  |  |  |
| **Logistic regression, v1** | 16 | 16.0 | -3 [-9, +3] |  |  |
| **LightGBM, v1** | 17 | 17.0 | -2 [-9, +3] |  |  |
| **Logistic regression, v2 (+text)** | 21 | 21.0 | +2 [-5, +9] | +5 [+0, +10] |  |
| **LightGBM, v2 (+text)** | 23 | 23.0 | +4 [-4, +10] | +6 [+0, +12] |  |

**train2024_test2025** (primary (forward in time)): test replica 2025, k = 243, 48 positives.

| ranking | hits | expected | 90% boot | tie group at cutoff | AP | diff vs Exploit code, then EPSS |
|---|---|---|---|---|---|---|
| CVSS 3 first | 5 | 5.12 | [1-9] | 3823 (45 slots) | 0.0063 | -8 [-15, -3] |
| EPSS first | 8 | 8.00 | [4-13] | 17 (14 slots) | 0.0322 | -5 [-9, -2] |
| Exploit code, then EPSS | 13 | 13.00 | [8-20] | 4 (3 slots) | 0.0480 |  |
| Logistic regression, v1 | 9 | 9.00 | [4-14] | 1 | 0.0942 | -4 [-10, +0] |
| LightGBM, v1 | 11 | 11.00 | [6-16] | 19 (3 slots) | 0.0369 | -2 [-9, +3] |
| Logistic regression, v2 (+text) | 13 | 13.00 | [7-19] | 1 | 0.0894 | +0 [-7, +5] |
| LightGBM, v2 (+text) | 15 | 15.00 | [9-21] | 1 | 0.0646 | +2 [-4, +7] |

**train2025_test2024** (stability check (NOT forward in time)): test replica 2024, k = 198, 27 positives.

| ranking | hits | expected | 90% boot | tie group at cutoff | AP | diff vs Exploit code, then EPSS |
|---|---|---|---|---|---|---|
| CVSS 3 first | 0 | 0.26 | [0-0] | 2943 (63 slots) | 0.0030 | -6 [-10, -2] |
| EPSS first | 3 | 3.00 | [1-6] | 3 (1 slots) | 0.0147 | -3 [-6, -1] |
| Exploit code, then EPSS | 6 | 6.00 | [2-10] | 19 (2 slots) | 0.0242 |  |
| Logistic regression, v1 | 7 | 7.00 | [3-12] | 6 (4 slots) | 0.0366 | +1 [-2, +5] |
| LightGBM, v1 | 6 | 6.00 | [2-10] | 1 | 0.0697 | +0 [-2, +3] |
| Logistic regression, v2 (+text) | 8 | 8.00 | [4-13] | 1 | 0.0534 | +2 [-1, +6] |
| LightGBM, v2 (+text) | 8 | 8.00 | [4-13] | 1 | 0.0740 | +2 [-2, +6] |

Does any model beat the best baseline in both directions? Logistic regression, v1: 1 of 2 directions; LightGBM, v1: 0 of 2 directions; Logistic regression, v2 (+text): 1 of 2 directions; LightGBM, v2 (+text): 2 of 2 directions.


## Two channels

### Two-channel allocation (no fitting)

> **LOW POWER** (75 positives). Channel A = exploit-then-EPSS order. Channel B = mean of within-pool percentile ranks of kev_text_score, assigner_kev_rate_smooth, vendor_kev_count_max, nearest_kev_sim. Allocation: top s of A, then B fills the remaining k - s, skipping CVEs already chosen. Hits are counted in arbitrary tie order (ties by cve_id).

Hits for every allocation on both replicas (s as a share of k; 100% = the baseline):

| s | 2024 (k=198) | 2025 (k=243) | pooled |
|---|---|---|---|
| 100% (198 / 243) | 6 | 13 | 19 |
| 90% (178 / 219) | 6 | 13 | 19 |
| 80% (158 / 194) | 7 | 13 | 20 |
| 70% (139 / 170) | 6 | 10 | 16 |
| 60% (119 / 146) | 6 | 8 | 14 |
| 50% (99 / 122) | 6 | 8 | 14 |

Headline (s chosen on one replica, reported on the other; ties go to the larger s):

| choose s on | chosen s | report on | hits there | baseline hits there |
|---|---|---|---|---|
| 2024 | 80% | 2025 | 13 | 13 |
| 2025 | 100% | 2024 | 6 | 6 |
| pooled |  |  | 19 | 19 |

Pooled-best s = **80%** of k (optimistic, chosen on the same data it is scored on). Final rule, decided before running: the 2026 list uses the allocation with the highest pooled hits across both replicas; ties go to the larger s.

Everything side by side, pooled over both replicas (test replica 2025 and 2024). Models are trained on the other replica. Interval = 90% paired bootstrap of the pooled difference vs the best baseline (1000 resamples within each replica, seed 0; for the allocations the ranking is held fixed in the resample):

| ranking | hits 2025 | hits 2024 | pooled hits | pooled expected | diff vs Exploit code, then EPSS |
|---|---|---|---|---|---|
| CVSS 3 first | 5 | 0 | 5 | 5.4 | -14 [-22, -8] |
| EPSS first | 8 | 3 | 11 | 11.0 | -8 [-13, -4] |
| Exploit code, then EPSS | 13 | 6 | 19 | 19.0 |  |
| Logistic regression, v1 | 9 | 7 | 16 | 16.0 | -3 [-9, +3] |
| LightGBM, v1 | 11 | 6 | 17 | 17.0 | -2 [-9, +3] |
| Logistic regression, v2 (+text) | 13 | 8 | 21 | 21.0 | +2 [-5, +9] |
| LightGBM, v2 (+text) | 15 | 8 | 23 | 23.0 | +4 [-4, +10] |
| B alone: kev_text_score | 2 | 2 | 4 | 4.0 | -15 [-24, -9] |
| B alone: assigner_kev_rate_smooth | 3 | 1 | 4 | 6.9 | -15 [-23, -7] |
| B alone: vendor_kev_count_max | 0 | 0 | 0 | 0.6 | -19 [-27, -13] |
| B alone: nearest_kev_sim | 2 | 3 | 5 | 5.0 | -14 [-22, -7] |
| B alone: mean of 4 percentile ranks | 5 | 1 | 6 | 6.0 | -13 [-22, -6] |
| Two-channel, s chosen on the other replica | 13 | 6 | 19 | 19.0 | +0 [-2, +0] |
| Two-channel, best pooled s (80% of k; optimistic) | 13 | 7 | 20 | 20.0 | +1 [-2, +2] |

Final list `outputs/top500_v2.csv`: allocation s = 400 from Channel A + 100 from Channel B on the 2026 scoreboard; 401 of 500 overlap with the baseline top 500.


## Blind spots

### Blind-spot profile (descriptive, not used for model design)

44 positives across both replicas have no public exploit flag and a within-month EPSS rank below the top-k EPSS cut. Vendor and days-to-KEV are post-snapshot facts shown for description only.

Top KEV vendors:

| KEV vendor | positives |
|---|---|
| Microsoft | 4 |
| Ivanti | 4 |
| Linux | 2 |
| Fortinet | 2 |
| SonicWall | 2 |
| PTZOptics | 2 |
| Advantive | 2 |
| Craft CMS | 2 |

Top assigners:

| assigner | positives |
|---|---|
| cve@mitre.org | 8 |
| disclosure@vulncheck.com | 5 |
| secure@microsoft.com | 4 |
| 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | 3 |
| psirt@fortinet.com | 2 |
| 416baaa9-dc9f-4396-8d5f-8c081fb06d67 | 2 |
| PSIRT@sonicwall.com | 2 |
| 3DS.Information-Security@3ds.com | 2 |

Days from the end of the snapshot month to KEV `date_added`: median 35, IQR 10 to 76 (min 2, max 223).

Share by snapshot month:

| replica | month | positives | share of replica's blind-spot positives |
|---|---|---|---|
| 2024 | 2024-01 | 1 | 6% |
| 2024 | 2024-02 | 2 | 12% |
| 2024 | 2024-03 | 1 | 6% |
| 2024 | 2024-04 | 1 | 6% |
| 2024 | 2024-05 | 3 | 18% |
| 2024 | 2024-06 | 3 | 18% |
| 2024 | 2024-07 | 1 | 6% |
| 2024 | 2024-08 | 3 | 18% |
| 2024 | 2024-09 | 2 | 12% |
| 2025 | 2025-01 | 6 | 22% |
| 2025 | 2025-02 | 3 | 11% |
| 2025 | 2025-03 | 5 | 19% |
| 2025 | 2025-04 | 2 | 7% |
| 2025 | 2025-05 | 3 | 11% |
| 2025 | 2025-06 | 2 | 7% |
| 2025 | 2025-07 | 1 | 4% |
| 2025 | 2025-08 | 4 | 15% |
| 2025 | 2025-09 | 1 | 4% |

Median prior scores of these positives vs the whole pool (descriptive):

| score | blind-spot positives (median) | all CVEs (median) |
|---|---|---|
| kev_text_score | 0.5232 | 0.1051 |
| assigner_kev_rate_smooth | 0.0119 | 0.0008 |
| vendor_kev_count_max | 0.0000 | 0.0000 |
| nearest_kev_sim | 0.7790 | 0.7432 |


## Plain verdict

- Best baseline (Exploit code, then EPSS): 13 hits on replica 2025 and 6 on 2024, 19.0 pooled expected hits.
- Logistic regression, v1: 9 (2025) and 7 (2024), pooled 16; diff vs baseline -3 [-9, +3]. More hits than the baseline in BOTH directions: **no**.
- LightGBM, v1: 11 (2025) and 6 (2024), pooled 17; diff vs baseline -2 [-9, +3]. More hits than the baseline in BOTH directions: **no**.
- Logistic regression, v2 (+text): 13 (2025) and 8 (2024), pooled 21; diff vs baseline +2 [-5, +9]. More hits than the baseline in BOTH directions: **no**.
- LightGBM, v2 (+text): 15 (2025) and 8 (2024), pooled 23; diff vs baseline +4 [-4, +10]. More hits than the baseline in BOTH directions: **yes**.
- Two-channel, s chosen on the other replica: 13 (2025) and 6 (2024), pooled 19; diff vs baseline +0 [-2, +0]. More hits than the baseline in BOTH directions: **no**.
- Two-channel, best pooled s (80% of k; optimistic): 13 (2025) and 7 (2024), pooled 20; diff vs baseline +1 [-2, +2]. More hits than the baseline in BOTH directions: **no**.

Intervals that include zero mean the gain is not distinguishable from noise with 75 positives. LightGBM with text features (v2) is the only ranking with more hits than the baseline in both directions, but its paired-bootstrap interval against the baseline still includes zero; the gain over the same model without text features has a lower bound of about zero. The two-channel allocation stays within one hit of the baseline. Channel B alone is far below the baseline, so the prior scores are a complement at best, not a replacement. The final list follows the pre-set rule (best pooled allocation, ties to larger s), not the v2 models, because the rule was fixed before the results; whether to switch to a v2 model is a separate decision for the team.
