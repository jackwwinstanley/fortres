# v1 report: allowed features, logistic regression and LightGBM

> **LOW POWER.** The replicas have 27 (2024) and 48 (2025) positives, 75 in total. Every number below is noisy; intervals are wide and small differences mean little.

## History-cutoff rule

KEV-based history features use a fixed cutoff of December 31 of the year before the pool year: replica 2024 uses KEV rows added on or before 2023-12-31, replica 2025 on or before 2024-12-31, and the 2026 scoreboard on or before 2025-12-31. No 2026 KEV information is used anywhere.

## Features (allowed columns only)

| group | columns |
|---|---|
| signals | epss, epss_missing, epss_rank_in_month |
| flags | exploitdb, metasploit, nuclei, poc_github, n_flags, any_exploit |
| timing | days_to_snapshot, days_to_cutoff |
| assigner | assigner_prior_cves, assigner_kev_count, assigner_kev_12m, assigner_kev_rate_smooth |
| vendor | n_vendors_mentioned, vendor_kev_count_max, vendor_kev_12m_max |

Monotone +1 constraints (LightGBM): epss, epss_rank_in_month, exploitdb, metasploit, nuclei, poc_github, n_flags, any_exploit. No CVSS, nvd_status, n_affected_cpes, n_references, references, affected_products or cwe_ids are model inputs. CVSS is joined only to score the CVSS baseline.

## Hyper-parameter selection and model choice

Rule (fixed before looking at any test result): choose between logistic regression and LightGBM by pooled out-of-fold average precision (AP) on the TRAINING replica only (leave-one-snapshot-month-out, 9 folds). If the two AP values are within 10% of each other, choose the simpler model (logistic regression). LightGBM grid: num_leaves {4,7}, min_child_samples {30,100}, n_estimators {150,400}, reg_lambda {1,10}, scale_pos_weight {1,10}; learning_rate 0.03, subsample 0.8, colsample_bytree 0.8. Logistic regression: C=1.0 (fixed).

| training replica | OOF AP logreg | OOF AP LightGBM | relative gap | decision | chosen LightGBM params |
|---|---|---|---|---|---|
| 2024 | 0.0170 | 0.0177 | 4% | **logreg** (within 10% -> simpler model (logreg)) | {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 400, "reg_lambda": 1, "scale_pos_weight": 10} |
| 2025 | 0.0706 | 0.1202 | 41% | **lgbm** (AP differs by more than 10% -> higher AP) | {"num_leaves": 4, "min_child_samples": 30, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10} |

## Headline: pooled cross-replica hits (LOW POWER, 75 positives)

Sum of hits over the two test replicas (train 2024 -> test 2025, plus train 2025 -> test 2024), each in the top k for that replica. The comparison baseline is the single best baseline by summed tie-aware expected hits (**Exploit code, then EPSS**). The difference interval is a paired bootstrap (1000 resamples within each replica, seed 0, same resample for model and baseline, 90% interval of the summed difference).

| ranking | pooled hits (arbitrary order) | pooled expected hits (ties) | diff vs Exploit code, then EPSS | 90% paired-bootstrap interval of diff |
|---|---|---|---|---|
| CVSS 3 first | 5 | 5.4 |  |  |
| EPSS first | 11 | 11.0 |  |  |
| Exploit code, then EPSS | 19 | 19.0 |  |  |
| **Logistic regression** | 16 | 16.0 | -3 | [-9, +3] |
| **LightGBM** | 17 | 17.0 | -2 | [-9, +3] |

## train2024_test2025: primary (forward in time) (LOW POWER)

Test replica 2025: pool 35,280, 48 positives, k = 243. Hits in the top k with 90% bootstrap interval; expected hits average over ties at the cutoff; 'tie group' is the size of the tie group straddling the cutoff.

| ranking | hits (arbitrary) | expected hits | 90% boot | tie group at cutoff | AP | diff vs Exploit code, then EPSS [90% paired] |
|---|---|---|---|---|---|---|
| CVSS 3 first | 5 | 5.12 | [1-9] | 3823 (45 slots) | 0.0063 | -8 [-15, -3] |
| EPSS first | 8 | 8.00 | [4-13] | 17 (14 slots) | 0.0322 | -5 [-9, -2] |
| Exploit code, then EPSS | 13 | 13.00 | [8-20] | 4 (3 slots) | 0.0480 |  |
| Logistic regression | 9 | 9.00 | [4-14] | 1 | 0.0942 | -4 [-10, +0] |
| LightGBM | 11 | 11.00 | [6-16] | 19 (3 slots) | 0.0369 | -2 [-9, +3] |

Per-month hits in the top k (2025):

|  | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 |
|---|---|---|---|---|---|---|---|---|---|
| positives in pool | 7 | 5 | 7 | 5 | 6 | 7 | 2 | 5 | 4 |
| Logistic regression | 0 | 0 | 1 | 2 | 2 | 3 | 0 | 0 | 1 |
| LightGBM | 0 | 0 | 4 | 2 | 1 | 3 | 0 | 0 | 1 |
| Exploit code, then EPSS | 1 | 0 | 2 | 3 | 3 | 2 | 0 | 1 | 1 |

## train2025_test2024: stability check (NOT forward in time) (LOW POWER)

Test replica 2024: pool 28,839, 27 positives, k = 198. Hits in the top k with 90% bootstrap interval; expected hits average over ties at the cutoff; 'tie group' is the size of the tie group straddling the cutoff.

| ranking | hits (arbitrary) | expected hits | 90% boot | tie group at cutoff | AP | diff vs Exploit code, then EPSS [90% paired] |
|---|---|---|---|---|---|---|
| CVSS 3 first | 0 | 0.26 | [0-0] | 2943 (63 slots) | 0.0030 | -6 [-10, -2] |
| EPSS first | 3 | 3.00 | [1-6] | 3 (1 slots) | 0.0147 | -3 [-6, -1] |
| Exploit code, then EPSS | 6 | 6.00 | [2-10] | 19 (2 slots) | 0.0242 |  |
| Logistic regression | 7 | 7.00 | [3-12] | 6 (4 slots) | 0.0366 | +1 [-2, +5] |
| LightGBM | 6 | 6.00 | [2-10] | 1 | 0.0697 | +0 [-2, +3] |

Per-month hits in the top k (2024):

|  | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 |
|---|---|---|---|---|---|---|---|---|---|
| positives in pool | 4 | 2 | 1 | 1 | 4 | 6 | 1 | 5 | 3 |
| Logistic regression | 2 | 0 | 0 | 0 | 0 | 3 | 0 | 2 | 0 |
| LightGBM | 2 | 0 | 0 | 0 | 1 | 2 | 0 | 1 | 0 |
| Exploit code, then EPSS | 2 | 0 | 0 | 0 | 1 | 2 | 0 | 1 | 0 |

## Pooled leave-one-month-out within each replica (OPTIMISTIC, LOW POWER)

Out-of-fold predictions from the same CV used for selection, so parameters were chosen on these folds and related CVEs in adjacent months can leak across folds. Treat as an upper bound.

Replica 2024 (k = 198, 27 positives):

| ranking | hits (arbitrary) | expected hits | 90% boot | tie group at cutoff |
|---|---|---|---|---|
| CVSS 3 first | 0 | 0.26 | [0-0] | 2943 (63 slots) |
| EPSS first | 3 | 3.00 | [1-6] | 3 (1 slots) |
| Exploit code, then EPSS | 6 | 6.00 | [2-10] | 19 (2 slots) |
| Logistic regression | 4 | 4.00 | [1-8] | 1 |
| LightGBM | 6 | 6.00 | [2-10] | 1 |

Replica 2025 (k = 243, 48 positives):

| ranking | hits (arbitrary) | expected hits | 90% boot | tie group at cutoff |
|---|---|---|---|---|
| CVSS 3 first | 5 | 5.12 | [1-9] | 3823 (45 slots) |
| EPSS first | 8 | 8.00 | [4-13] | 17 (14 slots) |
| Exploit code, then EPSS | 13 | 13.00 | [8-20] | 4 (3 slots) |
| Logistic regression | 12 | 12.00 | [7-18] | 1 |
| LightGBM | 12 | 12.00 | [7-18] | 10 (6 slots) |

## Ablation: drop one feature group (LOW POWER)

Refit with the parameters chosen on the full feature set (no re-tuning). Hits in the top k (arbitrary / expected).

| dropped group | 2024->2025 logreg | 2024->2025 lgbm | 2025->2024 logreg | 2025->2024 lgbm |
|---|---|---|---|---|
| none | 9 / 9.0 | 11 / 11.0 | 7 / 7.0 | 6 / 6.0 |
| -signals | 11 / 11.0 | 9 / 9.0 | 7 / 7.0 | 9 / 9.0 |
| -flags | 7 / 7.0 | 6 / 6.0 | 1 / 1.0 | 4 / 4.0 |
| -timing | 8 / 8.0 | 11 / 11.0 | 7 / 7.0 | 5 / 5.0 |
| -assigner | 12 / 12.0 | 11 / 11.0 | 5 / 5.0 | 5 / 5.0 |
| -vendor | 9 / 9.0 | 8 / 8.0 | 7 / 7.0 | 8 / 8.0 |

## Blind spots (Discovery table, LOW POWER)

Positives with no public exploit flag AND within-month EPSS rank below the cut a top-k EPSS ranking would make (percentile < 1 - k/pool). The last columns count how many of those the v1 model puts in its own top k.

| replica | positives | blind-spot positives | EPSS-rank threshold | caught by logreg | caught by LightGBM |
|---|---|---|---|---|---|
| 2025 | 48 | 27 | 0.9931 | 0 | 2 |
| 2024 | 27 | 17 | 0.9931 | 0 | 0 |

## CVSS >= 9.8 does not find attacks (Discovery table)

CVSS is used here only to describe the pool, never as a model input.

| replica | share of pool CVSS>=9.8 | CVEs inside | positives inside | rate inside | CVEs outside | positives outside | rate outside | lift |
|---|---|---|---|---|---|---|---|---|
| 2024 | 10.7% | 3078 | 12 | 0.390% | 25761 | 15 | 0.058% | 6.70x |
| 2025 | 11.4% | 4021 | 15 | 0.373% | 31259 | 33 | 0.106% | 3.53x |

## Candidate positives for a no-EPSS prior model (informational only)

CVEs published Jan-Sep of 2022 and 2023 labelled with the same rule (KEV date_added after the end of the publish month and on or before Nov 4 of that year). No EPSS or flag columns exist for those years; nothing was built.

| publish year | CVEs published Jan-Sep | pool (not on KEV by end of publish month) | have a KEV entry (any date) | candidate positives |
|---|---|---|---|---|
| 2022 | 18,845 | 18,804 | 99 | **36** |
| 2023 | 21,037 | 20,969 | 123 | **22** |

## Final model (fit on both replicas)

Pooled OOF AP (month folds across both replicas): logreg 0.0688, LightGBM 0.0887, relative gap 22% -> **lgbm** (AP differs by more than 10% -> higher AP). LightGBM params: `{"num_leaves": 4, "min_child_samples": 30, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 1}`. Scored `features_scoreboard.parquet`; wrote `outputs/top500_v1.csv` (lgbm ranking). `v1_top500_contrib.parquet` holds LightGBM pred_contrib values for those 500 CVEs (from the LightGBM fit, whichever model ranked them). Top LightGBM gain importances:

| feature | gain share | logreg coef (standardised) |
|---|---|---|
| assigner_kev_rate_smooth | 37.4% | +0.33 |
| n_flags | 20.6% | +0.11 |
| assigner_prior_cves | 10.1% | -0.80 |
| epss | 9.0% | +0.01 |
| any_exploit | 5.8% | +0.25 |
| poc_github | 4.5% | +0.12 |
| days_to_snapshot | 2.9% | -0.12 |
| days_to_cutoff | 2.7% | +0.18 |

## Does v1 beat the best baseline? (honest read, LOW POWER)

- **Logistic regression** has more hits than Exploit code, then EPSS in 1 of 2 directions (beats it in BOTH: **NO**). train2024_test2025: 9 hits vs 13 for Exploit code, then EPSS (expected 9.0 vs 13.0); train2025_test2024: 7 hits vs 6 for Exploit code, then EPSS (expected 7.0 vs 6.0).
- **LightGBM** has more hits than Exploit code, then EPSS in 0 of 2 directions (beats it in BOTH: **NO**). train2024_test2025: 11 hits vs 13 for Exploit code, then EPSS (expected 11.0 vs 13.0); train2025_test2024: 6 hits vs 6 for Exploit code, then EPSS (expected 6.0 vs 6.0).
- Pooled paired-bootstrap difference vs Exploit code, then EPSS for Logistic regression: [-9, +3] hits. The interval includes zero, so the evidence is inconclusive at this sample size.
- Pooled paired-bootstrap difference vs Exploit code, then EPSS for LightGBM: [-9, +3] hits. The interval includes zero, so the evidence is inconclusive at this sample size.

With 75 positives in total, differences of a few hits are within noise. No parameters or features were tuned on the test replicas to change this outcome.
