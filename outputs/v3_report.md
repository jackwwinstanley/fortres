# v3 report: stress tests of v2 LightGBM and the final candidate list

> **PRE-DRIFT-FIX (raw epss included): superseded by `outputs/v4_report.md`. Do not use any number in this report in a headline.**
> The 3c numbers below, including the seed-0 results and the 10-seed means, come from the legacy v2 feature set that contains raw `epss`.

> **LOW POWER.** 27 (2024) and 48 (2025) positives, 75 in total. Directions: train 2024 -> test 2025 (forward in time) and train 2025 -> test 2024 (stability check, not forward in time). Hits are in the top k (k = 198 for 2024, 243 for 2025), ties broken by score, epss_rank_in_month, cve_id. No hyper-parameter was tuned on test data.

## Pre-declared policy (fixed before the checks ran)

Primary candidate: v2 LightGBM trained on BOTH replicas with the pooled-AP-selected parameters. It is vetoed only if (i) the placebo p-value is greater than 0.2, (ii) the 10-seed mean of pooled hits is below the best baseline's pooled hits (19), or (iii) any leakage is found. If vetoed, fall back to the two-channel hybrid (`top500_v2.csv`). Candidates are not chosen by comparing their test hits.

| condition | value | triggers veto? |
|---|---|---|
| (i) placebo p-value (fraction of 50 null runs with pooled hits >= 23) | 0.00 | no |
| (ii) 10-seed mean pooled hits vs best baseline (19) | 19.7 | no |
| (iii) leakage found | no | no |

**Policy outcome: v2 LightGBM trained on both replicas.** No veto condition was triggered.

## Pooled hits per candidate (reference run, random_state 0)

| ranking | test 2025 | test 2024 | pooled |
|---|---|---|---|
| Exploit code, then EPSS (baseline) | 13 | 6 | 19 |
| v1 LightGBM | 11 | 6 | 17 |
| v2 LightGBM | 15 | 8 | 23 |
| v2 rank-average of logreg + LightGBM (evaluation only) | 13 | 8 | 21 |

The two-channel hybrid is `top500_v2.csv` (pooled 20, optimistic: s chosen on the data it is scored on). v2 LightGBM vs the baseline from the v2 report: +4 [-4, +10] (90% paired bootstrap).

## 1. Mechanism: where do the hits come from?

Positives are labelled **flagged** (any public exploit flag), **blind-spot** (no flag and within-month EPSS rank below the cut a top-k EPSS list makes) or **unflagged, EPSS-visible** (no flag but above that EPSS cut: a third group the two-way split leaves out). Models are trained on the other replica.

| test replica | group of positives | positives | baseline hits | v1 LightGBM hits | v2 LightGBM hits |
|---|---|---|---|---|---|
| 2025 | flagged | 21 | 13 | 9 | 11 |
| 2025 | unflagged, EPSS-visible | 0 | 0 | 0 | 0 |
| 2025 | blind-spot | 27 | 0 | 2 | 4 |
| 2025 | all positives | 48 | 13 | 11 | 15 |
| 2024 | flagged | 10 | 6 | 6 | 7 |
| 2024 | unflagged, EPSS-visible | 0 | 0 | 0 | 0 |
| 2024 | blind-spot | 17 | 0 | 0 | 1 |
| 2024 | all positives | 27 | 6 | 6 | 8 |

No positive in either replica is unflagged but EPSS-visible, so the flagged / blind-spot split is exhaustive here.

Hits gained (in v2's top k, not the baseline's) and lost (the reverse); full list in `outputs/v2_mechanism.csv`:

| test replica | kind | cve_id | group | KEV vendor | days to KEV |
|---|---|---|---|---|---|
| 2025 | gained | CVE-2024-13159 | blind-spot | Ivanti | 38 |
| 2025 | gained | CVE-2024-13160 | blind-spot | Ivanti | 38 |
| 2025 | gained | CVE-2024-13161 | blind-spot | Ivanti | 38 |
| 2025 | gained | CVE-2025-20281 | flagged | Cisco | 28 |
| 2025 | gained | CVE-2025-24472 | blind-spot | Fortinet | 18 |
| 2025 | gained | CVE-2025-41244 | flagged | Broadcom | 30 |
| 2025 | gained | CVE-2025-5777 | flagged | Citrix | 10 |
| 2025 | lost | CVE-2024-57727 | flagged | SimpleHelp  | 13 |
| 2025 | lost | CVE-2025-32433 | flagged | Erlang | 40 |
| 2025 | lost | CVE-2025-5086 | flagged | Dassault Systèmes | 73 |
| 2025 | lost | CVE-2025-54236 | flagged | Adobe | 24 |
| 2025 | lost | CVE-2025-54253 | flagged | Adobe | 45 |
| 2024 | gained | CVE-2024-30088 | flagged | Microsoft | 107 |
| 2024 | gained | CVE-2024-40711 | flagged | Veeam | 17 |
| 2024 | gained | CVE-2024-4358 | blind-spot | Progress | 13 |
| 2024 | gained | CVE-2024-6670 | flagged | Progress | 16 |
| 2024 | lost | CVE-2024-23897 | flagged | Jenkins | 201 |
| 2024 | lost | CVE-2024-32113 | flagged | Apache | 68 |

Vendor and days-to-KEV are post-snapshot facts shown for description only; they are never features. Distinct KEV events (same vendor and date added) behind these hits, as (CVEs, events): test 2024 gained: (4, 4); test 2024 lost: (2, 2); test 2025 gained: (7, 5); test 2025 lost: (5, 5). CVEs added to KEV together are one correlated event, so the effective gain is smaller than the CVE count.

## 2. Seed stability (fixed parameters, seeds 1-10)

| model | mean pooled | min | max | reference (seed 0) |
|---|---|---|---|---|
| v1 LightGBM | 17.4 | 16 | 19 | 17 |
| v2 LightGBM | 19.7 | 16 | 22 | 23 |

| seed | v1 test 2025 | v1 test 2024 | v1 pooled | v2 test 2025 | v2 test 2024 | v2 pooled |
|---|---|---|---|---|---|---|
| 1 | 11 | 6 | 17 | 10 | 6 | 16 |
| 2 | 9 | 7 | 16 | 9 | 7 | 16 |
| 3 | 12 | 6 | 18 | 15 | 7 | 22 |
| 4 | 11 | 6 | 17 | 15 | 7 | 22 |
| 5 | 11 | 6 | 17 | 11 | 8 | 19 |
| 6 | 12 | 7 | 19 | 15 | 7 | 22 |
| 7 | 11 | 8 | 19 | 12 | 8 | 20 |
| 8 | 10 | 6 | 16 | 15 | 7 | 22 |
| 9 | 12 | 7 | 19 | 11 | 7 | 18 |
| 10 | 10 | 6 | 16 | 12 | 8 | 20 |

## 3. Text ablation inside v2 (fixed parameters, no re-tuning)

Hits per direction use seed 0; the last two columns summarise seeds 1-10.

| variant | features | test 2025 | test 2024 | pooled (seed 0) | mean pooled (seeds 1-10) | range |
|---|---|---|---|---|---|---|
| none (full v2) | 34 | 15 | 8 | 23 | 19.7 | 16-22 |
| -kev_text_score | 33 | 13 | 8 | 21 | 21.3 | 18-25 |
| -nearest_kev_sim | 33 | 12 | 7 | 19 | 19.7 | 17-23 |
| -txt_ flags | 20 | 8 | 6 | 14 | 17.5 | 16-19 |
| -all text | 18 | 12 | 6 | 18 | 18.5 | 16-21 |

## 4. Placebo: the 16 text columns shuffled jointly within snapshot month (50 repeats)

Each repeat shuffles the text columns (one permutation for all 16, so their rows stay together) across rows within each snapshot month, separately in the training frame and the test frame, then refits v2 LightGBM (fixed parameters, seed 0) in both directions.

| quantity | value |
|---|---|
| null mean of pooled hits | 15.44 |
| null 95th percentile | 18.0 |
| null min / max | 12 / 19 |
| real v2 LightGBM pooled hits | 23 |
| p = fraction of null runs >= real | 0.00 |
| p with +1 correction, (count+1)/(n+1) | 0.020 |
| for context: fraction of null runs >= 10-seed mean of real | 0.00 |

Caveat: the shuffled-text null (mean 15.4) sits below the model with no text at all (10-seed mean 18.5) because shuffled columns act as noise features. So p measures 'real text beats noise text', a more lenient test than 'text beats no text' (full v2 19.7 vs no text 18.5 on 10-seed means).

Null distribution of pooled hits (counts): 12: 2, 13: 2, 14: 9, 15: 12, 16: 14, 17: 7, 18: 3, 19: 1. Saved in `outputs/v2_placebo.csv`.

## 5. Ensemble (evaluation only, not used for selection)

Rank average of v2 logistic regression and v2 LightGBM: test 2025 = 13, test 2024 = 8, pooled = 21.

## 6. Shift: replicas (pooled) vs the 2026 scoreboard

Standardised mean difference (scoreboard minus replicas) above 0.5 in absolute value is flagged.

| feature | mean (replicas) | mean (2026) | median (replicas) | median (2026) | missing (replicas) | missing (2026) | SMD |  |
|---|---|---|---|---|---|---|---|---|
| epss | 0.001194 | 0.002676 | 0.00043 | 0.0018 | 7.4% | 2.0% | +0.12 |  |
| epss_missing | 0.07396 | 0.01969 | 0 | 0 | 0.0% | 0.0% | -0.26 |  |
| epss_rank_in_month | 0.4632 | 0.4902 | 0.4153 | 0.4906 | 0.0% | 0.0% | +0.09 |  |
| exploitdb | 0.001419 | 0.0005092 | 0 | 0 | 0.0% | 0.0% | -0.03 |  |
| metasploit | 0.0006238 | 0.0002064 | 0 | 0 | 0.0% | 0.0% | -0.02 |  |
| nuclei | 0.003338 | 0.002298 | 0 | 0 | 0.0% | 0.0% | -0.02 |  |
| poc_github | 0.01879 | 0.02101 | 0 | 0 | 0.0% | 0.0% | +0.02 |  |
| n_flags | 0.02417 | 0.02403 | 0 | 0 | 0.0% | 0.0% | -0.00 |  |
| any_exploit | 0.02173 | 0.02264 | 0 | 0 | 0.0% | 0.0% | +0.01 |  |
| days_to_snapshot | 15.08 | 17.76 | 15 | 16 | 0.0% | 0.0% | +0.25 |  |
| days_to_cutoff | 157.7 | 122.3 | 157 | 96 | 0.0% | 0.0% | -0.46 |  |
| assigner_prior_cves | 7.652 | 8.135 | 8.364 | 9.017 | 0.0% | 0.0% | +0.20 |  |
| assigner_kev_count | 1.593 | 2.267 | 0.6931 | 2.079 | 0.0% | 0.0% | +0.36 |  |
| assigner_kev_12m | 0.9843 | 1.456 | 0 | 1.792 | 0.0% | 0.0% | +0.38 |  |
| assigner_kev_rate_smooth | 0.003991 | 0.005603 | 0.0008486 | 0.002391 | 0.0% | 0.0% | +0.18 |  |
| n_vendors_mentioned | 0.2504 | 0.2913 | 0 | 0 | 0.0% | 0.0% | +0.09 |  |
| vendor_kev_count_max | 0.5157 | 0.7387 | 0 | 0 | 0.0% | 0.0% | +0.17 |  |
| vendor_kev_12m_max | 0.1777 | 0.3018 | 0 | 0 | 0.0% | 0.0% | +0.19 |  |
| kev_text_score | 0.2032 | 0.2986 | 0.1051 | 0.2008 | 0.0% | 0.0% | +0.38 |  |
| nearest_kev_sim | 0.7481 | 0.7557 | 0.7432 | 0.7469 | 0.0% | 0.0% | +0.14 |  |
| txt_rce | 0.08893 | 0.07304 | 0 | 0 | 0.0% | 0.0% | -0.06 |  |
| txt_unauth | 0.06906 | 0.1398 | 0 | 0 | 0.0% | 0.0% | +0.23 |  |
| txt_auth_bypass | 0.01022 | 0.01211 | 0 | 0 | 0.0% | 0.0% | +0.02 |  |
| txt_cmd_injection | 0.0255 | 0.02681 | 0 | 0 | 0.0% | 0.0% | +0.01 |  |
| txt_deserialization | 0.0117 | 0.01167 | 0 | 0 | 0.0% | 0.0% | -0.00 |  |
| txt_path_traversal | 0.02338 | 0.02694 | 0 | 0 | 0.0% | 0.0% | +0.02 |  |
| txt_sqli | 0.07792 | 0.04468 | 0 | 0 | 0.0% | 0.0% | -0.14 |  |
| txt_priv_esc | 0.02873 | 0.0239 | 0 | 0 | 0.0% | 0.0% | -0.03 |  |
| txt_memory | 0.07907 | 0.09454 | 0 | 0 | 0.0% | 0.0% | +0.05 |  |
| txt_edge_device | 0.02388 | 0.0284 | 0 | 0 | 0.0% | 0.0% | +0.03 |  |
| txt_enterprise | 0.03628 | 0.04664 | 0 | 0 | 0.0% | 0.0% | +0.05 |  |
| txt_browser | 0.01517 | 0.05386 | 0 | 0 | 0.0% | 0.0% | +0.21 |  |
| txt_wordpress | 0.09727 | 0.06637 | 0 | 0 | 0.0% | 0.0% | -0.11 |  |
| txt_xss | 0.1833 | 0.08146 | 0 | 0 | 0.0% | 0.0% | -0.30 |  |

## Leakage audit

Pre-declared rules: the feature guard must pass; for each description pattern left after post-attack stripping, a flag is raised if at least 3 positives match and the positive rate is at least 5 times the negative rate; a text feature is flagged if its univariate AUC on a replica exceeds 0.95 (or is below 0.05). Limit: the Granite embeddings are not available locally, so `kev_text_score` and `nearest_kev_sim` were not recomputed; their time-safety rests on Person B's code, which I read: the classifier for pool year Y trains only on CVEs published before Y-01-01 labelled with KEV `date_added` <= (Y-1)-12-31, and `nearest_kev_sim` uses only KEV rows with `date_added` <= (Y-1)-12-31. Descriptions are the current NVD text and could have been edited after publication.

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

Description scan (pooled replicas):

| pattern | positives | negatives |  |
|---|---|---|---|
| post-attack phrases in RAW text (what stripping removed) | 5 / 75 (6.7%) | 77 / 64044 (0.12%) | ok |
| post-attack phrases left after stripping (must be 0) | 0 / 75 (0.0%) | 0 / 64044 (0.00%) | ok |
| ransomware | 0 / 75 (0.0%) | 11 / 64044 (0.02%) | ok |
| botnet | 0 / 75 (0.0%) | 6 / 64044 (0.01%) | ok |
| threat actor | 0 / 75 (0.0%) | 78 / 64044 (0.12%) | ok |
| in the wild | 1 / 75 (1.3%) | 12 / 64044 (0.02%) | ok |
| CISA / KEV / known exploited | 0 / 75 (0.0%) | 7 / 64044 (0.01%) | ok |
| exploitation wording (mass/active/ongoing exploitation, widely exploited) | 0 / 75 (0.0%) | 194 / 64044 (0.30%) | ok |

Univariate AUC of each text feature:

| feature | AUC replica 2024 | AUC replica 2025 |  |
|---|---|---|---|
| kev_text_score | 0.819 | 0.804 | ok |
| nearest_kev_sim | 0.759 | 0.691 | ok |
| txt_rce | 0.538 | 0.631 | ok |
| txt_unauth | 0.651 | 0.612 | ok |
| txt_auth_bypass | 0.551 | 0.546 | ok |
| txt_cmd_injection | 0.506 | 0.497 | ok |
| txt_deserialization | 0.514 | 0.525 | ok |
| txt_path_traversal | 0.507 | 0.541 | ok |
| txt_sqli | 0.504 | 0.466 | ok |
| txt_priv_esc | 0.559 | 0.497 | ok |
| txt_memory | 0.496 | 0.493 | ok |
| txt_edge_device | 0.505 | 0.511 | ok |
| txt_enterprise | 0.686 | 0.555 | ok |
| txt_browser | 0.491 | 0.504 | ok |
| txt_wordpress | 0.445 | 0.457 | ok |
| txt_xss | 0.431 | 0.415 | ok |

## Final list

**Selected by the policy: v2 LightGBM trained on both replicas.**

| item | value |
|---|---|
| file | `outputs/top500_v3.csv` (500 unique ids) |
| final-model parameters (pooled-AP selection, month folds) | `{"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 1}` |
| pooled OOF AP of the selection | 0.0557 |
| overlap with baseline top 500 (`top500_v0.csv`) | 213 |
| overlap with `top500_v2.csv` | 180 |
| v2 LightGBM (both replicas) top 500 overlap with baseline | 213 |
| CVEs with an exploit flag in the final list vs the baseline list | 475 vs 500 |
| list stability: overlap of the seed-0 top 500 with the top 500 from seeds 1-10 (information only) | mean 469, min 463, max 475 of 500 |
| contributions | `outputs/v3_top500_contrib.parquet` (LightGBM pred_contrib, one column per feature) |

## How strong is the evidence?

**WEAK.** With 75 positives, results are noisy. v2 LightGBM has 23 pooled hits against the baseline's 19 (seed 0; paired-bootstrap difference +4 [-4, +10]), a 10-seed mean of 19.7 (range 16-22), and a placebo null mean of 15.4 with p = 0.00. The bootstrap interval includes zero, so a gain over the baseline is not established at 90%. Seed 0, the reference run, is at the top of the seed range, so the single-seed margin overstates the typical gain: the 10-seed mean is +0.7 hits against the baseline. In the ablation (10-seed means) the full model scores 19.7, dropping kev_text_score gives 21.3, dropping nearest_kev_sim 19.7, dropping the txt_ flags 17.5 and dropping all text 18.5: the ablation points to the plain regex flags, not the Granite embedding scores, as the source of any lift (differences of 1-2 hits are within seed noise). Several of the extra hits are CVEs added to KEV together (see section 1). The placebo shows how often noise text would do as well; its caveat is in section 4. Leakage checks: none raised, within the limits stated above. Treat the list as a modest, uncertain improvement at best.
