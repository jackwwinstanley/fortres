# v4 report: drift-robust feature set, 20-seed bag, stress tests redone

> **LOW POWER.** 27 (2024) and 48 (2025) positives, 75 in total. Directions: train 2024 -> test 2025 (forward in time) and train 2025 -> test 2024 (stability check, not forward in time). Hits are in the top k (198 for 2024, 243 for 2025). Headline numbers are the 20-seed bag or multi-seed means; seed-0 single runs are labelled and not for headline. **Everything labelled 'pre-drift-fix' (raw epss included) is superseded and must not be used in a headline.**

## Decisions and policy (declared before the numbers)

1. Raw `epss` is removed (it moved ~4x in 2026); `epss_rank_in_month` and `epss_missing` stay.
2. Scale-type features with PSI > 0.25 (pooled replicas vs 2026 scoreboard) are replaced by their within-pool percentile rank: **days_to_cutoff, assigner_prior_cves, assigner_kev_count, assigner_kev_12m, assigner_kev_rate_smooth**.
3. Hyper-parameters use the same pre-set rule (pooled-AP on the training replica; final model pooled-AP over both replicas); nothing is tuned on a test replica.
4. The final model is a 20-seed LightGBM bag (each seed's scores rank-normalised within the pool, then averaged). It is chosen because bagging removes seed luck, not because of its hits. `kev_text_score` and `nearest_kev_sim` stay in the set (neutral within noise, see the ablation).
5. v4 replaces v3 as primary unless: (i) placebo p > 0.2; (ii) the 20-seed mean of single-seed pooled hits is below the baseline's (19); (iii) leakage is found. v3 vs v4 is not decided by comparing test hits.

| veto condition | value | triggered? |
|---|---|---|
| (i) placebo p (fraction of 50 null runs with pooled hits >= the 20-seed mean 22.1) | 0.02 | no |
| (ii) 20-seed mean single-seed pooled hits vs baseline 19 | 22.1 | no |
| (iii) leakage found | no | no |

**Policy outcome: v4: 20-seed LightGBM bag, no raw EPSS.** No veto condition was triggered.

## Headline (20-seed bag; use these numbers, not seed-0 rows)

The v4 bag has **21 pooled hits** (12 on test 2025, 9 on test 2024) against the baseline's **19** (13 + 6): +2, with a 90% interval of [-4, +9] (CVE-level paired bootstrap) and [-4, +9] (event-clustered bootstrap). Single seeds average 22.1 (min 17, max 25). Evidence strength: **WEAK**.

## Drift: PSI of every v2 feature (pooled replicas vs 2026 scoreboard)

10 bins from the replicas (spike-aware: a value holding >= 10% of the replica rows, usually 0, gets its own bin; binary flags use one bin per value). PSI > 0.25 is a large shift. Scale-type = counts or raw scores (not binary flags, not an existing percentile rank). `b/drift.py` reports raw EPSS PSI 1.70 against the 2025 replica alone; pooled replicas give 2.87 here.

| feature | type | PSI before | decision | PSI after (v4 column) |
|---|---|---|---|---|
| epss | removed | 2.866 | **removed** |  |
| epss_missing | binary | 0.075 | kept | 0.075 |
| epss_rank_in_month | rank | 0.145 | kept | 0.145 |
| exploitdb | binary | 0.001 | kept | 0.001 |
| metasploit | binary | 0.000 | kept | 0.000 |
| nuclei | binary | 0.000 | kept | 0.000 |
| poc_github | binary | 0.000 | kept | 0.000 |
| n_flags | scale | 0.000 | kept | 0.000 |
| any_exploit | binary | 0.000 | kept | 0.000 |
| days_to_snapshot | scale | 0.048 | kept | 0.048 |
| days_to_cutoff | scale | 1.028 | **replaced by percentile rank** | 2.333 |
| assigner_prior_cves | scale | 1.886 | **replaced by percentile rank** | 0.855 |
| assigner_kev_count | scale | 1.172 | **replaced by percentile rank** | 2.658 |
| assigner_kev_12m | scale | 0.779 | **replaced by percentile rank** | 2.767 |
| assigner_kev_rate_smooth | scale | 0.739 | **replaced by percentile rank** | 0.446 |
| n_vendors_mentioned | scale | 0.006 | kept | 0.006 |
| vendor_kev_count_max | scale | 0.094 | kept | 0.094 |
| vendor_kev_12m_max | scale | 0.234 | kept | 0.234 |
| kev_text_score | scale | 0.156 | kept | 0.156 |
| nearest_kev_sim | scale | 0.100 | kept | 0.100 |
| txt_rce | binary | 0.003 | kept | 0.003 |
| txt_unauth | binary | 0.056 | kept | 0.056 |
| txt_auth_bypass | binary | 0.000 | kept | 0.000 |
| txt_cmd_injection | binary | 0.000 | kept | 0.000 |
| txt_deserialization | binary | 0.000 | kept | 0.000 |
| txt_path_traversal | binary | 0.001 | kept | 0.001 |
| txt_sqli | binary | 0.020 | kept | 0.020 |
| txt_priv_esc | binary | 0.001 | kept | 0.001 |
| txt_memory | binary | 0.003 | kept | 0.003 |
| txt_edge_device | binary | 0.001 | kept | 0.001 |
| txt_enterprise | binary | 0.003 | kept | 0.003 |
| txt_browser | binary | 0.051 | kept | 0.051 |
| txt_wordpress | binary | 0.013 | kept | 0.013 |
| txt_xss | binary | 0.095 | kept | 0.095 |

**The percentile-rank replacement did not reduce PSI for every replaced feature:** days_to_cutoff (1.03 -> 2.33), assigner_kev_count (1.17 -> 2.66), assigner_kev_12m (0.78 -> 2.77) got worse. These features are tie-heavy (zeros, or one value per snapshot month for days_to_cutoff), so a within-pool rank moves the pile of tied values to a different position in each pool instead of removing the difference. The replacement was applied as pre-specified; it should not be read as having fixed the shift for these columns.

### Share of CVEs whose assigner has zero history (`assigner_prior_cves == 0`)

| pool | share |
|---|---|
| replica 2024 | 12.3% |
| replica 2025 | 0.8% |
| 2026 scoreboard | 1.2% |

The 2024 replica has far more CVEs from assigners with no prior CVEs than either the 2025 replica or the 2026 scoreboard, so a model trained on 2024 sees an assigner-history regime the 2026 pool does not have; the 2025 replica resembles 2026.

## Selection (same pre-set rule, training replica only)

| training replica | OOF AP logreg | OOF AP LightGBM | relative gap | rule would pick | LightGBM params |
|---|---|---|---|---|---|
| 2024 | 0.0458 | 0.0257 | 44% | logreg | {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10} |
| 2025 | 0.0656 | 0.0834 | 21% | lgbm | {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 1} |

The final model is the LightGBM bag by pre-declaration (see policy); the rule's pick is shown for information.

## Directional results on the new feature set

| ranking | test 2025 | test 2024 | pooled | diff vs baseline (90%: CVE-level / event-clustered) |
|---|---|---|---|---|
| Exploit code, then EPSS (baseline) | 13 | 6 | 19 |  |
| **v4 20-seed bag (headline)** | 12 | 9 | 21 | +2  [-4, +9] / [-4, +9] |
| v4 single seeds 0-19, mean per direction | 13.2 | 8.9 | 22.1 | +3.1 |
| v4 logistic regression (deterministic) | 13 | 11 | 24 | +5  [-3, +11] / [-4, +13] |
| previous v2 20-seed bag (pre-drift-fix) | 11 | 7 | 18 | -1  [-7, +5] / [-6, +5] |
| v4 seed 0 only (not for headline) | 13 | 9 | 22 |  |
| previous v2 seed 0 only (pre-drift-fix, not for headline) | 15 | 8 | 23 |  |

The deterministic logistic regression has more pooled hits than the bag; choosing it now would be selecting by test hits, which the policy forbids. If the team wants a different final model type, decide it by a rule fixed in advance. Paired differences of the v4 bag (pooled; CVE-level / event-clustered 90% intervals): vs the previous v2 bag (pre-drift-fix) +3 [-0, +8] / [-1, +8]; vs the previous v2 seed 0 (pre-drift-fix, not for headline) -2 [-6, +4] / [-7, +5]. The event-clustered bootstrap groups the positives into 67 KEV events (41 in the 2025 replica, 26 in 2024) by (KEV date added, KEV vendor), resamples events together and resamples negatives iid; it is the more conservative interval.

## Old vs new in one table (does removing raw EPSS change anything?)

Old = pre-drift-fix (legacy v2 set with raw epss, 34 features). New = v4 set (33 features, no raw epss, 5 features rank-replaced). Fixed parameters from the pre-set rule on each set; same seeds; same directions.

| quantity | old (pre-drift-fix) | new (v4) |
|---|---|---|
| features | 34 | 33 |
| 20-seed bag pooled hits (test 2025 + test 2024) | 18 (11 + 7) | **21** (12 + 9) |
| bag minus baseline, CVE-level 90% interval | -1 [-7, +5] | +2 [-4, +9] |
| bag minus baseline, event-clustered 90% interval | -1 [-6, +5] | +2 [-4, +9] |
| single-seed pooled hits, 20 seeds: mean / min / max | 19.6 / 16 / 23 | 22.1 / 17 / 25 |
| seed 0 pooled hits (not for headline) | 23 | 22 |
| v1-style (no text) 20-seed pooled hits: mean / min / max | 17.1 / 15 / 19 (legacy v1, own params) | 20.1 / 18 / 22 (v4 minus text) |
| ablation 10-seed mean: full | 19.7 | 21.7 |
| ablation: -kev_text_score | 21.3 | 22.6 |
| ablation: -nearest_kev_sim | 19.7 | 22.3 |
| ablation: -txt_ flags | 17.5 | 19.6 |
| ablation: -all text | 18.5 | 19.6 |
| placebo null mean / 95th percentile | 15.4 / 18 | 19.2 / 21 |
| placebo p vs the 20-seed mean of real single-seed hits | 0.00 | 0.02 |
| leakage flags | none | none |

Baseline for reference: 19 pooled hits (13 on 2025, 6 on 2024).

## Stress tests on the new feature set

### Seed distribution (single seeds 0-19, fixed parameters) next to the baseline

| model | mean pooled | min | max |
|---|---|---|---|
| baseline (no seeds) | 19 | 19 | 19 |
| legacy v1 (raw epss; pre-drift-fix) | 17.1 | 15 | 19 |
| legacy v2 (raw epss; pre-drift-fix) | 19.6 | 16 | 23 |
| v1-style new: v4 minus text | 20.1 | 18 | 22 |
| **v4 (full new set)** | 22.1 | 17 | 25 |
| v4 20-seed bag | 21 | 21 | 21 |

### Text ablation on the new set (10-seed means, seeds 1-10, fixed parameters, no re-tuning)

| variant | mean pooled | min | max | mean test 2025 | mean test 2024 |
|---|---|---|---|---|---|
| full | 21.7 | 17 | 25 | 12.8 | 8.9 |
| -kev_text_score | 22.6 | 19 | 26 | 13.3 | 9.3 |
| -nearest_kev_sim | 22.3 | 19 | 26 | 13.2 | 9.1 |
| -txt_ flags | 19.6 | 16 | 24 | 11.1 | 8.5 |
| -all text | 19.6 | 18 | 22 | 10.6 | 9.0 |

### Placebo: the 16 text columns shuffled jointly within snapshot month (50 repeats)

| quantity | value |
|---|---|
| null mean of pooled hits | 19.22 |
| null 95th percentile | 21.0 |
| null min / max | 16 / 23 |
| real: 20-seed mean of single-seed pooled hits (veto reference) | 22.1 |
| p = fraction of null runs >= that mean | 0.02 |
| p vs seed-0 real / vs the bag's hits (for context) | 0.04 / 0.28 |
| no-text model next to the null: 10-seed mean / 20-seed mean | 19.6 / 20.1 |

Shuffled text columns act as noise features, so the null is expected at or below the no-text model; p therefore measures 'real text beats noise text', a more lenient test than 'text beats no text' (compare the no-text row to the full model). The bag's own hits are matched by 28% of the single-seed null runs, which is not a like-for-like comparison but shows how little room there is. Null distribution (counts): 16: 1, 17: 7, 18: 10, 19: 11, 20: 7, 21: 12, 22: 1, 23: 1.

### Mechanism: where do the hits come from? (test replicas; models trained on the other replica)

Groups: flagged = any public exploit flag; blind-spot = no flag and within-month EPSS rank below the cut a top-k EPSS list makes; unflagged-EPSS-visible = no flag but above that cut.

| test replica | group of positives | positives | baseline | previous v2 seed 0 | previous v2 bag | v4 bag |
|---|---|---|---|---|---|---|
| 2025 | flagged | 21 | 13 | 11 | 11 | 11 |
| 2025 | unflagged, EPSS-visible | 0 | 0 | 0 | 0 | 0 |
| 2025 | blind-spot | 27 | 0 | 4 | 0 | 1 |
| 2025 | all positives | 48 | 13 | 15 | 11 | 12 |
| 2024 | flagged | 10 | 6 | 7 | 7 | 8 |
| 2024 | unflagged, EPSS-visible | 0 | 0 | 0 | 0 | 0 |
| 2024 | blind-spot | 17 | 0 | 1 | 0 | 1 |
| 2024 | all positives | 27 | 6 | 8 | 7 | 9 |

Hits gained (in the v4 bag's top k, not the baseline's) and lost (the reverse), grouped by KEV event (same vendor and date added); full CVE list in `outputs/v4_mechanism.csv`. Vendor and dates are post-snapshot facts shown for description only.

| test replica | kind | KEV vendor | date added | CVEs | group | CVE ids |
|---|---|---|---|---|---|---|
| 2024 | gained | Microsoft | 2024-10-15 | 1 | flagged | CVE-2024-30088 |
| 2024 | gained | Progress | 2024-09-16 | 1 | flagged | CVE-2024-6670 |
| 2024 | gained | VMware | 2024-07-30 | 1 | blind-spot | CVE-2024-37085 |
| 2024 | gained | Veeam | 2024-10-17 | 1 | flagged | CVE-2024-40711 |
| 2024 | lost | Jenkins | 2024-08-19 | 1 | flagged | CVE-2024-23897 |
| 2025 | gained | Broadcom | 2025-10-30 | 1 | flagged | CVE-2025-41244 |
| 2025 | gained | Cisco | 2025-07-28 | 1 | flagged | CVE-2025-20281 |
| 2025 | gained | Citrix | 2025-07-10 | 1 | flagged | CVE-2025-5777 |
| 2025 | gained | Fortinet | 2025-03-18 | 1 | blind-spot | CVE-2025-24472 |
| 2025 | lost | Adobe | 2025-10-15 | 1 | flagged | CVE-2025-54253 |
| 2025 | lost | Adobe | 2025-10-24 | 1 | flagged | CVE-2025-54236 |
| 2025 | lost | Dassault Systèmes | 2025-09-11 | 1 | flagged | CVE-2025-5086 |
| 2025 | lost | Erlang | 2025-06-09 | 1 | flagged | CVE-2025-32433 |
| 2025 | lost | FreeType | 2025-05-06 | 1 | flagged | CVE-2025-27363 |

(CVEs, events): test 2024 gained: (4, 4); test 2024 lost: (1, 1); test 2025 gained: (4, 4); test 2025 lost: (5, 5).

### Leakage audit (same pre-declared rules as step 3c, new feature list)

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

Limit: the Granite embeddings are not available locally, so `kev_text_score` and `nearest_kev_sim` were not recomputed; their time-safety rests on Person B's code (classifier for pool year Y trains only on CVEs published before Y-01-01 labelled with KEV `date_added` <= (Y-1)-12-31; `nearest_kev_sim` uses KEV rows with `date_added` <= (Y-1)-12-31). Descriptions are the current NVD text.

## Final list: `outputs/top500_v4.csv`

| item | value |
|---|---|
| model | 20-seed LightGBM bag on both replicas, v4 features, parameters from the pooled-AP selection |
| parameters | `{"num_leaves": 4, "min_child_samples": 30, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 1}` |
| pooled OOF AP of the selection | 0.0565 |
| ranking rule | bag score, then epss_rank_in_month, then cve_id |
| overlap with top500_v3 | 408 |
| overlap with the baseline top 500 | 191 |
| overlap with top500_v2 (two-channel hybrid) | 158 |
| CVEs with an exploit flag: v4 list vs baseline list | 423 vs 500 |
| contributions | `outputs/v4_top500_contrib.parquet` (LightGBM pred_contrib averaged over the 20 seeds, one column per feature) |

## How strong is the evidence?

**WEAK.** The v4 20-seed bag has 21 pooled hits against the baseline's 19 (+2; CVE-level 90% interval [-4, +9], event-clustered [-4, +9]). Single seeds average 22.1 (min 17, max 25), and the placebo null mean is 19.2 with p = 0.02. Removing raw EPSS moved the bag from 18 to 21 pooled hits (+3) and the single-seed mean from 19.6 to 22.1. The event-clustered interval includes zero, so a gain over the baseline is not established at 90% once correlated KEV events are respected. Text ablation (10-seed means): full 21.7, without kev_text_score 22.6, without nearest_kev_sim 22.3, without the txt_ flags 19.6, without any text 19.6; differences of 1-2 hits are within seed noise. With 75 positives from a handful of KEV events, treat any improvement over the baseline as uncertain.
