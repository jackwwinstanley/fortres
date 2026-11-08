# Ranking-method tests on the v5 features (b/rank): report for Jack

Branch `b/rank` (no PR). Code `src/b/rank.py`. Every attempted run, including failures, discarded inner-CV combos and the
skipped K, is in `outputs/rank_eval.csv`. Nothing in top500*, headline.json, runlog.csv, docs/, site/, app/ or README.md was
touched, and no list or contribution file was regenerated. b/outside Part 1 flagged no leaky v5 feature, so there is no
"feature removed" re-run. LOW POWER: 75 positives.

## Verdict under the fixed rule: candidate I (regularised v5) qualifies
I is the only candidate that passes all three conditions:

| condition | needed | I |
|---|---|---|
| forward | ≥ v5's 12 | **18** |
| stability | ≥ v5's 9 | **9** |
| pooled gain | ≥ 2 and ≥ the noise floor of 4 | **+6** (90% interval +2 to +11) |

H comes before I in the priority order but does not qualify, so I is the pick. Nothing was regenerated. Adopting I
(a new top500 and new docs) is Jack's call.

## Noise floor first (`outputs/rank_noise_floor.csv`): frozen v5, its own parameters
| seed set | forward | stability | pooled |
|---|---|---|---|
| 0-19 (the headline bag, reference) | 12 | 9 | 21 |
| 1000-1019 | 15 | 9 | 24 |
| 2000-2019 | 12 | 9 | 21 |
| 3000-3019 | 15 | 10 | 25 |
| **spread over the 3 new sets** | 3 | 1 | **4** |

The headline bag reproduces 12 / 9 / 21 exactly. Seed choice alone moves v5 by up to 4 pooled hits, and the headline seeds
sit at the low end.

## All candidates: 20-seed bags, seeds 0-19 (`outputs/rank_summary.csv`, `outputs/rank_adoption.csv`)
| candidate | forward (train 2024 → test 2025) | stability (train 2025 → test 2024) | pooled | pooled vs v5, 90% | qualifies |
|---|---|---|---|---|---|
| v5 frozen | 12 | 9 | 21 | | |
| H monotone (EPSS rank + 4 exploit flags only) | 13 | 9 | 22 | +1 [−4, +5] | no (gain < 4) |
| **I regularised** | **18** | **9** | **27** | **+6 [+2, +11]** | **yes** |
| F positive weighting | 14 | 9 | 23 | +2 [−2, +5] | no (gain < 4) |
| D lambdarank | 13 | 9 | 22 | +1 [−2, +4] | no |
| E rank_xendcg | 4 | 7 | 11 | −10 [−16, −4] | no |
| J rank-average of v5, D, F, H | 12 | 9 | 21 | +0 [+0, +0] | no |
| K XGBoost rank:ndcg | skipped | | | | xgboost is not installed |

Settings chosen by leave-one-month-out CV inside the training year only:

| candidate | train 2024 | train 2025 |
|---|---|---|
| I | num_leaves 2 (stumps), min_child_samples 200, colsample 0.4, L2 30 | num_leaves 3, min_child_samples 200, colsample 0.6, L2 30 |
| F | scale_pos_weight 3 | scale_pos_weight 10 (= v5) |

I inherits n_estimators 150 and scale_pos_weight 10 from v5 in both directions.

## Robustness of I (run after the verdict; it does not change it): `outputs/rank_I_robustness.csv`
Same I settings, the three other seed sets, against v5 on the same seeds:

| seed set | I forward / stability / pooled | v5 forward / stability / pooled | I − v5 pooled |
|---|---|---|---|
| 1000-1019 | 18 / 10 / 28 | 15 / 9 / 24 | +4 |
| 2000-2019 | 18 / 8 / 26 | 12 / 9 / 21 | +5 |
| 3000-3019 | 18 / 9 / 27 | 15 / 10 / 25 | +2 |

I's forward result is steady (18 every time). Its stability result wobbles (8 to 10) and is sometimes below v5's. The pooled
gain is +2 to +5 depending on seeds, smaller than the headline +6.

## Diagnostic for the model card: vendor-grouped CV on v5 (`outputs/rank_vendor_cv.csv`)
Within each practice year, v5 with its own settings and a 5-seed bag, 5 folds: whole vendors held out vs ordinary
stratified folds. The vendor is the CVE's most common CPE vendor, used only for grouping (assigner when unknown).

| replica | ungrouped AP / hits | vendor-grouped AP / hits | vendor known |
|---|---|---|---|
| 2024 (27 positives, k 198) | 0.033 / 7 | 0.043 / 6 | 85% |
| 2025 (48 positives, k 243) | 0.103 / 19 | 0.042 / 10 | 65% |

In 2025, holding out whole vendors halves the hits (19 → 10). Part of v5's in-year skill there comes from recognising
vendors it has already seen. 2024 shows no gap. The cross-year tests above are the honest numbers; this table is only
for the model card.

## Deviations and failures (all logged)
- **D and E:** "one query group per pool" was attempted and failed, because LightGBM caps a query at 10,000 rows and
  the pools have 29-35k. Both fall back to one query group per snapshot month.
- **I, first attempt:** every grid combination failed on a coding bug of mine (colsample_bytree passed twice). It was
  fixed and re-run; the bug did not affect any other candidate.
- **Vendor diagnostic, first attempt:** a CSV-parsing error; re-run with a different reader.
- **H:** it differs from v5 only in leaving n_flags and any_exploit unconstrained, because v5 already constrains EPSS
  rank and the exploit flags.
