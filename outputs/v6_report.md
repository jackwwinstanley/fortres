# v6 candidate (b/rank candidate I, regularised v5): report for Jack's verdict

Branch `b/v6`: b/rank with origin/main merged in. No PR. Code `src/models/train_v6.py`.

- **No v5 file changed.** Untouched: top500.csv, top500_v5.csv, headline.json, runlog.csv, docs/, site/, app/ and README.md.
  All new files are `v6_*`, plus `top500_v6.csv`.
- **v5 stays the headline** until Jack decides. No doc or site numbers were edited.
- LOW POWER: 27 + 48 = 75 positives.

## How this model was chosen
v6 is the only variant that passed a rule fixed before any result: at least v5's score forward and in stability, and a
pooled gain of at least 2 hits and at least the noise floor, with ties going to the earliest of H, I, F, D, E, J, K. The
noise floor is the pooled spread of the frozen v5 bag over 3 new seed sets: 21 to 25, so 4.

In this round seven variants were declared, each a 20-seed bag with settings chosen only by cross-validation inside the
training year:

| variant | forward / stability / pooled | result |
|---|---|---|
| H monotone | 13 / 9 / 22 | not enough |
| **I regularised (became v6)** | **18 / 9 / 27** | **qualified** |
| F positive weighting | 14 / 9 / 23 | not enough |
| D lambdarank (one query per month; one query per pool is impossible in LightGBM) | 13 / 9 / 22 | not enough |
| E rank_xendcg | 4 / 7 / 11 | much worse |
| J rank-average of v5, D, F and H | 12 / 9 / 21 | same as v5 |
| K XGBoost | skipped | not installed |

Earlier rounds of outside data changed nothing:
- VulnCheck KEV was rejected, because its dates are hindsight.
- CISA Vulnrichment flags one CVE and none in 2026.
- GitHub PoC creation dates plus the monthly EPSS change scored 18 vs 21.

Caveats:
- **Seeds:** on matched seed sets v6 beats v5 by only +2 to +5, not +6.
- **Vendors:** a vendor-grouped diagnostic on v5 halves its 2025 in-year hits (19 → 10) when whole vendors are held out,
  and shows no gap in 2024. Part of the in-year skill is vendor familiarity.

## 1. Final settings and list
The settings use the same rule as v5's final model: leave-one-month-out CV (month-of-year folds) on the pooled 2024 +
2025 replicas, pooled OOF AP, over candidate I's 16-cell grid. No test year was used.

- **Chosen:** num_leaves 3, min_child_samples 200, colsample_bytree 0.4, reg_lambda 30, plus n_estimators 150 and
  scale_pos_weight 1 inherited from v5's final selection. CV AP 0.0305; all 16 cells are in `outputs/v6_runs.csv`.
- **Model:** 20-seed (0-19) rank-averaged bag on the v5 features. Ranking: bag score, then epss_rank_in_month, then cve_id.
- **Files:**
  - `outputs/top500_v6.csv`: **check_top500.py: PASS**;
  - `outputs/v6_scores.csv`: the score and rank of all 72,670 CVEs;
  - `outputs/v6_top500_contrib.parquet`: same format as v5's.

## 2. Checks
The practice-year checks use I's per-direction settings from b/rank:
- train 2024: num_leaves 2, colsample 0.4;
- train 2025: num_leaves 3, colsample 0.6;
- both: min_child_samples 200, L2 30, 150 trees, scale_pos_weight 10.

### Overlap and exploit flags (`outputs/v6_overlap.csv`)
| | value |
|---|---|
| top500_v6 ∩ top500_v5 | 429 |
| top500_v6 ∩ baseline top 500 (exploit code, then EPSS) | 193 (v5: 190) |
| with an exploit flag: v6 / v5 / baseline | **498** / 431 / 500 |

v6's list is almost entirely flagged CVEs. Within them it ranks differently from the simple rule: it shares only 193 of
500 with it.

### Hits and bootstrap (`outputs/v6_bootstrap.csv`; 1,000 draws, CVE-level and event-clustered)
| test | v6 | v5 | best simple rule | v6 − rule (CVE / event 90%) | v6 − v5 (CVE / event 90%) |
|---|---|---|---|---|---|
| forward (train 2024 → test 2025) | **18** | 12 | 13 | +5 [0, +10] / [−2, +12] | +6 [+2, +10] / [+1, +12] |
| stability (train 2025 → test 2024) | 9 | 9 | 6 | +3 [0, +7] / [0, +7] | +0 [−2, +2] / [−2, +2] |
| pooled | **27** | 21 | 19 | +8 [+2, +14] / [+1, +15] | +6 [+2, +11] / [+1, +13] |

Single seeds give 26.75 pooled hits on average (min 25, max 28).

### Spread across the 4 seed sets (`outputs/v6_seed_spread.csv`)
| seeds | v6 forward / stability / pooled | v5 forward / stability / pooled | v6 − v5 |
|---|---|---|---|
| 0-19 | 18 / 9 / 27 | 12 / 9 / 21 | +6 |
| 1000-1019 | 18 / 10 / 28 | 15 / 9 / 24 | +4 |
| 2000-2019 | 18 / 8 / 26 | 12 / 9 / 21 | +5 |
| 3000-3019 | 18 / 9 / 27 | 15 / 10 / 25 | +2 |

v6's spread is 26 to 28 (2), against v5's 21 to 25 (4).

### Blind-spot view on the 75 (`outputs/v6_blindspots.csv`, same definition as the 44-of-75)
| year | group | exploited | simple rule | v5 | v6 |
|---|---|---|---|---|---|
| 2025 | flagged | 21 | 13 | 11 | 14 |
| 2025 | blind spot | 27 | 0 | 1 | **4** |
| 2024 | flagged | 10 | 6 | 8 | 8 |
| 2024 | blind spot | 17 | 0 | 1 | 1 |
| **blind spots total** | | **44** | **0** | **2** | **5** |

v6's blind-spot catches are CVE-2024-13159, CVE-2024-13160, CVE-2024-13161, CVE-2025-24472 and CVE-2024-23113. The
first three are one Ivanti EPM event, so they're one discovery rather than three.

### Placebo, like-for-like (`outputs/v6_placebo.csv`)
30 real 5-seed bags were compared with 30 bags trained on labels shuffled within each snapshot month.
- **Real:** mean 27.0 pooled hits (26 to 28).
- **Shuffled:** mean 0.57 (0 to 3).
- **Difference:** +26.4, one-sided bootstrap p < 0.001.

### Leakage experiment, same settings (`outputs/v6_leakage_results.csv`)
| arm | forward | stability | pooled |
|---|---|---|---|
| honest (v6 settings) | 18 | 9 | 27 |
| with banned after-the-fact columns | 21 | 12 | 33 |

The banned columns would add 6 hits that could never be delivered on 2026. v5's own experiment gave 21 → 28.

## 3. Headline candidate
`outputs/v6_headline_candidate.json` follows headline.json's schema and also has v6 vs v5 blocks. headline.json itself is
unchanged.

## 4. Explanations
**71** CVEs in top500_v6 are not in `outputs/explanations.csv`. They're listed with their v6 rank in
`outputs/v6_missing_explanations.csv`. They would need explanations (and a Guardian check) before v6 could be shipped.
