# Method zoo summary (b/zoo)

Generated 2026-11-08T05:06:48+00:00 by `python -m src.b.zoo.aggregate` from `outputs/zoo/*.csv`. Harness: `src/b/zoo/harness.py` (frozen in its own commit before any method ran). Features: frozen v5. Forward = train 2024 -> test 2025 (k = 243, 48 positives); stability = train 2025 -> test 2024 (k = 198, 27 positives); pooled = sum. Hits = KEV positives in the top k (ties: EPSS rank, then cve_id). LOW POWER: 75 positives in total.

## Baselines (20-seed bags, per-seed scores cached)

| baseline | seed set | forward | stability | pooled |
|---|---|---|---|---|
| v5 | 0-19 | 12 | 9 | 21 |
| v5 | 1000-1019 | 15 | 9 | 24 |
| v5 | 2000-2019 | 12 | 9 | 21 |
| v5 | 3000-3019 | 15 | 10 | 25 |
| I | 0-19 | 18 | 9 | 27 |
| I | 1000-1019 | 18 | 10 | 28 |
| I | 2000-2019 | 18 | 8 | 26 |
| I | 3000-3019 | 18 | 9 | 27 |

I's pooled spread over the 4 seed sets (measured): **2**. Screening gain threshold = max(2, spread) = **2**.

## Rules (fixed before any result)

- Screening (seeds 0-19): forward >= I's forward, stability >= I's stability, pooled gain over I >= 2.
- Confirmation: survivor re-run on seed sets 1000-1019, 2000-2019, 3000-3019 (deterministic methods: their blend with I re-run too); must beat I's pooled on all three and not lose forward in any.
- Tie-break: m19, m09, m11, m12, m02, m18, m07, m01, m06, m03, m08. Nothing adopted after 2:30 AM EST. 'Adopted' = named here only; no list or doc regenerated.
- Feature coverage on the 2026 scoreboard = share of rows where the feature differs from its most common training value; 0 -> rejected.

## Results (seeds 0-19): forward first, then stability, then pooled; delta vs I with 90% paired-bootstrap interval

| method | variant | forward (I) | stability (I) | pooled (I) | delta vs I pooled [90%] | fwd random-tie hits | 2026 coverage | status |
|---|---|---|---|---|---|---|---|---|
| m19_adversarial | I_plus_feature | 18 (18) | 9 (9) | 27 (27) | +0 [-2, +1] | 18.0 | p_2026_like 100% | failed screening |
| m19_adversarial | blend_I | 18 (18) | 7 (9) | 25 (27) | -2 [-6, +0] | 18.0 | n/a | failed screening |
| m19_adversarial | standalone | 17 (18) | 7 (9) | 24 (27) | -3 [-6, -1] | 17.0 | n/a | failed screening |
| m09_prototypes | I_plus_feature | 18 (18) | 8 (9) | 26 (27) | -1 [-4, +0] | 18.0 | proto_max 100%, proto_top3 100% | failed screening |
| m09_prototypes | blend_I | 5 (18) | 4 (9) | 9 (27) | -18 [-26, -11] | 5.0 | n/a | failed screening |
| m09_prototypes | standalone | 1 (18) | 3 (9) | 4 (27) | -23 [-32, -15] | 1.0 | proto_max 100%, proto_top3 100% | failed screening |
| m11_regex | I_plus_feature | 18 (18) | 10 (9) | 28 (27) | +1 [+0, +3] | 18.0 | rx_count 23%, rx_any 23% | failed screening |
| m11_regex | blend_I | 5 (18) | 1 (9) | 6 (27) | -21 [-29, -13] | 5.0 | n/a | failed screening |
| m11_regex | standalone | 0 (18) | 0 (9) | 0 (27) | -27 [-36, -19] | 0.0 | rx_count 23%, rx_any 23% | failed screening |
| m12_tfidf | I_plus_feature | 18 (18) | 9 (9) | 27 (27) | +0 [-2, +1] | 18.0 | tfidf_lr 100% | failed screening |
| m12_tfidf | blend_I | 10 (18) | 5 (9) | 15 (27) | -12 [-19, -6] | 10.0 | n/a | failed screening |
| m12_tfidf | standalone | 6 (18) | 2 (9) | 8 (27) | -19 [-27, -12] | 6.0 | tfidf_lr 100% | failed screening |
| m02_cwe_eb | I_plus_feature | 16 (18) | 9 (9) | 25 (27) | -2 [-5, +0] | 16.0 | cwe_eb_rate 100% | failed screening |
| m02_cwe_eb | blend_I | 8 (18) | 6 (9) | 14 (27) | -13 [-20, -6] | 8.0 | n/a | failed screening |
| m02_cwe_eb | standalone | 0 (18) | 1 (9) | 1 (27) | -26 [-35, -18] | 0.45 | cwe_eb_rate 100% | failed screening |
| m18_balanced_bag | blend_I | 7 (18) | 3 (9) | 10 (27) | -17 [-27, -12] | 7.0 | n/a | failed screening |
| m18_balanced_bag | standalone | 3 (18) | 2 (9) | 5 (27) | -22 [-31, -14] | 3.0 | n/a | failed screening |
| m07_extratrees | blend_I | 15 (18) | 10 (9) | 25 (27) | -2 [-6, +1] | 15.0 | n/a | failed screening |
| m07_extratrees | standalone | 13 (18) | 8 (9) | 21 (27) | -6 [-12, +0] | 13.0 | n/a | failed screening |
| m01_elasticnet | blend_I | 18 (18) | 9 (9) | 27 (27) | +0 [-7, +3] | 18.0 | n/a | failed screening |
| m01_elasticnet | standalone | 13 (18) | 9 (9) | 22 (27) | -5 [-11, +1] | 13.0 | n/a | failed screening |
| m06_mean_minus_sd | blend_I | 18 (18) | 9 (9) | 27 (27) | +0 [-2, +0] | 18.0 | n/a | failed screening |
| m06_mean_minus_sd | standalone | 18 (18) | 9 (9) | 27 (27) | +0 [-2, +0] | 18.0 | n/a | failed screening |
| m03_cox | blend_I | 18 (18) | 9 (9) | 27 (27) | +0 [-3, +2] | 18.0 | n/a | failed screening |
| m03_cox | standalone | 16 (18) | 7 (9) | 23 (27) | -4 [-10, +0] | 16.0 | n/a | failed screening |
| m08_isoforest | I_plus_feature | 16 (18) | 7 (9) | 23 (27) | -4 [-8, -1] | 16.0 | iso_anomaly 100% | failed screening |
| m08_isoforest | blend_I | 16 (18) | 8 (9) | 24 (27) | -3 [-7, +0] | 16.0 | n/a | failed screening |
| m08_isoforest | standalone | 13 (18) | 6 (9) | 19 (27) | -8 [-14, -1] | 13.0 | iso_anomaly 100% | failed screening |

## Confirmation

No method variant passed screening, so nothing was re-run for confirmation.

## Adoption

**No survivor.** Nothing in the zoo passes screening and confirmation; I (and the v6 list) stay as they are.

## Runs attempted and failures

Runs attempted (every row in outputs/zoo/m*.csv, including failures and confirmation re-runs): **31** (28 distinct method x variant x seed set).

- 2026-11-08T05:01:24+00:00 m09_prototypes / standalone / seeds 0-19: process exited with code -11 (see log) (superseded: re-run after a fix and completed)
- 2026-11-08T05:01:24+00:00 m09_prototypes / blend_I / seeds 0-19: process exited with code -11 (see log) (superseded: re-run after a fix and completed)
- 2026-11-08T05:01:24+00:00 m09_prototypes / I_plus_feature / seeds 0-19: process exited with code -11 (see log) (superseded: re-run after a fix and completed)

## Checks

- m02 CWE missingness by nvd_status (check only, never a feature): `outputs/zoo/m02_cwe_missingness_check.csv`.
- Leak rules: methods see only v5 features, description text, CWE ids (m02), snapshot EPSS/exploit flags and in-fold labels; label-dependent steps (chi-square, CWE shrinkage, TF-IDF model, Cox, inner CV) fit on the training year only, feature-variant training rows leave-one-month-out. m19's discriminator is label-blind (training year vs 2026 scoreboard).
