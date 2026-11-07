# LEAKAGE EXPERIMENT (issue #8). Not a submission model.

Same data, v4 features, parameter rule and 20-seed bag as the v4 headline model; the leaky model also gets banned after-the-fact columns (NVD status, CPE/reference counts, blank-vs-filled CVSS/CWE, NVD CVSS, exploit-tagged reference links). Run: `python -m src.b.leakage`.

## In plain words
- Honest model: **21** exploited CVEs caught across both practice years. With banned columns: **29** (+38%).
- Banned columns carry **40%** of the leaky model's split gain. The biggest: `leak_nvd_status_analyzed`, `leak_nvd_cvss3_score`, `leak_n_references`.
- That gap is what a model would claim but could never deliver on 2026, because at the snapshot those fields were not filled in yet. This is why the contract bans them.

## Hits (top k), per test year

| direction          | model                   |   k |   positives |   hits |   expected |   ci_lo |   ci_hi |     ap |
|:-------------------|:------------------------|----:|------------:|-------:|-----------:|--------:|--------:|-------:|
| train2024_test2025 | CVSS 3 first            | 243 |          48 |      5 |       5.12 |       1 |       9 | 0.0063 |
| train2024_test2025 | EPSS first              | 243 |          48 |      8 |       8    |       4 |      13 | 0.0322 |
| train2024_test2025 | Exploit code, then EPSS | 243 |          48 |     13 |      13    |       8 |      20 | 0.048  |
| train2024_test2025 | honest                  | 243 |          48 |     12 |      12    |       7 |      19 | 0.0626 |
| train2024_test2025 | leaky                   | 243 |          48 |     17 |      17    |      10 |      24 | 0.1204 |
| train2025_test2024 | CVSS 3 first            | 198 |          27 |      0 |       0.26 |       0 |       0 | 0.003  |
| train2025_test2024 | EPSS first              | 198 |          27 |      3 |       3    |       1 |       6 | 0.0147 |
| train2025_test2024 | Exploit code, then EPSS | 198 |          27 |      6 |       6    |       2 |      10 | 0.0242 |
| train2025_test2024 | honest                  | 198 |          27 |      9 |       9    |       4 |      14 | 0.0428 |
| train2025_test2024 | leaky                   | 198 |          27 |     12 |      12    |       7 |      18 | 0.1499 |

## Leaky model: share of split gain (mean of both directions)

|                                  |   gain share |
|:---------------------------------|-------------:|
| assigner_kev_rate_smooth_pctrank |        0.159 |
| leak_nvd_status_analyzed         |        0.13  |
| n_flags                          |        0.1   |
| leak_nvd_cvss3_score             |        0.086 |
| leak_n_references                |        0.077 |
| kev_text_score                   |        0.06  |
| assigner_prior_cves_pctrank      |        0.057 |
| leak_n_affected_cpes             |        0.047 |
| leak_refs_tagged_exploit         |        0.043 |
| nearest_kev_sim                  |        0.039 |
| days_to_cutoff_pctrank           |        0.03  |
| txt_enterprise                   |        0.022 |
| days_to_snapshot                 |        0.02  |
| epss_rank_in_month               |        0.018 |
| poc_github                       |        0.017 |

LOW POWER: 27 and 48 positives; ranges are 90% paired bootstrap.