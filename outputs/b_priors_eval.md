# Do the new track-record priors help v5? (Person B)

Same v5 data, parameter rule, 20-seed bag, tie rule and k as `src/models/train_v5.py`; only extra columns differ (within-pool percentile ranks). LOW POWER: 75 positives.

| variant | test 2025 | test 2024 | pooled (bag) | single seeds: mean (min-max) | vs v5, 90% paired bootstrap |
|---|---|---|---|---|---|
| v5 | 12 | 9 | 21 | 21.75 (17-25) |  |
| v5 + knn | 14 | 9 | 23 | 20.95 (18-26) | +2 [-1, +5] |
| v5 + product | 12 | 9 | 21 | 21.15 (18-24) | +0 [+0, +0] |
| v5 + both | 15 | 9 | 24 | 21.6 (17-24) | +3 [+1, +7] |
