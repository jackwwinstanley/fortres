# Person B text features: replica evaluation

ROC AUC and hits@k (k = round(500 * pool / 72670)) on each held-out replica year.
Produced by `python -m src.b.report`.

## Replica 2024 (pool 28,839, 27 positives, k = 198)

| run | kev_text_score AUC | kev_text_score hits | nearest_kev_sim AUC | nearest_kev_sim hits |
|---|---|---|---|---|
| 1. original (month-end KEV cutoff, unstripped text) | 0.8210 | 2 | 0.7831 | 4 |
| 2. year KEV cutoff, unstripped text | 0.8210 | 2 | 0.7583 | 3 |
| 3. year KEV cutoff, phrases stripped before embedding | 0.8188 | 2 | 0.7588 | 3 |

## Replica 2025 (pool 35,280, 48 positives, k = 243)

| run | kev_text_score AUC | kev_text_score hits | nearest_kev_sim AUC | nearest_kev_sim hits |
|---|---|---|---|---|
| 1. original (month-end KEV cutoff, unstripped text) | 0.8045 | 0 | 0.7084 | 2 |
| 2. year KEV cutoff, unstripped text | 0.8045 | 0 | 0.6931 | 2 |
| 3. year KEV cutoff, phrases stripped before embedding | 0.8041 | 2 | 0.6909 | 2 |
