# Plan: an older year the model never saw (2023) — written and committed BEFORE any result

One run, no tuning, no variant choice. Reported whatever the result. This is a back-test, **not forward in time**: the model is
trained on later years (2024 and 2025) and tested on an earlier one.

**Caveat, stated first.** The competition data has no 2023 monthly signals, so the 2023 signals are **rebuilt from outside data**. It
is not a perfect replica of how the 2024 and 2025 pools were built, and a fidelity check (below) measures how close the recipe gets.

## Pool and label (same as src.replicas.build_replica, year = 2023)
- CVEs in `data/vulnerabilities.csv` published 2023-01-01 to 2023-09-30; the snapshot is the publish month.
- Excluded if already in KEV by the end of the snapshot month.
- Label: 1 if KEV `date_added` is after the end of the snapshot month and on or before 2023-11-04 (`data/known_exploited.csv`).
- k = `k_for_pool(pool size)`, the same scaling rule (500 per 72,670 CVEs).

## Rebuilt 2023 signals (date rule: nothing dated after the end of the snapshot month)
| column | source | date rule |
|---|---|---|
| epss | FIRST EPSS daily archive, https://epss.empiricalsecurity.com (formerly epss.cyentia.com) | file for the last day of the snapshot month; if missing, the nearest earlier day, never later |
| exploitdb | Exploit-DB `files_exploits.csv` (https://gitlab.com/exploit-database/exploitdb, CVE ids in `codes`) | later of `date_published` and `date_added` <= month end |
| metasploit | rapid7/metasploit-framework, full git history | author date of the commit that added the CVE's reference to the module (git pickaxe), as in PR #58 <= month end |
| nuclei | `outputs/newdata_nuclei_first_added.csv` (PR #58: git first-added dates; invalid and bulk dates excluded) | first-added date <= month end |
| poc_github | nomi-sec/PoC-in-GitHub | repo `created_at` <= month end |
| in_kev | `data/known_exploited.csv` | `date_added` <= month end |

A flag with no dated record is 0. EPSS caveat: EPSS v3 launched on 2023-03-07, so January and February use the older model; the
within-month rank feature absorbs the scale.

## Other features (same code as 2024 and 2025)
- `src.features.build.build_features` with history cutoff **2022-12-31** (assigner and vendor KEV history use only KEV additions by then).
- Text: `kev_text_score` (logistic regression on Granite embeddings of CVEs published before 2023-01-01, labelled by KEV <= 2022-12-31, targets excluded), `nearest_kev_sim` (KEV <= 2022-12-31), `txt_*` regexes. Missing 2023 descriptions are embedded locally with the same model and text cleaning (`src.b.texts`, `src.b.embed`).
- `drift_fix.to_v5` transforms within the 2023 pool. No banned column.

## Models and comparisons
Training data: the 2024 and 2025 replicas combined (labels and features as committed).
| method | definition |
|---|---|
| v6 | 20-seed rank-averaged bag, v5 features, `final_params` from `outputs/headline.json` (unchanged) |
| v5 | 20-seed bag, v5's own final settings (`v1.select_lgbm` on both replicas, month folds, unchanged) |
| simple rule | public exploit first, then EPSS |
| EPSS alone | within-month EPSS rank |
| severity | highest CVSS 3 score first |
| random | expected value |

Tie-breaks as in the existing scorer.

## Metric and intervals
Hits in the top k. Paired bootstrap of v6 minus each method: CVE-level and event-clustered (KEV vendor + date), 1,000 draws, seed 0, 90%
percentile intervals. Also reported: positives, distinct vendor/date events, recall, precision, lift versus chance, and the depth each
ranking needs to match v6's hits.

## Placebo
v6 trained on labels shuffled within each snapshot month of the training data, 30 five-seed bags, against 30 real five-seed bags.

## Fidelity check (run before the 2023 run; not tuning)
The same recipe rebuilds the 2024 pool's signals, compared with `data/exploit_signals_2024.csv`: agreement on EPSS (equal at 5 decimals, and
correlation) and on each flag. The recipe is not changed after seeing the check or the 2023 result.

## Outputs
`outputs/extra_year_eval.csv`, `outputs/extra_year_report.md`, `src/b/extra_year.py`, a test. No list, model or `headline.json` changes.
Downloads stay under the gitignored `data/outside/` and `~/ibm/ext/`.
