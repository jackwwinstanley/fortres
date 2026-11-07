# CONTRACT – handoff files between Person A and Person B

One owner per file. Never edit the other person's files. Validate with
`python scripts/check_contract.py` (schemas live in `src/common/schema.py`).

Note: small `.parquet` files (replicas, scoreboard/text/extracted features) **are tracked in git**
so the other person can pull them. `.npy` and `emb*` files (embeddings, hundreds of MB) are
**gitignored**; pass them through the shared drive. `top500_v*.csv`, `runlog.csv` and
`explanations.csv` are also tracked.

## Files

| Owner | Path | Columns / dtypes | Sort order |
|---|---|---|---|
| A | `outputs/replica_2024.parquet`, `outputs/replica_2025.parquet` | `cve_id` str, `published` date, `snapshot_month` str `YYYY-MM`, `epss` float (nullable), `exploitdb`/`metasploit`/`nuclei`/`poc_github` int8 0/1, `days_to_snapshot` int, `days_to_cutoff` int, `label` int8 0/1 | `snapshot_month`, `cve_id` |
| A | `outputs/scoreboard_features.parquet` | same as replicas minus `label` (incl. `days_to_snapshot`, `days_to_cutoff` measured to 2026-11-04); 72,670 rows, `cve_id` unique | `cve_id` |
| A | `outputs/features_replica_2024.parquet`, `features_replica_2025.parquet`, `features_scoreboard.parquet` | `cve_id`, `snapshot_month`, `published`, (`label` replicas only) + the 18 `ALLOWED_FEATURES` in `src/common/schema.py`; no description text | `cve_id` order of the source file |
| A | `outputs/top500_v1.csv`, `v1_report.md`, `v1_importances.csv`, `v1_top500_contrib.parquet` | v1 model outputs (`cve_id`+one column per feature for contributions) | rank order |
| B | `outputs/emb_small.npy` + `outputs/emb_ids.csv` | float32 matrix (N × d); `emb_ids.csv` has one column `cve_id`; row *i* of the matrix ↔ row *i* of the CSV. Write chunks as `emb_small_part{N}.npy`, then merge | row order = `emb_ids.csv` order |
| B | `outputs/text_features.parquet` | `cve_id` str (unique), `kev_text_score` float, `nearest_kev_sim` float, plus int8 flag columns prefixed `txt_` | `cve_id` |
| B (stretch) | `outputs/extracted_features.parquet` | `cve_id`, `product_type`, `auth_required`, `network_reachable`, `impact_type` (all str, nullable except `cve_id`) | `cve_id` |
| A | `outputs/top500_vN.csv` | single column `cve_id`, exactly 500 unique scoreboard IDs | best score first |
| A | `outputs/runlog.csv` | `timestamp, version, replica, k, hits, baseline_exploit_epss_hits, notes`; **append-only** | chronological |
| B | `outputs/explanations.csv` | `cve_id`, `reason` (one sentence) | `cve_id` |

## Exact replica definition (Person A, `python -m src.replicas`)
For Y in {2024, 2025}:
- **Pool:** CVEs in `vulnerabilities.csv` with `published` in Y-01-01..Y-09-30 (not from the signals files).
- **snapshot_month:** publish month `YYYY-MM`. (Real 2026 scoreboard uses July for June; Y=2024/25 June signals exist, so June is used.)
- **Signals:** left join `exploit_signals_Y` on `(cve_id, month == snapshot_month)`; no row -> `epss` NULL, flags 0.
- **Exclusion:** drop if signals `in_kev == 1` that month OR KEV `date_added` <= last day of snapshot month.
- **Label:** 1 if KEV `date_added` > last day of snapshot month AND <= Y-11-04, else 0.
- **days_to_snapshot** = last day of snapshot month - published; **days_to_cutoff** = Y-11-04 - last day of snapshot month.
- No description, CVSS or NVD-status columns are ever saved in these files (CVSS is joined only inside `src/baselines.py`).

Other tracked outputs: `positive_rate_by_month.csv`, `replica_report.md`, `replica_stats.json`, `baseline_results.json`.

## v1 features (Person A, `python -m src.features.build`)
All history features use the fixed prior-December-31 cutoff H above. Description text is read only to find
vendor mentions and is never saved.

| group | feature | definition | time-safety |
|---|---|---|---|
| signals | `epss`, `epss_missing` | snapshot-month EPSS (NaN kept) and a 0/1 missing flag | snapshot-month value |
| signals | `epss_rank_in_month` | percentile rank of `epss` within the same snapshot_month and the same pool, missing = 0 (absorbs the March 2025 EPSS model change) | uses only snapshot-month values |
| flags | `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_flags`, `any_exploit` | exploit-code flags at snapshot, count and max | snapshot-month value |
| timing | `days_to_snapshot`, `days_to_cutoff` | days from publish to end of snapshot month; days from snapshot-month end to Nov 4 | calendar arithmetic |
| assigner | `assigner_prior_cves` | log1p(CVEs the assigner published on or before H) | published <= H |
| assigner | `assigner_kev_count`, `assigner_kev_12m` | log1p(KEV CVEs of that assigner added <= H; added in the 12 months ending at H) | KEV `date_added` <= H |
| assigner | `assigner_kev_rate_smooth` | (kev_count + 20 * global_rate) / (prior_cves + 20); global_rate = KEV share of CVEs published <= H; unseen assigners get global_rate | as above |
| vendor | `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max` | whole-word (token-bounded, so `cisco` does not match `ciscoworks`) mentions in the description of vendors from the KEV `vendor` field (cleaned; vendors shorter than 4 characters and a short ambiguous-word stoplist are dropped and logged in `outputs/vendor_lexicon_dropped.csv`); max log1p KEV count (all-time <= H, last 12 months) among mentioned vendors | lexicon and counts from KEV `date_added` <= H |

`src/common/schema.py` holds `ALLOWED_FEATURES`, `BANNED_NAMES` and `tests/test_feature_guard.py` fails if a
model uses anything else. Model rules (`src/models/train_v1.py`): hyper-parameters are chosen by
leave-one-snapshot-month-out CV on the training replica only; nothing is tuned on a test replica;
model tie-break is score, then `epss_rank_in_month`, then `cve_id`. Ties at the cutoff are also reported as
tie-aware expected hits (`expected_hits_at_k`).

## v2 (text features) and two-channel allocation (Person A)
`ALLOWED_FEATURES` = the 18 v1 features + `TEXT_FEATURES` (`kev_text_score`, `nearest_kev_sim`, 14 `txt_*` flags from
`text_features.parquet`, joined by `cve_id`). `kev_text_score` and `nearest_kev_sim` are the only text-derived names containing
"kev" and are allowed because they obey the prior-December-31 cutoff above. Outputs: `outputs/top500_v2.csv` (single column
`cve_id`, 500 unique), `outputs/v2_report.md`, `outputs/depth_curves.csv`, `outputs/blindspot_positives.csv`
(descriptive only, never a feature). Two-channel allocation (`src/models/two_channel.py`): Channel A = exploit-then-EPSS order,
Channel B = mean of within-pool percentile ranks of `kev_text_score`, `assigner_kev_rate_smooth`, `vendor_kev_count_max`,
`nearest_kev_sim` (no fitting); top s from A then B fills the rest. Final list uses the s with the highest pooled hits over both
replicas, ties to the larger s.

## v3 stress tests and the final candidate (Person A)
`python -m src.models.stress_v2` runs the stress tests and applies a pre-declared policy: the primary candidate is v2 LightGBM
trained on both replicas (parameters from the pooled-AP selection); it is vetoed only if the placebo p-value exceeds 0.20, the
10-seed mean of pooled hits is below the best baseline's, or any leakage is found; a veto falls back to `top500_v2.csv`.
Outputs: `outputs/top500_v3.csv` (single column `cve_id`, 500 unique), `v3_report.md`, `v3_top500_contrib.parquet`
(`cve_id` + one LightGBM contribution column per feature of `ALLOWED_FEATURES`, same row order as `top500_v3.csv`),
`v2_mechanism.csv` (gained/lost hits with post-snapshot KEV vendor and dates, descriptive only, never a feature) and
`v2_placebo.csv`. The placebo shuffles the 16 text columns jointly across rows within each snapshot month.

### Text features must be time-safe (Person B)
`kev_text_score` and `nearest_kev_sim` for a CVE in snapshot month *M* may only use KEV
entries with `date_added` ≤ end of month *M* (e.g. fit/compare against the KEV set as of the
snapshot, never the full KEV list). For replicas, compute per snapshot with the KEV set
frozen at that date; for scoreboard CVEs use KEV known at the 2026 snapshot. Any model fitted on
text (e.g. a classifier) is trained on earlier months only. Document the exact cut-off logic in
the script header and `README.md`. `txt_*` flags are regexes on the description only.

## ALLOWED columns (known at snapshot time)
`description`, `assigner`, `published`, snapshot-month `epss`, `exploitdb`, `metasploit`,
`nuclei`, `poc_github`, `days_since_publish` at snapshot, and vendor/assigner history computed
**only from KEV entries added BEFORE the snapshot**.

## BANNED for the honest model (can leak)
`nvd_status`, `n_affected_cpes`, `n_references`, blank-vs-filled severity scores,
`cvss3_source == nvd@nist.gov` scores, `references.csv` links, NIST-filled `cwe_ids` and
`affected_products` for new CVEs, anything from KEV added after the snapshot, any 2026 KEV
info. These may only be used in a clearly labelled **leakage experiment**.

## History-cutoff rule (all KEV-based history features)
History features (KEV counts by assigner or vendor, KEV-based text features) are computed as of a
**fixed cutoff: December 31 of the year BEFORE the pool year**.
- replica 2024 -> KEV rows with `date_added` <= 2023-12-31
- replica 2025 -> KEV rows with `date_added` <= 2024-12-31
- 2026 scoreboard -> KEV rows with `date_added` <= 2025-12-31 (the KEV file ends there; no 2026 KEV information may ever be used)
`nearest_kev_sim` and any other KEV-based text feature use the same prior-December-31 cutoff, and the
text classifier is trained only on CVEs published before 2024.

## Scoring rule
`k = round(500 * pool_size / 72670)`; `hits` = labelled positives in the top `k` by score;
ties broken by `cve_id` ascending (deterministic). Implemented in `src/common/scoring.py`.

## Workflow rules
- One owner per file. Person A: replicas, scorer, baselines, features, LightGBM, leakage tests,
  top500 files. Person B: Granite embeddings, text features, explanations, charts, Streamlit
  dashboard, write-up.
- Branches: `a/model` (A), `b/granite` (B). Merge to `main` only when `pytest` and
  `python scripts/check_contract.py` pass.
- Pull hourly. Never rewrite shared history (no force-push to `main`, no rebasing pushed commits).
