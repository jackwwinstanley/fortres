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
