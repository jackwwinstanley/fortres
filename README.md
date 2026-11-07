# IBM "Before the Breach" – predicting which CVEs get exploited

Sheridan Datathon 2026. Rank the 72,670 CVEs in `data/scoreboard_2026.csv` and submit
`top500.csv` (one column `cve_id`, 500 unique IDs). Judges count how many were added to
CISA KEV by 2026-11-04. Only information known at the snapshot may be used; see `CONTRACT.md`.

## Run
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# put the datathon CSVs in ./data (not committed)
pytest -q
python scripts/check_contract.py
python scripts/check_top500.py outputs/top500_v1.csv
```

## Layout
`src/common/` shared paths, schema, scoring · `src/legacy/` first practice-pool script ·
`scripts/` validators · `tests/` · `outputs/` handoff files · `notebooks/`

## Columns used (v1, allowed columns only; see CONTRACT.md)
- **signals:** `epss`, `epss_missing`, `epss_rank_in_month`
- **exploit flags:** `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_flags`, `any_exploit`
- **timing:** `days_to_snapshot`, `days_to_cutoff`
- **assigner history** (KEV as of Dec 31 of the previous year): `assigner_prior_cves`, `assigner_kev_count`, `assigner_kev_12m`, `assigner_kev_rate_smooth`
- **vendor history** (same cutoff): `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max`

Not used by the model: `nvd_status`, `n_affected_cpes`, `n_references`, CVSS (baseline only), `cwe_ids`, references, affected products, any 2026 KEV information.
Results and caveats (low power: 75 positives): `outputs/v1_report.md`. Run: `python -m src.replicas && python -m src.features.build && python -m src.models.train_v1`.
