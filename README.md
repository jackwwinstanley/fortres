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

## Columns used
TODO
