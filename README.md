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
### Text features (Person B, `outputs/text_features.parquet`)
Run `python -m src.b.texts && python -m src.b.embed && python -m src.b.text_features`
(about 2 min on a Mac; the embeddings are not committed). Then `python -m src.b.report --label ...`
writes `outputs/b_text_report.md`.
- Text: only `description` and `published` from `vulnerabilities.csv`. Post-attack phrases
  ("exploited in the wild", "actively exploited", ...; `src/b/phrases.py`) are removed **before**
  embedding with `ibm-granite/granite-embedding-30m-english`.
- `kev_text_score`: for pool year Y, a logistic regression on embeddings is trained on CVEs published
  before Y-01-01, labelled by KEV `date_added` <= (Y-1)-12-31.
- `nearest_kev_sim`: max cosine similarity to KEV entries with `date_added` <= (Y-1)-12-31
  (2023-12-31 for replica 2024, 2024-12-31 for replica 2025, 2025-12-31 for the 2026 scoreboard).
- `txt_*`: int8 regex flags on the description (RCE, unauthenticated, edge device, ...).
