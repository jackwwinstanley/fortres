# IBM Breach – predicting which CVEs get exploited

Sheridan Datathon (IBM track). Rank 2026 CVEs by likelihood of landing on CISA's KEV list.

## Data
Not committed (too large). Download from the datathon Drive folder and unzip into `data/`.

## Setup
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Scripts
- `src/01_build_pool.py` – builds the 2024-01..2025-06 practice pool with 6-month forward labels and prints baseline scores.

## Columns used (time-safe only)
epss, exploitdb, metasploit, nuclei, poc_github, cvss3_score (baseline comparison).
