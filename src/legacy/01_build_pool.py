"""Step 1: build the practice pool (2024-01 .. 2025-06) and score baselines.

For each snapshot month, the pool holds CVEs that were PUBLISHED that month and
were NOT yet in KEV at the snapshot. Label = 1 if CISA added the CVE to KEV
within the following 6 months. Only time-safe columns are kept as features.

Run from the project root:  python src/01_build_pool.py
"""
from pathlib import Path

import duckdb
import pandas as pd

D = Path("data")
OUT = Path("outputs")
OUT.mkdir(exist_ok=True)

FIRST_MONTH, LAST_MONTH = "2024-01", "2025-06"  # last month leaves a full 6-month window
TOP_FRAC = 500 / 72670  # judges' cut: top 500 of 72,670 (~0.69%)

con = duckdb.connect()

# --- 1. sanity check: files load and row counts look right -------------------
for name in ["vulnerabilities", "known_exploited", "exploit_signals_2024",
             "exploit_signals_2025", "scoreboard_2026"]:
    n = con.execute(f"SELECT count(*) FROM read_csv_auto('{D}/{name}.csv')").fetchone()[0]
    print(f"{name:24s} {n:>9,} rows")

# --- 2. views over the raw files ---------------------------------------------
con.execute(f"""
CREATE VIEW vuln AS
  SELECT cve_id, CAST(published AS DATE) AS published, cvss3_score
  FROM read_csv_auto('{D}/vulnerabilities.csv');

CREATE VIEW kev AS
  SELECT cve_id, CAST(date_added AS DATE) AS date_added
  FROM read_csv_auto('{D}/known_exploited.csv');

CREATE VIEW sig AS
  SELECT * FROM read_csv_auto(
    ['{D}/exploit_signals_2024.csv', '{D}/exploit_signals_2025.csv'],
    types={{'month': 'VARCHAR'}});
""")

# --- 3. the pool with forward-looking labels ---------------------------------
con.execute(f"""
CREATE TABLE pool AS
SELECT s.month, s.cve_id, v.published,
       s.epss, s.exploitdb, s.metasploit, s.nuclei, s.poc_github, v.cvss3_score,
       COALESCE(
         k.date_added >  last_day(CAST(s.month || '-01' AS DATE))
         AND k.date_added <= CAST(last_day(CAST(s.month || '-01' AS DATE))
                                  + INTERVAL 6 MONTH AS DATE),
         FALSE)::INT AS label
FROM sig s
JOIN vuln v USING (cve_id)
LEFT JOIN kev k USING (cve_id)
WHERE strftime(v.published, '%Y-%m') = s.month
  AND s.in_kev = 0
  AND s.month BETWEEN '{FIRST_MONTH}' AND '{LAST_MONTH}';
""")
df = con.execute("SELECT * FROM pool").df()
df.to_csv(OUT / "pool.csv", index=False)

print(f"\nPool: {len(df):,} CVEs, {df.label.sum()} positives "
      f"({df.label.mean():.3%} base rate)")
print(df.groupby("month").label.agg(["size", "sum"]).rename(
    columns={"size": "cves", "sum": "attacked"}).to_string())

# --- 4. baselines: how many attacked CVEs land in the top 0.69%? -------------
df["any_exploit"] = df[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1)
k = max(1, int(len(df) * TOP_FRAC))


def hits(frame: pd.DataFrame, by, asc=False) -> int:
    return int(frame.sort_values(by, ascending=asc, kind="stable").head(k).label.sum())


print(f"\nBaselines: top {k} of {len(df):,} ({TOP_FRAC:.2%}); "
      f"{df.label.sum()} positives available")
print(f"  CVSS v3 only       : {hits(df.fillna({'cvss3_score': 0}), 'cvss3_score')}")
print(f"  EPSS only          : {hits(df, 'epss')}")
print(f"  exploit code + EPSS: {hits(df, ['any_exploit', 'epss'])}")
