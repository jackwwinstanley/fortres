"""Write the two sample files for the "Rank a dataset" page into app/samples/ (gitignored) from data/scoreboard_2026.csv.

Run:  python scripts/make_app_samples.py
One month of 2026 (May) and 2,000 rows drawn with a fixed seed, with the scoreboard's own columns only.
"""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MONTH, N, SEED = "2026-05", 2000, 0
ONE_MONTH, RANDOM = "2026_one_month_2026-05.csv", "2026_random_2000.csv"


def main(scoreboard: Path = ROOT / "data" / "scoreboard_2026.csv", out: Path = ROOT / "app" / "samples") -> int:
    if not Path(scoreboard).exists():
        print("needs data/scoreboard_2026.csv (competition data, not in the repo): put the datathon CSVs in ./data", file=sys.stderr)
        return 2
    s = pd.read_csv(scoreboard)
    out.mkdir(parents=True, exist_ok=True)
    m = s[s["snapshot_month"] == MONTH]
    m.to_csv(out / ONE_MONTH, index=False)
    r = s.sample(min(N, len(s)), random_state=SEED).sort_values("cve_id")
    r.to_csv(out / RANDOM, index=False)
    print(f"wrote app/samples/{ONE_MONTH} ({len(m):,} rows) and app/samples/{RANDOM} ({len(r):,} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
