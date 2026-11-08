"""Validate a top500 submission file.  Usage: python scripts/check_top500.py <path> [--scoreboard PATH]"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd  # noqa: E402

from src.common.paths import SCOREBOARD_CSV, require_data  # noqa: E402


def check(path, scoreboard=SCOREBOARD_CSV, n=500) -> list[str]:
    """Return a list of problems (empty list = PASS)."""
    problems = []
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as e:  # unreadable / empty
        return [f"cannot read file: {e}"]
    if list(df.columns) != ["cve_id"]:
        problems.append(f"header must be exactly ['cve_id'], got {list(df.columns)}")
        if "cve_id" not in df.columns:
            return problems
    ids = df["cve_id"]
    if len(ids) != n:
        problems.append(f"expected {n} rows, got {len(ids)}")
    if ids.duplicated().any():
        problems.append(f"{int(ids.duplicated().sum())} duplicate IDs")
    if (ids != ids.str.strip()).any() or (ids == "").any():
        problems.append("whitespace or empty IDs found")
    valid = set(pd.read_csv(scoreboard, usecols=["cve_id"], dtype=str)["cve_id"])
    unknown = sorted(set(ids.str.strip()) - valid)
    if unknown:
        problems.append(f"{len(unknown)} IDs not in scoreboard, e.g. {unknown[:3]}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--scoreboard", default=SCOREBOARD_CSV)
    a = ap.parse_args()
    require_data(a.scoreboard)
    problems = check(a.path, a.scoreboard)
    if problems:
        print(f"FAIL {a.path}")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print(f"PASS {a.path}")


if __name__ == "__main__":
    main()
