"""Build the 2024 and 2025 benchmark replicas, mirroring how the 2026 scoreboard is scored.

Run:  python -m src.replicas

Replica definition for year Y (see CONTRACT.md):
  pool       CVEs in vulnerabilities.csv published Y-01-01..Y-09-30 (NOT from the signals files)
  snapshot   publish month (YYYY-MM). The real 2026 scoreboard uses July for June because June
             2026 signals are missing; Y=2024/2025 June signals exist, so we use June.
  signals    left join exploit_signals_Y on (cve_id, month == snapshot_month); no row -> epss NULL, flags 0
  exclusion  drop if signals in_kev==1 for that month OR KEV date_added <= end of snapshot month
  label      1 if KEV date_added in (end of snapshot month, Y-11-04], else 0
Only time-safe columns are written (no description / CVSS / NVD status / references).
"""
import json
from pathlib import Path

import duckdb
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR, SCOREBOARD_CSV
from src.common.schema import FEATURE_COLS, REPLICA_COLS
from src.common.scoring import TOTAL_SCOREBOARD

YEARS = (2024, 2025)
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


def _finalize(df: pd.DataFrame, cols: dict) -> pd.DataFrame:
    """Cast to the contract dtypes."""
    df = df.copy()
    df["published"] = pd.to_datetime(df["published"]).dt.date
    for c in FLAGS + ["label"]:
        if c in df:
            df[c] = df[c].astype("int8")
    for c in ("days_to_snapshot", "days_to_cutoff"):
        df[c] = df[c].astype("int32")
    df["epss"] = df["epss"].astype("float64")
    return df[list(cols)]


def build_replica(year, vuln_csv, kev_csv, signals_csv, con=None):
    """Return (replica DataFrame, stats dict). Paths are parameters so tests can use synthetic CSVs."""
    con = con or duckdb.connect()
    start, end, cutoff = f"{year}-01-01", f"{year}-09-30", f"{year}-11-04"
    con.execute(f"""
    CREATE OR REPLACE TEMP TABLE base AS
    SELECT cve_id, CAST(published AS DATE) AS published,
           strftime(CAST(published AS DATE), '%Y-%m') AS snapshot_month,
           last_day(CAST(published AS DATE)) AS eom
    FROM read_csv_auto('{vuln_csv}', all_varchar=true)
    WHERE CAST(published AS DATE) BETWEEN DATE '{start}' AND DATE '{end}';

    CREATE OR REPLACE TEMP TABLE kev AS
    SELECT cve_id, MIN(CAST(date_added AS DATE)) AS date_added
    FROM read_csv_auto('{kev_csv}', all_varchar=true) GROUP BY cve_id;

    CREATE OR REPLACE TEMP TABLE sig AS
    SELECT cve_id, month, TRY_CAST(epss AS DOUBLE) AS epss,
           TRY_CAST(in_kev AS INTEGER) AS in_kev,
           TRY_CAST(exploitdb AS INTEGER) AS exploitdb, TRY_CAST(metasploit AS INTEGER) AS metasploit,
           TRY_CAST(nuclei AS INTEGER) AS nuclei, TRY_CAST(poc_github AS INTEGER) AS poc_github
    FROM read_csv_auto('{signals_csv}', all_varchar=true);

    CREATE OR REPLACE TEMP TABLE j AS
    SELECT b.cve_id, b.published, b.snapshot_month, b.eom,
           s.cve_id IS NOT NULL AS has_signal, s.epss,
           COALESCE(s.exploitdb, 0) AS exploitdb, COALESCE(s.metasploit, 0) AS metasploit,
           COALESCE(s.nuclei, 0) AS nuclei, COALESCE(s.poc_github, 0) AS poc_github,
           COALESCE(s.in_kev, 0) = 1 AS sig_kev,
           COALESCE(k.date_added <= b.eom, FALSE) AS date_kev,
           k.date_added AS kev_date
    FROM base b
    LEFT JOIN sig s ON s.cve_id = b.cve_id AND s.month = b.snapshot_month
    LEFT JOIN kev k ON k.cve_id = b.cve_id;
    """)
    n_base = con.execute("SELECT count(*), count(DISTINCT cve_id) FROM base").fetchone()
    n_j = con.execute("SELECT count(*) FROM j").fetchone()[0]
    assert n_base[0] == n_base[1], "duplicate cve_id in vulnerabilities.csv"
    assert n_j == n_base[0], "join fanned out: duplicate (cve_id, month) rows in signals or KEV"

    sig_only, date_only, both = con.execute(
        "SELECT count(*) FILTER (WHERE sig_kev AND NOT date_kev),"
        " count(*) FILTER (WHERE date_kev AND NOT sig_kev),"
        " count(*) FILTER (WHERE sig_kev AND date_kev) FROM j").fetchone()
    df = con.execute(f"""
    SELECT cve_id, published, snapshot_month, epss, exploitdb, metasploit, nuclei, poc_github,
           (eom - published) AS days_to_snapshot,
           (DATE '{cutoff}' - eom) AS days_to_cutoff,
           CAST(COALESCE(kev_date > eom AND kev_date <= DATE '{cutoff}', FALSE) AS TINYINT) AS label,
           has_signal
    FROM j WHERE NOT (sig_kev OR date_kev)
    ORDER BY snapshot_month, cve_id""").df()
    no_signal = df.loc[~df.pop("has_signal").astype(bool)].groupby("snapshot_month").size()
    df = _finalize(df, REPLICA_COLS)
    stats = {
        "year": year, "pool_before_exclusion": int(n_base[0]),
        "dropped_signal_only": int(sig_only), "dropped_date_only": int(date_only),
        "dropped_both": int(both), "kept": len(df), "positives": int(df["label"].sum()),
        "no_signal_by_month": {k: int(v) for k, v in no_signal.items()},
        "pool_by_month": {k: int(v) for k, v in df.groupby("snapshot_month").size().items()},
    }
    return df, stats


def build_scoreboard_features(scoreboard_csv=SCOREBOARD_CSV, con=None, expected_rows=TOTAL_SCOREBOARD):
    con = con or duckdb.connect()
    df = con.execute(f"""
    SELECT cve_id, CAST(published AS DATE) AS published, snapshot_month,
           TRY_CAST(epss AS DOUBLE) AS epss,
           COALESCE(TRY_CAST(exploitdb AS INTEGER), 0) AS exploitdb,
           COALESCE(TRY_CAST(metasploit AS INTEGER), 0) AS metasploit,
           COALESCE(TRY_CAST(nuclei AS INTEGER), 0) AS nuclei,
           COALESCE(TRY_CAST(poc_github AS INTEGER), 0) AS poc_github,
           (last_day(CAST(snapshot_month || '-01' AS DATE)) - CAST(published AS DATE)) AS days_to_snapshot,
           (DATE '2026-11-04' - last_day(CAST(snapshot_month || '-01' AS DATE))) AS days_to_cutoff
    FROM read_csv_auto('{scoreboard_csv}', all_varchar=true) ORDER BY cve_id""").df()
    assert len(df) == expected_rows, f"scoreboard has {len(df)} rows, README says {expected_rows}"
    assert df["cve_id"].is_unique, "duplicate cve_id in scoreboard"
    return _finalize(df, FEATURE_COLS)


def main(data_dir: Path = DATA_DIR, out_dir: Path = OUT_DIR):
    out_dir.mkdir(exist_ok=True)
    con = duckdb.connect()
    all_stats, rate_rows = {}, []
    for y in YEARS:
        df, st = build_replica(y, data_dir / "vulnerabilities.csv", data_dir / "known_exploited.csv",
                               data_dir / f"exploit_signals_{y}.csv", con)
        df.to_parquet(out_dir / f"replica_{y}.parquet", index=False)
        all_stats[str(y)] = st
        g = df.groupby("snapshot_month").agg(
            pool=("cve_id", "size"), positives=("label", "sum"), mean_days_to_cutoff=("days_to_cutoff", "mean"))
        g["positive_rate"] = g["positives"] / g["pool"]
        rate_rows.append(g.reset_index().assign(replica=y))
        print(f"replica_{y}: {st['kept']:,} rows, {st['positives']} positives "
              f"(dropped: sig-only {st['dropped_signal_only']}, date-only {st['dropped_date_only']}, "
              f"both {st['dropped_both']})")
        if st["positives"] < 50:
            print(f"  !!! WARNING: replica {y} has only {st['positives']} positives (<50): "
                  f"hit counts will be very noisy")
    sb = build_scoreboard_features(con=con)
    sb.to_parquet(out_dir / "scoreboard_features.parquet", index=False)
    print(f"scoreboard_features: {len(sb):,} rows")
    cols = ["replica", "snapshot_month", "pool", "positives", "positive_rate", "mean_days_to_cutoff"]
    pd.concat(rate_rows)[cols].round({"positive_rate": 6, "mean_days_to_cutoff": 1}).to_csv(
        out_dir / "positive_rate_by_month.csv", index=False)
    all_stats["scoreboard_by_month"] = {k: int(v) for k, v in sb.groupby("snapshot_month").size().items()}
    (out_dir / "replica_stats.json").write_text(json.dumps(all_stats, indent=1))


if __name__ == "__main__":
    main()
