"""Score the three standard baselines on each replica and write the v0 top 500.

Run:  python -m src.baselines   (after python -m src.replicas)

CVSS is joined from vulnerabilities.csv INSIDE this script only; it is never written to replicas.
This block only MEASURES baselines; nothing is tuned.
"""
import json
from datetime import datetime, timezone

import duckdb
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.scoring import _ranked, bootstrap_interval, hits_at_k, k_for_pool, baselines

RUNLOG_COLS = ["timestamp", "version", "replica", "k", "hits", "baseline_exploit_epss_hits", "notes"]
VERSIONS = {"baseline_cvss": "cvss3_score", "baseline_epss": "epss", "baseline_exploit_epss": "exploit_epss"}


def add_scores(df: pd.DataFrame) -> pd.DataFrame:
    """exploit_epss: any exploit flag first, then EPSS (NULL EPSS last)."""
    any_exploit = df[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1)
    return df.assign(exploit_epss=any_exploit * 2 + df["epss"].fillna(-1))


def load_cvss(data_dir=DATA_DIR) -> pd.DataFrame:
    return duckdb.connect().execute(
        f"SELECT cve_id, TRY_CAST(cvss3_score AS DOUBLE) AS cvss3_score "
        f"FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)").df()


def score_replica(df: pd.DataFrame, n_boot=1000) -> dict:
    k = k_for_pool(len(df))
    res = {"k": k, "pool": len(df), "positives": int(df["label"].sum())}
    for version, col in VERSIONS.items():
        res[version] = {"hits": hits_at_k(df, col, k=k),
                        "ci90": bootstrap_interval(df, col, k, n=n_boot, seed=0)}
    # cross-check against the shared helper
    b = baselines(df, cvss_col="cvss3_score", k=k)
    assert (b["cvss"], b["epss"], b["exploit_epss"]) == tuple(
        res[v]["hits"] for v in VERSIONS), "scoring helpers disagree"
    return res


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    cvss = load_cvss(data_dir)
    results, log_rows = {}, []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for y in (2024, 2025):
        rep = pd.read_parquet(out_dir / f"replica_{y}.parquet").merge(cvss, on="cve_id", how="left")
        res = score_replica(add_scores(rep))
        results[str(y)] = res
        for version in VERSIONS:
            lo, hi = res[version]["ci90"]
            log_rows.append({
                "timestamp": now, "version": version, "replica": y, "k": res["k"],
                "hits": res[version]["hits"],
                "baseline_exploit_epss_hits": res["baseline_exploit_epss"]["hits"],
                "notes": f"pool={res['pool']} positives={res['positives']} boot90=[{lo:.0f},{hi:.0f}]"})
    log = pd.DataFrame(log_rows, columns=RUNLOG_COLS)
    path = out_dir / "runlog.csv"
    log.to_csv(path, mode="a", header=not path.exists(), index=False)
    (out_dir / "baseline_results.json").write_text(json.dumps(results, indent=1))

    print(f"{'replica':8}{'pool':>8}{'pos':>6}{'k':>6} | {'CVSS':>14}{'EPSS':>14}{'exploit+EPSS':>16}   (hits [90% boot])")
    for y, r in results.items():
        cells = [f"{r[v]['hits']:>4} [{r[v]['ci90'][0]:.0f}-{r[v]['ci90'][1]:.0f}]" for v in VERSIONS]
        print(f"{y:8}{r['pool']:>8,}{r['positives']:>6}{r['k']:>6} | {cells[0]:>14}{cells[1]:>14}{cells[2]:>16}")

    sb = add_scores(pd.read_parquet(out_dir / "scoreboard_features.parquet"))
    top = _ranked(sb, "exploit_epss").head(500)[["cve_id"]]
    top.to_csv(out_dir / "top500_v0.csv", index=False)
    print(f"wrote {out_dir / 'top500_v0.csv'} ({len(top)} rows)")


if __name__ == "__main__":
    main()
