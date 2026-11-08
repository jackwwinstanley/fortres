"""Write the tables behind docs/findings.md that no earlier step produced.  Reads data and cached scores; changes no model output.

Run from a checkout with data/ present:  python scripts/discovery_tables.py

Writes (all new, under outputs/):
  discovery_kev_severity.csv  CISA KEV entries by year added and CVSS 3 severity (finding 2)
  discovery_events.csv        the 75 practice-year KEV additions grouped into events: same KEV date and vendor (finding 7)
  discovery_workload.csv      how deep each ranking must go to reach v6's hits at the published list size (finding 9)
  discovery_epss_jump.csv     median EPSS by pool and snapshot month, and the July 2026 jump factor (finding 10)

The workload table needs the cached v6 practice-year scores (outputs/.cache/rank/bag_I_<train year>.npy, written by
`python -m src.b.rank`). It stops with an error unless those scores reproduce the published 18 / 9 / 27 and the published 19
for the simple rule.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "outputs"
DATA = ROOT / "data"
SEVERITIES = ["Critical", "High", "Medium", "Low", "None or unscored"]
JUMP_START = "2026-07"


def severity(score) -> str:
    """CVSS 3 rating bands from the score."""
    if pd.isna(score) or score == 0:
        return "None or unscored"
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def kev_severity_table(kev: pd.DataFrame, vulns: pd.DataFrame, first=2021, last=2025) -> pd.DataFrame:
    """One row per year added, plus a 'total' row. kev has cve_id and date_added; vulns has cve_id and cvss3_score."""
    d = kev[["cve_id", "date_added"]].merge(vulns[["cve_id", "cvss3_score"]], on="cve_id", how="left")
    d["year"] = pd.to_datetime(d["date_added"]).dt.year
    d = d[d["year"].between(first, last)]
    d["severity"] = d["cvss3_score"].map(severity)
    t = pd.crosstab(d["year"], d["severity"]).reindex(columns=SEVERITIES, fill_value=0)
    t.insert(0, "entries", t.sum(axis=1))
    t.loc["total"] = t.sum()
    return t.reset_index().rename(columns={"index": "year"})


def depth_to_match(labels_in_rank_order, hits: int):
    """How far down a ranking you must go to collect `hits` positives (1-based); None if it never does."""
    idx = np.flatnonzero(np.asarray(labels_in_rank_order))
    return int(idx[hits - 1]) + 1 if hits <= len(idx) else None


def events_table(positives: pd.DataFrame) -> pd.DataFrame:
    """positives: cve_id, replica, date_added, vendor. One row per event, the definition kev_events() uses in the bootstrap."""
    g = positives.groupby(["date_added", "vendor"], sort=True)
    return g.agg(n_cves=("cve_id", "size"), replicas=("replica", lambda s: ";".join(str(x) for x in sorted(set(s)))),
                 cves=("cve_id", lambda s: ";".join(sorted(s)))).reset_index()


def epss_jump(rows: pd.DataFrame, start=JUMP_START) -> tuple[pd.DataFrame, float]:
    """rows: pool, snapshot_month, epss. Returns the monthly medians and the factor: median EPSS of 2026 snapshots from `start`
    on, divided by the median of the 2024 and 2025 practice pools together."""
    t = rows.groupby(["pool", "snapshot_month"])["epss"].agg(n="size", median_epss="median").reset_index()
    before = rows.loc[rows["pool"].isin(["2024", "2025"]), "epss"].median()
    after = rows.loc[(rows["pool"] == "2026") & (rows["snapshot_month"] >= start), "epss"].median()
    return t, float(after / before)


def workload(ctx, dirs, rank_order, cvss3) -> pd.DataFrame:
    """Hits at the published k and depth needed to match v6's hits, per test and pooled."""
    scores = {"fortres (v6)": ["v6s", "epss_rank_in_month"], "usual rule (public code, then EPSS)": ["exploit_epss"],
              "EPSS only (within-month rank)": ["epss_rank_in_month"], "severity (CVSS 3 score)": ["c3"]}
    rows = []
    for d in dirs:
        c = ctx[d]
        m = c["meta"].reset_index(drop=True).copy()
        m["v6s"] = np.load(OUT / ".cache" / "rank" / f"bag_I_{d[0]}.npy")
        m["c3"] = cvss3.reindex(m["cve_id"]).fillna(-1).to_numpy()
        ordered = {name: rank_order(m, cols)["label"].to_numpy() for name, cols in scores.items()}
        target = int(ordered["fortres (v6)"][: c["k"]].sum())
        for name, labels in ordered.items():
            rows.append({"test_pool": d[1], "method": name, "k": c["k"], "hits_at_k": int(labels[: c["k"]].sum()),
                         "fortres_hits": target, "fixes_to_match": depth_to_match(labels, target)})
    t = pd.DataFrame(rows)
    pooled = t.groupby("method", sort=False)[["k", "hits_at_k", "fortres_hits", "fixes_to_match"]].sum().reset_index()
    pooled.insert(0, "test_pool", "pooled")
    return pd.concat([t, pooled], ignore_index=True)


def main() -> int:
    from src.common.scoring import rank_order
    from src.models import stress_v2 as st

    kev = pd.read_csv(DATA / "known_exploited.csv")
    vulns = pd.read_csv(DATA / "vulnerabilities.csv", usecols=["cve_id", "cvss3_score"])
    kev_severity_table(kev, vulns).to_csv(OUT / "discovery_kev_severity.csv", index=False)

    _, _, _, ctx = st.prepare(OUT, DATA)
    w = workload(ctx, st.DIRS, rank_order, vulns.set_index("cve_id")["cvss3_score"])
    got = w[w["method"] == "fortres (v6)"].set_index("test_pool")["hits_at_k"].to_dict()
    rule = int(w[(w["method"].str.startswith("usual")) & (w["test_pool"] == "pooled")]["hits_at_k"].iloc[0])
    if (got[2025], got[2024], got["pooled"], rule) != (18, 9, 27, 19):
        raise SystemExit(f"cached scores do not reproduce the published results: {got}, rule {rule}")
    w.to_csv(OUT / "discovery_workload.csv", index=False)

    pos = []
    for d in st.DIRS:
        m = ctx[d]["meta"]
        pos.append(m.loc[m["label"] == 1, ["cve_id"]].assign(replica=d[1]))
    pos = pd.concat(pos).merge(kev[["cve_id", "date_added", "vendor"]], on="cve_id", how="left")
    assert pos["date_added"].notna().all() and len(pos) == 75
    events_table(pos).to_csv(OUT / "discovery_events.csv", index=False)

    frames = [pd.read_parquet(OUT / f"replica_{y}.parquet", columns=["snapshot_month", "epss"]).assign(pool=str(y)) for y in (2024, 2025)]
    frames.append(pd.read_csv(DATA / "scoreboard_2026.csv", usecols=["snapshot_month", "epss"]).assign(pool="2026"))
    t, factor = epss_jump(pd.concat(frames, ignore_index=True))
    t["jump_factor_from_2026_07"] = round(factor, 2)
    t.to_csv(OUT / "discovery_epss_jump.csv", index=False)
    print("discovery tables written; EPSS jump factor", round(factor, 2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
