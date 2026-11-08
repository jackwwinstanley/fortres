"""Export the data behind the charts on the site's findings page (site/index.html#found) to site/data/findings.json.

Run:  python scripts/export_site_findings.py

Every value is read from a committed file under outputs/; nothing is typed here. The page only draws these values,
and tests/test_site_fortres.py checks the JSON against the same files.
"""
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.common import primary  # noqa: E402

OUT = ROOT / "outputs"
DEST = ROOT / "site" / "data" / "findings.json"


def build() -> dict:
    h = json.loads((OUT / "headline.json").read_text())
    b = pd.read_csv(primary.file("blindspots"))
    blind = b[b["group"] == "blind-spot"]
    caught = [c for s in blind["ours_caught_cves"].dropna() for c in str(s).split(";") if c]
    sev_df = pd.read_csv(OUT / "discovery_kev_severity.csv")
    tot = sev_df[sev_df["year"].astype(str) == "total"].iloc[0]
    work = pd.read_csv(OUT / "discovery_workload.csv")
    pooled = work[work["test_pool"].astype(str) == "pooled"]
    ex = json.loads((OUT / "explanations_summary.json").read_text())
    vcv = pd.read_csv(OUT / "rank_vendor_cv.csv")
    v25 = vcv[vcv["replica"] == 2025]
    ev = pd.read_csv(OUT / "discovery_events.csv")
    ep = pd.read_csv(OUT / "discovery_epss_jump.csv")
    return {
        "source": "scripts/export_site_findings.py from outputs/",
        "blind": {"total": int(b["exploited"].sum()), "blind": int(blind["exploited"].sum()),
                  "rule_caught_blind": int(blind["baseline_caught"].sum()), "ours_caught_blind": int(blind["ours_caught"].sum()),
                  "ours_caught_cves": caught},
        "severity": {k: int(tot[k]) for k in ["entries", "Critical", "High", "Medium", "Low", "None or unscored"]},
        "leakage": {"honest": h["leakage"]["honest"]["pooled_hits"], "leaky": h["leakage"]["leaky"]["pooled_hits"]},
        "workload": [{"method": r["method"], "k": int(r["k"]), "hits_at_k": int(r["hits_at_k"]),
                      "fixes_to_match": int(r["fixes_to_match"])} for _, r in pooled.iterrows()],
        "reasons": {"total": ex["total"], "passed_guardian": ex["passed_guardian"],
                    "guardian_rejected": ex["guardian_verdicts"]["Yes"], "local_failed": ex["guardian_verdicts"]["not_run"]},
        "vendor_cv_2025": {"ungrouped": int(v25[v25["scheme"].str.startswith("ungrouped")]["oof_hits_top_k"].iloc[0]),
                           "vendor_grouped": int(v25[v25["scheme"].str.startswith("vendor")]["oof_hits_top_k"].iloc[0])},
        "events": [[str(r["date_added"]), str(r["vendor"]).strip(), int(r["n_cves"])] for _, r in ev.iterrows()],
        "epss_months": [[str(r["snapshot_month"]), float(r["median_epss"])] for _, r in ep.iterrows()],
        "epss_jump": float(ep["jump_factor_from_2026_07"].iloc[0]),
    }


if __name__ == "__main__":
    DEST.write_text(json.dumps(build(), ensure_ascii=False, separators=(",", ":")) + "\n")
    print(f"wrote {DEST.relative_to(ROOT)}")
