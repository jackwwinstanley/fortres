"""Write site/data/picks.json: the top of the final list with each reason and its Guardian verdict, plus the Guardian summary.

Read only by the Fortres page (site/). Run after the explanations are final:
    python scripts/export_site_picks.py
"""
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
N = 12


def main():
    story = json.loads((ROOT / "site" / "data" / "story.json").read_text())
    exp = pd.read_csv(ROOT / "outputs" / "explanations.csv").set_index("cve_id")
    summary = json.loads((ROOT / "outputs" / "explanations_summary.json").read_text())
    rows = []
    for it in story["top"]["items"][:N]:
        e = exp.loc[it["cve"]] if it["cve"] in exp.index else None
        rows.append({
            "rank": it["rank"], "cve": it["cve"], "kind": it["kind"], "flaw": it["flaw"], "group": it["group"],
            "epss_pct": it["epss_pct"], "exploit": bool(it["exploit"]),
            "reason": (e["explanation"] if e is not None else it["reason"]),
            "guardian_passed": bool(e is not None and e["guardian_verdict"] == "No"),
            "source": (e["source"] if e is not None else "unknown"),
        })
    out = {"list": story["top"]["list"], "rows": rows,
           "guardian": {k: summary[k] for k in ("total", "passed_guardian", "template_fallback", "guardian_model", "granite_model")}}
    (ROOT / "site" / "data" / "picks.json").write_text(json.dumps(out, indent=1))
    print(f"wrote site/data/picks.json ({len(rows)} rows)")


if __name__ == "__main__":
    main()
