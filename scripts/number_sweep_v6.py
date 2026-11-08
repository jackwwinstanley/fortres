"""Run scripts/number_sweep.py's checks with v6 expected values (outputs/v6_headline_candidate.json, v6_leakage_results.csv, v6_blindspots.csv)."""
import json, sys
from pathlib import Path
import pandas as pd
root = Path.cwd(); sys.path.insert(0, str(root / "scripts")); import number_sweep as ns
out = root / "outputs"
h = json.loads((out / "v6_headline_candidate.json").read_text())
lk = pd.read_csv(out / "v6_leakage_results.csv")
bs = pd.read_csv(out / "v6_blindspots.csv")
fwd, stab = h["forward_train2024_test2025"], h["stability_train2025_test2024"]
e = {"pooled": (h["pooled_hits_bag"], h["baseline_pooled_hits"]), "forward": (fwd["bag_hits"], fwd["baseline_hits"]),
     "stability": (stab["bag_hits"], stab["baseline_hits"]),
     "ranges": {tuple(int(round(x)) for x in r) for r in [h["pooled"]["diff_cve_level_90"], fwd["diff_cve_level_90"]]},
     "honest": int(lk.loc[lk.model == "honest", "hits"].sum()), "leaky": int(lk.loc[lk.model == "leaky", "hits"].sum()),
     "leaky_split": (int(lk[(lk.model == "leaky") & lk.direction.str.startswith("forward")]["hits"].iloc[0]),
                     int(lk[(lk.model == "leaky") & lk.direction.str.startswith("stability")]["hits"].iloc[0])),
     "blind": (int(bs.loc[bs.group == "blind-spot", "exploited"].sum()), int(bs["exploited"].sum())),
     "guardian": json.loads((out / "explanations_summary.json").read_text())}
probs = []
for f in ns.files(root):
    probs += ns.check_text(str(f.relative_to(root)), f.read_text(errors="ignore"), e)
print("v6 expected:", {k: v for k, v in e.items() if k != "guardian"})
print(len(probs), "problem(s)"); print("\n".join(probs))
