"""Person B: do the new track-record priors (src/b/priors.py) add anything to Person A's v5 model?

Run:  python -m src.b.eval_priors     -> outputs/b_priors_eval.md, outputs/b_priors_eval.json

Exactly Person A's v5 setup (src/models/train_v5.py): same data and X5 frame, the same pre-set hyper-parameter rule
(select_lgbm on the TRAINING replica only, month folds), 20-seed rank-averaged bag, both directions, tie rule and k.
Variants differ only in extra columns, each added as its within-pool percentile rank (drift-safe, like v4/v5):
  v5                     Person A's features
  v5 + knn               + knn_kev_rate
  v5 + product           + product_kev_count_max, product_kev_12m_max
  v5 + both              + all three
Reported: bag hits per direction, pooled; mean/min/max of single-seed pooled hits; and a paired bootstrap (CVE-level, 1000
draws per direction, pooled by summing the two directions' draws) of (variant bag - v5 bag). LOW POWER: 75 positives.
"""
import json

import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import SHARE_FEATURES, V1_FEATURES, V5_TRANSFORMS
from src.common.scoring import paired_bootstrap_hits
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v4 import bag
from src.models.train_v5 import FEATURES_V5

SEEDS = list(range(20))
NEW = {"knn": ["knn_kev_rate"], "product": ["product_kev_count_max", "product_kev_12m_max"]}
NEW["both"] = NEW["knn"] + NEW["product"]


def positions(c, score):
    order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
    pos = np.empty(len(order), dtype=np.int64)
    pos[order] = np.arange(len(order))
    return pos


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, sb, sb2, ctx = st.prepare(out_dir, data_dir)
    pri = pd.read_parquet(out_dir / "b_priors.parquet").set_index("cve_id")
    for y in (2024, 2025):
        f = pd.read_parquet(out_dir / f"features_replica_{y}.parquet").reset_index(drop=True)
        assert f["cve_id"].tolist() == data[y]["meta"]["cve_id"].tolist()
        x5 = dfx.to_v5(pd.concat([data[y]["X2"], f[SHARE_FEATURES]], axis=1)).reset_index(drop=True)
        p = pri.reindex(f["cve_id"]).reset_index(drop=True)
        assert p[NEW["both"]].notna().all().all(), "priors missing for some replica CVEs"
        for col in NEW["both"]:
            x5[col + "_pctrank"] = p[col].rank(pct=True, method="average").to_numpy()
        data[y]["XP"] = x5
    variants = {"v5": FEATURES_V5, **{f"v5 + {k}": FEATURES_V5 + [c + "_pctrank" for c in cols] for k, cols in NEW.items()}}
    res, bags = {}, {}
    for name, feats in variants.items():
        per_dir, seed_pooled, b = [], np.zeros(len(SEEDS)), {}
        for d in st.DIRS:
            c = ctx[d]
            params = v1.select_lgbm(c["tr"]["XP"][feats], c["tr"]["y"], c["tr"]["groups"], feats, f"priors {name} train {d[0]}")[0]
            sc = [v1.lgbm_model(params, feats, seed=s).fit(c["tr"]["XP"][feats], c["tr"]["y"]).predict_proba(c["te"]["XP"][feats])[:, 1]
                  for s in SEEDS]
            seed_pooled += np.array([st.hits_of(c, x) for x in sc])
            b[d] = bag(sc)
            per_dir.append(st.hits_of(c, b[d]))
        bags[name] = b
        res[name] = {"bag_by_dir": dict(zip(["test2025", "test2024"], per_dir)), "bag_pooled": int(sum(per_dir)),
                     "single_seed_pooled_mean_min_max": [round(float(seed_pooled.mean()), 2), int(seed_pooled.min()), int(seed_pooled.max())]}
        print(name, res[name])
    # paired bootstrap of (variant - v5), pooled over the two directions
    for name in variants:
        if name == "v5":
            continue
        tot = 0
        for j, d in enumerate(st.DIRS):
            c = ctx[d]
            B = paired_bootstrap_hits(c["label"], [positions(c, bags["v5"][d]), positions(c, bags[name][d])], c["k"], n=1000, seed=j)
            tot = tot + (B[:, 1] - B[:, 0])
        res[name]["diff_vs_v5_pooled"] = res[name]["bag_pooled"] - res["v5"]["bag_pooled"]
        res[name]["diff_vs_v5_90"] = [float(np.percentile(tot, 5)), float(np.percentile(tot, 95))]
    (out_dir / "b_priors_eval.json").write_text(json.dumps(res, indent=1))
    lines = ["# Do the new track-record priors help v5? (Person B)", "",
             "Same v5 data, parameter rule, 20-seed bag, tie rule and k as `src/models/train_v5.py`; only extra columns differ "
             "(within-pool percentile ranks). LOW POWER: 75 positives.", "",
             "| variant | test 2025 | test 2024 | pooled (bag) | single seeds: mean (min-max) | vs v5, 90% paired bootstrap |",
             "|---|---|---|---|---|---|"]
    for name, r in res.items():
        m = r["single_seed_pooled_mean_min_max"]
        dv = "" if name == "v5" else f"{r['diff_vs_v5_pooled']:+d} [{r['diff_vs_v5_90'][0]:+.0f}, {r['diff_vs_v5_90'][1]:+.0f}]"
        lines.append(f"| {name} | {r['bag_by_dir']['test2025']} | {r['bag_by_dir']['test2024']} | {r['bag_pooled']} | {m[0]} ({m[1]}-{m[2]}) | {dv} |")
    (out_dir / "b_priors_eval.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return res


if __name__ == "__main__":
    main()
