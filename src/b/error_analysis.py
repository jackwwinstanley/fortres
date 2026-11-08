"""Person B: error analysis of the v5 forward test (train 2024 -> test 2025), where v5 catches 12 and the simple rule 13.

Run:  python -m src.b.error_analysis     -> outputs/b_error_analysis.md, outputs/b_error_analysis.json

1. Rebuilds Person A's v5 20-seed bag exactly (same X5 frame, select_lgbm rule on the training replica, seeds 0-19) in
   BOTH directions and lists, per direction, the KEV CVEs that only the model or only the simple rule caught, with the
   facts that explain the ranking: within-month EPSS rank, public-exploit flags, model rank, text tags, kev_text_score
   percentile, assigner history, and the Granite facts where available.
2. Tests ONE cheap, pre-declared fix, chosen before looking at its hits: a 50/50 blend of the v5 bag's within-pool
   percentile and the simple rule's within-pool percentile (exploit-then-EPSS order). The weight is fixed at 0.5, not
   tuned. It is scored the same way Person A scores (k, tie rule) on both directions, for the bag and every single seed.
"""
import json

import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import SHARE_FEATURES, TEXT_FEATURES
from src.common.scoring import k_for_pool, paired_bootstrap_hits, rank_order
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v4 import bag
from src.models.train_v5 import FEATURES_V5

SEEDS = list(range(20))
TXT = [f for f in TEXT_FEATURES if f.startswith("txt_")]
W_BLEND = 0.5  # fixed before looking at results


def baseline_pct(meta):
    """Within-pool percentile of the simple rule's order (1 = top), from Person A's exploit_epss ranking."""
    order = rank_order(meta.reset_index(drop=True), ["exploit_epss"]).index.to_numpy()
    pct = np.empty(len(order))
    pct[order] = 1 - np.arange(len(order)) / len(order)
    return pct


def positions(c, score):
    order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
    pos = np.empty(len(order), dtype=np.int64)
    pos[order] = np.arange(len(order))
    return pos


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, sb, sb2, ctx = st.prepare(out_dir, data_dir)
    for y in (2024, 2025):
        f = pd.read_parquet(out_dir / f"features_replica_{y}.parquet").reset_index(drop=True)
        data[y]["X5"] = dfx.to_v5(pd.concat([data[y]["X2"], f[SHARE_FEATURES]], axis=1)).reset_index(drop=True)
    ex = pd.read_parquet(out_dir / "b_extract_cache.parquet").drop(columns=["guard_changes"], errors="ignore").set_index("cve_id") \
        if (out_dir / "b_extract_cache.parquet").exists() else pd.DataFrame()
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "vendor", "product", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")
    report, lines = {}, ["# Error analysis: v5 vs the simple rule (Person B)", "",
                         "v5 20-seed bag rebuilt exactly as `src/models/train_v5.py`. LOW POWER: 27 and 48 KEV CVEs.", ""]
    for (tr, te), label in zip(st.DIRS, ["forward: train 2024 -> test 2025", "stability: train 2025 -> test 2024"]):
        c = ctx[(tr, te)]
        params = v1.select_lgbm(c["tr"]["X5"], c["tr"]["y"], c["tr"]["groups"], FEATURES_V5, f"v5 train {tr}")[0]
        sc = [v1.lgbm_model(params, FEATURES_V5, seed=s).fit(c["tr"]["X5"][FEATURES_V5], c["tr"]["y"]).predict_proba(c["te"]["X5"][FEATURES_V5])[:, 1]
              for s in SEEDS]
        b = bag(sc)
        meta = c["meta"].reset_index(drop=True)
        k = k_for_pool(len(meta))
        bp = baseline_pct(meta)
        blend = W_BLEND * pd.Series(b).rank(pct=True).to_numpy() + (1 - W_BLEND) * bp
        pos_m, pos_b, pos_x = positions(c, b), np.argsort(np.argsort(-bp, kind="stable")), positions(c, blend)
        pos = meta["label"].to_numpy() == 1
        caught_m, caught_b = pos & (pos_m < k), pos & (pos_b < k)
        X = c["te"]["X5"].reset_index(drop=True)
        tf = c["te"]["X2"].reset_index(drop=True)
        rows = []
        for i in np.flatnonzero(caught_m ^ caught_b):
            cve = meta.loc[i, "cve_id"]
            facts = ex.loc[cve].to_dict() if cve in ex.index else {}
            rows.append({
                "cve_id": cve, "caught_by": "model only" if caught_m[i] else "simple rule only",
                "kev": f"{kev.loc[cve, 'vendor']} {kev.loc[cve, 'product']}" if cve in kev.index else "",
                "model_rank": int(pos_m[i]) + 1, "rule_rank": int(pos_b[i]) + 1, "k": k,
                "epss_rank_in_month": round(float(meta.loc[i, "epss_rank_in_month"]), 3),
                "exploit_flags": ",".join(f for f in ["exploitdb", "metasploit", "nuclei", "poc_github"] if meta.loc[i, f] == 1) or "none",
                "kev_text_pct": round(float(pd.Series(tf["kev_text_score"]).rank(pct=True)[i]), 3),
                "txt_tags": ",".join(t.replace("txt_", "") for t in TXT if tf.loc[i, t] == 1) or "none",
                "assigner_kev_share": round(float(X.loc[i, "assigner_kev_share"]), 4) if "assigner_kev_share" in X else None,
                "granite_facts": " / ".join(str(facts.get(k_, "")) for k_ in ["product_type", "auth_required", "impact_type"]) if facts else "",
            })
        # pre-declared blend: bag and single seeds, paired bootstrap vs v5 bag
        seed_h = [st.hits_of(c, s) for s in sc]
        seed_blend_h = [st.hits_of(c, W_BLEND * pd.Series(s).rank(pct=True).to_numpy() + (1 - W_BLEND) * bp) for s in sc]
        B = paired_bootstrap_hits(c["label"], [pos_m, pos_x], k, n=1000, seed=0)
        res = {"k": k, "model_hits": int(caught_m.sum()), "rule_hits": int(caught_b.sum()), "both": int((caught_m & caught_b).sum()),
               "blend_hits": int((pos & (pos_x < k)).sum()), "seed_mean_model": round(float(np.mean(seed_h)), 2),
               "seed_mean_blend": round(float(np.mean(seed_blend_h)), 2),
               "blend_minus_model_90": [float(np.percentile(B[:, 1] - B[:, 0], 5)), float(np.percentile(B[:, 1] - B[:, 0], 95))],
               "differences": rows}
        report[label] = res
        lines += [f"## {label} (k = {k})", "",
                  f"Model {res['model_hits']} · simple rule {res['rule_hits']} · caught by both {res['both']} · "
                  f"pre-declared 50/50 blend {res['blend_hits']} (single seeds: model mean {res['seed_mean_model']}, "
                  f"blend mean {res['seed_mean_blend']}; blend − model 90% paired bootstrap {res['blend_minus_model_90']})", "",
                  pd.DataFrame(rows).to_markdown(index=False) if rows else "_no differences_", ""]
    (out_dir / "b_error_analysis.json").write_text(json.dumps(report, indent=1, default=str))
    (out_dir / "b_error_analysis.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__ == "__main__":
    main()
