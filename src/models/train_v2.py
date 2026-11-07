"""v2: v1 features + Person B's text features (issue #19).  Run: python -m src.models.train_v2

Same rules as v1 (see train_v1.py): allowed columns only, KEV history cutoff = Dec 31 of the previous year,
hyper-parameters chosen by leave-one-snapshot-month-out CV on the TRAINING replica only, model choice by the
10%-AP rule, nothing tuned on a test replica. Text features are joined by cve_id only.
LOW POWER: 27 + 48 = 75 positives.
"""
import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import ALLOWED_FEATURES, FEATURE_GROUPS_V2, TEXT_FEATURES, check_feature_list
from src.common.scoring import k_for_pool
from src.models import train_v1 as v1

FEATURES_V2 = list(ALLOWED_FEATURES)
VARIANTS = {"logreg_v1": ("logreg", v1.FEATURES), "lgbm_v1": ("lgbm", v1.FEATURES),
            "logreg_v2": ("logreg", FEATURES_V2), "lgbm_v2": ("lgbm", FEATURES_V2)}
LABEL = {"logreg_v1": "Logistic regression, v1", "lgbm_v1": "LightGBM, v1",
         "logreg_v2": "Logistic regression, v2 (+text)", "lgbm_v2": "LightGBM, v2 (+text)"}
BEST_BASE = "Exploit code, then EPSS"


def load_with_text(out_dir=OUT_DIR, data_dir=DATA_DIR):
    """v1 data dict plus text features joined by cve_id; X holds the v2 columns, meta also holds the text scores."""
    data, sb = v1.load(out_dir, data_dir)
    text = pd.read_parquet(out_dir / "text_features.parquet").set_index("cve_id")
    for y in (2024, 2025):
        d = data[y]
        t = text.reindex(d["meta"]["cve_id"])[TEXT_FEATURES].reset_index(drop=True)
        assert not t.isna().any().any(), "text_features.parquet is missing CVEs"
        d["X2"] = pd.concat([d["X"], t], axis=1)
        # score columns reused by the depth-curve and two-channel analyses (never model inputs here)
        for c in ["assigner_kev_rate_smooth", "vendor_kev_count_max"]:
            d["meta"][c] = d["X"][c].to_numpy()
        for c in ["kev_text_score", "nearest_kev_sim"]:
            d["meta"][c] = t[c].to_numpy()
    t = text.reindex(sb["cve_id"])[TEXT_FEATURES].reset_index(drop=True)
    assert not t.isna().any().any(), "text_features.parquet is missing scoreboard CVEs"
    return data, sb, pd.concat([sb[v1.FEATURES], t], axis=1)


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    assert not check_feature_list(FEATURES_V2), check_feature_list(FEATURES_V2)
    data, sb, sb2 = load_with_text(out_dir, data_dir)

    # ---- selection per training replica and feature set
    sel = {}
    for y in (2024, 2025):
        d = data[y]
        for tag, feats, X in [("v1", v1.FEATURES, d["X"]), ("v2", FEATURES_V2, d["X2"])]:
            params, _, ap_lgbm = v1.select_lgbm(X, d["y"], d["groups"], feats, f"train {y}" if tag == "v1" else f"v2 train {y}")
            oof_lr = v1.lomo_oof("logreg", None, X, d["y"], d["groups"], feats)
            ap_lr = average_precision_score(d["y"], oof_lr)
            choice, rel, why = v1.decide_model(ap_lr, ap_lgbm)
            sel[(tag, y)] = dict(params=params, ap_lgbm=ap_lgbm, ap_lr=ap_lr, choice=choice, rel=rel, why=why)

    # ---- directional evaluation (train on one replica, test on the other)
    res, Bs, names_, ks, preds = {}, {}, {}, {}, []
    for name, tr, te, label in v1.DIRECTIONS:
        scores = {}
        for var, (kind, feats) in VARIANTS.items():
            tag = "v1" if var.endswith("v1") else "v2"
            Xtr = data[tr]["X"] if tag == "v1" else data[tr]["X2"]
            Xte = data[te]["X"] if tag == "v1" else data[te]["X2"]
            scores[var] = v1.fit_predict(kind, sel[(tag, tr)]["params"], Xtr, data[tr]["y"], Xte, feats)
        res[name], Bs[name], names_[name], ks[name] = v1.eval_frame(data[te]["meta"], scores)
        preds.append(pd.DataFrame({"test_year": te, "cve_id": data[te]["meta"]["cve_id"].to_numpy(), **scores}))
    cache = out_dir / ".cache"
    cache.mkdir(exist_ok=True)
    pd.concat(preds).to_parquet(cache / "test_preds.parquet", index=False)

    bb, _ = v1.best_baseline([res[n] for n, *_ in v1.DIRECTIONS])
    idx = {n: i for i, n in enumerate(names_[v1.DIRECTIONS[0][0]])}
    dirs = [n for n, *_ in v1.DIRECTIONS]

    def pooled(a, b=None):
        arb = sum(res[n][a]["arbitrary"] for n in dirs)
        exp = sum(res[n][a]["expected"] for n in dirs)
        out = [arb, exp]
        if b is not None:
            d = sum(Bs[n][:, idx[a]] - Bs[n][:, idx[b]] for n in dirs)
            lo, hi = np.percentile(d, [5, 95])
            out += [arb - sum(res[n][b]["arbitrary"] for n in dirs), lo, hi]
        return out

    L = ["### Model comparison: v1 vs v2 (+ Granite text features)", "",
         "> **LOW POWER** (75 positives in total). Same selection rule and the same two directions as v1.", ""]
    L += ["Text features added: " + ", ".join(f"`{c}`" for c in TEXT_FEATURES) + ".", ""]
    rows = []
    for tag in ("v1", "v2"):
        for y in (2024, 2025):
            s = sel[(tag, y)]
            rows.append((tag, y, f"{s['ap_lr']:.4f}", f"{s['ap_lgbm']:.4f}", f"{s['rel']:.0%}", f"**{s['choice']}**",
                         json.dumps(s["params"])))
    L += ["Hyper-parameter selection and model choice (OOF AP on the training replica; within 10% -> logreg):", "",
          v1.md(["features", "training replica", "OOF AP logreg", "OOF AP LightGBM", "gap", "decision", "LightGBM params"], rows), ""]

    L += [f"Pooled over both directions (train 2024 -> test 2025 plus train 2025 -> test 2024). Best baseline: **{bb}**. "
          "Intervals are 90% paired bootstraps (1000 resamples within each replica, seed 0, same resample for both rankings).", ""]
    rows = []
    for b in v1.BASELINES:
        a, e = pooled(b)
        rows.append((b, a, f"{e:.1f}", "", "", ""))
    for var in VARIANTS:
        a, e, d_b, lo_b, hi_b = pooled(var, bb)
        if var.endswith("v2"):
            _, _, d_1, lo_1, hi_1 = pooled(var, var.replace("v2", "v1"))
            vs1 = f"{d_1:+d} [{lo_1:+.0f}, {hi_1:+.0f}]"
        else:
            vs1 = ""
        rows.append((f"**{LABEL[var]}**", a, f"{e:.1f}", f"{d_b:+d} [{lo_b:+.0f}, {hi_b:+.0f}]", vs1, ""))
    L += [v1.md(["ranking", "pooled hits", "pooled expected hits", f"diff vs {bb}", "diff vs same model on v1", ""], rows), ""]

    for name, tr, te, label in v1.DIRECTIONS:
        r, B, names, k = res[name], Bs[name], names_[name], ks[name]
        L += [f"**{name}** ({label}): test replica {te}, k = {k}, {int(data[te]['y'].sum())} positives.", ""]
        rows = []
        for n in names:
            e = r[n]
            diff = B[:, names.index(n)] - B[:, names.index(bb)]
            ds = "" if n == bb else f"{e['arbitrary'] - r[bb]['arbitrary']:+d} [{np.percentile(diff, 5):+.0f}, {np.percentile(diff, 95):+.0f}]"
            rows.append((LABEL.get(n, n), e["arbitrary"], f"{e['expected']:.2f}", v1.ci_str(e["ci"]), v1.tie_str(e),
                         f"{e['ap']:.4f}", ds))
        L += [v1.md(["ranking", "hits", "expected", "90% boot", "tie group at cutoff", "AP", f"diff vs {bb}"], rows), ""]

    wins = {var: sum(res[n][var]["arbitrary"] > res[n][bb]["arbitrary"] for n in dirs) for var in VARIANTS}
    L += ["Does any model beat the best baseline in both directions? " +
          "; ".join(f"{LABEL[v]}: {w} of 2 directions" for v, w in wins.items()) + ".", ""]
    (out_dir / ".cache" / "v2_models.md").write_text("\n".join(L) + "\n")

    # ---- run log (append-only, skip exact duplicates)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    log = []
    for name, tr, te, label in v1.DIRECTIONS:
        for var in ("logreg_v2", "lgbm_v2"):
            kind = VARIANTS[var][0]
            r = res[name][var]
            note = (f"low power; {label}; expected={r['expected']:.1f}; boot90={v1.ci_str(r['ci'])}; "
                    f"params={json.dumps(sel[('v2', tr)]['params']) if kind == 'lgbm' else 'C=' + str(v1.LR_C)}")
            log.append(dict(timestamp=now, version="v2_" + kind, replica=name, k=ks[name], hits=r["arbitrary"],
                            baseline_exploit_epss_hits=res[name][BEST_BASE]["arbitrary"], notes=note))
    path = out_dir / "runlog.csv"
    old = pd.read_csv(path, dtype=str)
    new = pd.DataFrame(log)
    seen = set(zip(old["version"], old["replica"], old["hits"], old["notes"]))
    new = new[[kk not in seen for kk in zip(new["version"], new["replica"], new["hits"].astype(str), new["notes"])]]
    new.to_csv(path, mode="a", header=False, index=False)
    json.dump({"best_baseline": bb, "pooled": {v: pooled(v, bb)[:2] for v in VARIANTS}},
              open(out_dir / ".cache" / "v2_summary.json", "w"))
    print("\n".join(L[-30:]))
    print(f"wrote .cache/v2_models.md; runlog +{len(new)} rows")


if __name__ == "__main__":
    main()
