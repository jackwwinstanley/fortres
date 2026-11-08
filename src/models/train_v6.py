"""v6 candidate = b/rank candidate I (regularised v5) on the frozen v5 features.  Run:  python -m src.models.train_v6

Writes ONLY v6_* files (plus outputs/top500_v6.csv); never touches any v5 file, top500.csv, headline.json, runlog.csv,
docs/, site/, app/ or README.md.

1. Final settings: the same rule v5's final model used (train_v5.py): leave-one-month-out CV on the pooled 2024 + 2025
   replicas with month-of-year folds, criterion pooled OOF average precision, over candidate I's grid
   (num_leaves {2,3} x min_child_samples {200,400} x colsample_bytree {0.4,0.6} x reg_lambda {30,100}), with n_estimators and
   scale_pos_weight inherited from v5's final selection. No test year is involved, and the 2026 scoreboard has no labels.
   20-seed (0-19) rank-averaged bag on the v5 features -> outputs/top500_v6.csv, outputs/v6_top500_contrib.parquet,
   outputs/v6_scores.csv.
2. Checks (directional, with I's per-direction settings from b/rank): overlaps, exploit-flag share, blind-spot view,
   like-for-like placebo (real vs within-month shuffled training labels, 30 x 5-seed bags each), leakage experiment
   (honest vs banned-columns arm, same settings), paired and event-clustered bootstrap vs the best simple rule and vs v5,
   spread across the 4 seed sets.
3. outputs/v6_headline_candidate.json (headline.json schema), outputs/v6_report.md.
4. outputs/v6_missing_explanations.csv.
"""
import itertools
import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from joblib import Parallel, delayed

from src.b import leakage as lk
from src.b import rank as R
from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import MONOTONE_UP, SHARE_FEATURES
from src.common.scoring import clustered_paired_bootstrap_hits, paired_bootstrap_hits, rank_order
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v4 import bag, ci, kev_events, topk_base
from src.models.train_v5 import FEATURES_V5, bootstrap_p

F5 = list(FEATURES_V5)
SEEDS = list(range(20))
DIRS = st.DIRS
DN = {DIRS[0]: "forward_train2024_test2025", DIRS[1]: "stability_train2025_test2024"}
PLACEBO_N, PLACEBO_BAG = 30, 5
JOBS = 4
RUNS = []


def run(step, status, **kw):
    RUNS.append({"step": step, "status": status, **{k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in kw.items()}})
    print("RUN", step, status, kw, flush=True)


def model(params, feats, seed):
    mono = [1 if f in MONOTONE_UP else 0 for f in feats]
    return lgb.LGBMClassifier(monotone_constraints=mono, **{**v1.FIXED, "random_state": int(seed), **params})


def _fit(params, feats, Xtr, ytr, Xte, seed):
    return model(params, feats, seed).fit(Xtr[feats], ytr).predict_proba(Xte[feats])[:, 1]


def bag_of(params, feats, Xtr, ytr, Xte, seeds):
    return bag(Parallel(n_jobs=JOBS)(delayed(_fit)(params, feats, Xtr, ytr, Xte, s) for s in seeds))


def main():
    data, ctx = R.load()
    _, sb, sb2, _ = st.prepare(OUT_DIR, DATA_DIR)
    sb2s = pd.concat([sb2.reset_index(drop=True), sb[SHARE_FEATURES].reset_index(drop=True)], axis=1)
    sb5 = dfx.to_v5(sb2s)[F5]
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")

    # ---------------------------------------------------------------- 1. final settings + final bag
    X_all = pd.concat([data[2024]["X5"], data[2025]["X5"]], ignore_index=True)
    y_all = np.concatenate([data[2024]["y"], data[2025]["y"]])
    g_month = np.array([g[-2:] for g in np.concatenate([data[2024]["groups"], data[2025]["groups"]])])
    p5_final = v1.select_lgbm(X_all, y_all, g_month, F5, "v5 final (both replicas, month folds)")[0]
    combos = [{**p5_final, **dict(zip(R.GRID_I, v))} for v in itertools.product(*R.GRID_I.values())]
    cv = Parallel(n_jobs=JOBS)(delayed(R._safe_cv)(R.V5_SPEC, p, X_all, y_all, g_month) for p in combos)
    best = max((ap, i) for i, (ap, err) in enumerate(cv) if err is None)[1]
    for i, (p, (ap, err)) in enumerate(zip(combos, cv)):
        run("final settings: inner CV on pooled 2024+2025 (month-of-year folds)", "failed" if err else ("selected" if i == best else "not selected"),
            params=p, cv_ap=ap, notes=err or "")
    p6 = combos[best]
    models = [model(p6, F5, s).fit(X_all[F5], y_all) for s in SEEDS]
    sbm = sb5.assign(cve_id=sb["cve_id"].to_numpy())
    sbm["s"] = bag([m.predict_proba(sbm[F5])[:, 1] for m in models])
    ranked = rank_order(sbm, ["s", "epss_rank_in_month"])
    final_ids = ranked.head(500)["cve_id"].tolist()
    pd.DataFrame({"cve_id": final_ids}).to_csv(OUT_DIR / "top500_v6.csv", index=False)
    ranked[["cve_id", "s"]].rename(columns={"s": "v6_score"}).assign(v6_rank=np.arange(1, len(ranked) + 1)).to_csv(OUT_DIR / "v6_scores.csv", index=False)
    idx = pd.Series(np.arange(len(sbm)), index=sbm["cve_id"]).loc[final_ids].to_numpy()
    contrib = np.mean([m.booster_.predict(sbm.iloc[idx][F5], pred_contrib=True)[:, :-1] for m in models], axis=0)
    pd.DataFrame(contrib, columns=F5).assign(cve_id=final_ids)[["cve_id", *F5]].to_parquet(OUT_DIR / "v6_top500_contrib.parquet", index=False)
    run("final bag", "ok", params=p6, notes="20 seeds on both replicas; top500_v6.csv, v6_scores.csv, v6_top500_contrib.parquet")

    # ---------------------------------------------------------------- 2a. overlaps
    ids = {n: pd.read_csv(OUT_DIR / f"top500_{n}.csv")["cve_id"].tolist() for n in ("v0", "v5")}
    fl = sbm.set_index("cve_id")
    flagged = lambda lst: int((fl.loc[lst, ["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1) == 1).sum())  # noqa: E731
    overlap = {"top500_v6_vs_top500_v5": len(set(final_ids) & set(ids["v5"])), "top500_v6_vs_baseline_top500_v0": len(set(final_ids) & set(ids["v0"])),
               "top500_v5_vs_baseline_top500_v0": len(set(ids["v5"]) & set(ids["v0"])),
               "exploit_flag_v6": flagged(final_ids), "exploit_flag_v5": flagged(ids["v5"]), "exploit_flag_baseline": flagged(ids["v0"])}
    pd.DataFrame([overlap]).to_csv(OUT_DIR / "v6_overlap.csv", index=False)

    # ---------------------------------------------------------------- 2b. directional scores (I settings per direction from b/rank)
    pI = {d: json.loads((R.CACHE / f"sel_I_{d[0]}.json").read_text())["params"] for d in DIRS}
    sc6 = {d: R.bag_scores(f"I_{d[0]}", R.V5_SPEC, pI[d], ctx[d], SEEDS) for d in DIRS}
    sc5 = {d: R.bag_scores(f"v5_0-19_{d[0]}", R.V5_SPEC, ctx[d]["p5"], ctx[d], SEEDS) for d in DIRS}
    h6 = [st.hits_of(ctx[d], sc6[d]) for d in DIRS]
    h5 = [st.hits_of(ctx[d], sc5[d]) for d in DIRS]
    hb = [topk_base(ctx[d]) for d in DIRS]
    run("directional hits", "ok", v6=h6, v5=h5, baseline=hb)
    single = np.array([[st.hits_of(ctx[d], _fit(pI[d], F5, ctx[d]["tr"]["X5"], ctx[d]["tr"]["y"], ctx[d]["te"]["X5"], s)) for d in DIRS] for s in SEEDS])

    # ---------------------------------------------------------------- 2c. bootstrap: paired + event-clustered
    Bc, Be = {}, {}
    for d in DIRS:
        meta = ctx[d]["meta"].reset_index(drop=True).assign(b6=sc6[d], b5=sc5[d])
        pos = [v1.rank_pos(meta, ["exploit_epss"]), v1.rank_pos(meta, ["b5", "epss_rank_in_month"]), v1.rank_pos(meta, ["b6", "epss_rank_in_month"])]
        Bc[d] = paired_bootstrap_hits(meta["label"].to_numpy(), pos, ctx[d]["k"], n=v1.N_BOOT, seed=0)
        Be[d] = clustered_paired_bootstrap_hits(meta["label"].to_numpy(), kev_events(meta, kev), pos, ctx[d]["k"], n=v1.N_BOOT, seed=0)
    boot = []
    for label, dirs in (("forward", [DIRS[0]]), ("stability", [DIRS[1]]), ("pooled", list(DIRS))):
        for vs, j in (("best simple rule", 0), ("v5", 1)):
            c = ci(sum(Bc[d][:, 2] - Bc[d][:, j] for d in dirs))
            e = ci(sum(Be[d][:, 2] - Be[d][:, j] for d in dirs))
            obs = sum(h6[DIRS.index(d)] - (hb if j == 0 else h5)[DIRS.index(d)] for d in dirs)
            boot.append({"test": label, "v6_vs": vs, "diff": obs, "cve_level_90": list(c), "event_clustered_90": list(e)})
    pd.DataFrame(boot).to_csv(OUT_DIR / "v6_bootstrap.csv", index=False)

    # ---------------------------------------------------------------- 2d. blind-spot view on the 75
    br = []
    for d in DIRS:
        meta = ctx[d]["meta"]
        r6 = lk.blind_breakdown(d[1], meta, sc6[d])
        r5 = lk.blind_breakdown(d[1], meta, sc5[d])
        for a, b in zip(r5, r6):
            br.append({"year": a["year"], "group": a["group"], "exploited": a["exploited"], "simple_rule_caught": a["baseline_caught"],
                       "v5_caught": a["ours_caught"], "v6_caught": b["ours_caught"], "v6_caught_cves": b["ours_caught_cves"]})
    blind = pd.DataFrame(br)
    blind.to_csv(OUT_DIR / "v6_blindspots.csv", index=False)

    # ---------------------------------------------------------------- 2e. placebo: real vs shuffled labels (like-for-like)
    real, null = [], []
    for j in range(PLACEBO_N):
        real.append(sum(st.hits_of(ctx[d], bag_of(pI[d], F5, ctx[d]["tr"]["X5"], ctx[d]["tr"]["y"], ctx[d]["te"]["X5"],
                                                  range(100 + j * PLACEBO_BAG, 100 + (j + 1) * PLACEBO_BAG))) for d in DIRS))
        tot = 0
        for d in DIRS:
            rng = np.random.default_rng(j)
            y = np.asarray(ctx[d]["tr"]["y"]).copy()
            months = np.asarray(ctx[d]["tr_months"])
            for m in np.unique(months):  # shuffle the labels within each snapshot month (keeps the positives per month)
                ix = np.where(months == m)[0]
                y[ix] = y[rng.permutation(ix)]
            tot += st.hits_of(ctx[d], bag_of(pI[d], F5, ctx[d]["tr"]["X5"], y, ctx[d]["te"]["X5"], range(1000 + j * PLACEBO_BAG, 1000 + (j + 1) * PLACEBO_BAG)))
        null.append(tot)
    real, null = np.array(real), np.array(null)
    d_obs, d_ci, p_boot = bootstrap_p(real, null)
    pd.DataFrame({"bag": range(PLACEBO_N), "real_pooled_hits": real, "shuffled_labels_pooled_hits": null}).to_csv(OUT_DIR / "v6_placebo.csv", index=False)
    run("placebo", "ok", real_mean=float(real.mean()), shuffled_mean=float(null.mean()), diff=d_obs, ci=list(d_ci), p=p_boot)

    # ---------------------------------------------------------------- 2f. leakage experiment with v6 settings
    lrows = []
    for d in DIRS:
        tr, te = d
        XL = {}
        for y in (tr, te):
            idsy = data[y]["meta"]["cve_id"]
            b = lk.banned_columns(idsy, DATA_DIR).set_index("cve_id").reindex(idsy).reset_index(drop=True)
            XL[y] = pd.concat([data[y]["X5"][F5].reset_index(drop=True), b], axis=1)
        leaky = F5 + [c for c in XL[tr].columns if c.startswith("leak_")]
        for arm, feats in (("honest", F5), ("leaky", leaky)):
            s = bag_of(pI[d], feats, XL[tr], data[tr]["y"], XL[te], SEEDS)
            lrows.append({"direction": DN[d], "model": arm, "hits": st.hits_of(ctx[d], s), "k": ctx[d]["k"], "settings": json.dumps(pI[d])})
    lres = pd.DataFrame(lrows)
    lres.to_csv(OUT_DIR / "v6_leakage_results.csv", index=False)
    run("leakage", "ok", table=lres[["direction", "model", "hits"]].to_dict("records"))

    # ---------------------------------------------------------------- 2g. spread over the 4 seed sets
    spread = []
    for name, seeds in {"seeds 0-19": SEEDS, **R.NOISE_SETS}.items():
        tag = "0-19" if name == "seeds 0-19" else name.split()[1]
        h = [st.hits_of(ctx[d], R.bag_scores(f"I_{d[0]}" if tag == "0-19" else f"I_{tag}_{d[0]}", R.V5_SPEC, pI[d], ctx[d], list(seeds))) for d in DIRS]
        g = [st.hits_of(ctx[d], R.bag_scores(f"v5_{tag}_{d[0]}", R.V5_SPEC, ctx[d]["p5"], ctx[d], list(seeds))) for d in DIRS]
        spread.append({"seed_set": name, "v6_forward": h[0], "v6_stability": h[1], "v6_pooled": sum(h), "v5_forward": g[0], "v5_stability": g[1],
                       "v5_pooled": sum(g), "v6_minus_v5_pooled": sum(h) - sum(g)})
    spread = pd.DataFrame(spread)
    spread.to_csv(OUT_DIR / "v6_seed_spread.csv", index=False)

    # ---------------------------------------------------------------- 4. missing explanations
    ex = set(pd.read_csv(OUT_DIR / "explanations.csv", usecols=["cve_id"])["cve_id"])
    missing = [c for c in final_ids if c not in ex]
    pd.DataFrame({"cve_id": missing, "v6_rank": [final_ids.index(c) + 1 for c in missing]}).to_csv(OUT_DIR / "v6_missing_explanations.csv", index=False)

    # ---------------------------------------------------------------- 3. headline candidate (headline.json schema)
    b = {r["test"] + "|" + r["v6_vs"]: r for r in boot}
    lk_sum = {arm: {"pooled_hits": int(lres.loc[lres["model"] == arm, "hits"].sum()),
                    **{DN[d]: int(lres.loc[(lres["model"] == arm) & (lres["direction"] == DN[d]), "hits"].iloc[0]) for d in DIRS}} for arm in ("honest", "leaky")}
    head = {
        "primary": "v6 CANDIDATE (not adopted until Jack's verdict): 20-seed LightGBM bag, v5 features, regularised settings (b/rank candidate I)",
        "pooled_hits_bag": int(sum(h6)), "baseline_pooled_hits": int(sum(hb)),
        "forward_train2024_test2025": {"bag_hits": int(h6[0]), "baseline_hits": int(hb[0]),
                                       "diff_cve_level_90": b["forward|best simple rule"]["cve_level_90"], "diff_event_clustered_90": b["forward|best simple rule"]["event_clustered_90"]},
        "stability_train2025_test2024": {"bag_hits": int(h6[1]), "baseline_hits": int(hb[1])},
        "pooled": {"diff_cve_level_90": b["pooled|best simple rule"]["cve_level_90"], "diff_event_clustered_90": b["pooled|best simple rule"]["event_clustered_90"]},
        "seeds": {"bag_seeds": len(SEEDS), "single_seed_pooled_hits_mean_min_max": [round(float(single.sum(1).mean()), 2), int(single.sum(1).min()), int(single.sum(1).max())],
                  "placebo": f"{PLACEBO_N} real {PLACEBO_BAG}-seed bags vs {PLACEBO_N} shuffled-label {PLACEBO_BAG}-seed bags"},
        "v6_minus_v5_pooled_hits": int(sum(h6) - sum(h5)),
        "v6_vs_v5": {k: {"diff": b[f"{k}|v5"]["diff"], "diff_cve_level_90": b[f"{k}|v5"]["cve_level_90"], "diff_event_clustered_90": b[f"{k}|v5"]["event_clustered_90"]}
                     for k in ("forward", "stability", "pooled")},
        "placebo_bootstrap_p": p_boot,
        "positives": {"2024": int(data[2024]["y"].sum()), "2025": int(data[2025]["y"].sum())},
        "leakage": {"source": "outputs/v6_leakage_results.csv", **lk_sum},
        "final_params": p6,
        "note": "CANDIDATE ONLY. LOW POWER (75 positives). headline.json (v5) is unchanged until Jack's verdict."}
    (OUT_DIR / "v6_headline_candidate.json").write_text(json.dumps(head, indent=1))
    pd.DataFrame(RUNS).to_csv(OUT_DIR / "v6_runs.csv", index=False)
    summary = dict(overlap=overlap, blind=blind.drop(columns="v6_caught_cves").to_dict("records"), placebo=(real.mean(), null.mean(), d_obs, d_ci, p_boot),
                   leakage=lk_sum, boot=boot, spread=spread.to_dict("records"), missing=len(missing), single=single.sum(1).tolist(), p6=p6, h6=h6, h5=h5, hb=hb)
    (OUT_DIR / ".cache" / "v6_summary.json").write_text(json.dumps(summary, indent=1, default=float))
    print(json.dumps(summary, indent=1, default=float))


if __name__ == "__main__":
    main()
