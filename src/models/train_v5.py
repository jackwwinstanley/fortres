"""Step 3e: v5 = the LAST feature-set change. Run:  python -m src.models.train_v5

Fixes the drift treatment of step 3d, where the within-pool rank raised PSI for tie-heavy features. Rule (fixed before running,
drift only, never hits): for each scale-sensitive feature choose, among raw / within-pool percentile rank / scale-free share, the
transformation with the lowest PSI between the pooled replicas and the 2026 scoreboard; ties go to raw. Raw epss stays removed;
epss_rank_in_month and epss_missing are unchanged. The result becomes the final model regardless of its hits: v5 replaces v4 as the
primary list. Model: 20-seed LightGBM bag (same pre-set hyper-parameter rule), forward direction (train 2024 -> test 2025) reported
first, train 2025 -> test 2024 labelled a stability check; logistic regression is a robustness line only. LOW POWER: 75 positives.
"""
import json
from datetime import datetime, timezone

import duckdb
import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import (ALLOWED_FEATURES, PSI_REPLACED, SHARE_FEATURES, TEXT_FEATURES, V1_FEATURES, V2_FEATURES, V4_FEATURES,
                               V5_TRANSFORMS, check_feature_list)
from src.common.scoring import clustered_paired_bootstrap_hits, paired_bootstrap_hits, rank_order
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v4 import bag, ci, fmt_ci, kev_events, pooled_matrix, seed_scores, topk_base

FEATURES_V5 = list(ALLOWED_FEATURES)
DIRS = st.DIRS                       # forward first: (train 2024, test 2025), then the stability check (train 2025, test 2024)
DIR_LABEL = {DIRS[0]: "train 2024 -> test 2025 (forward in time)", DIRS[1]: "train 2025 -> test 2024 (stability check, NOT forward in time)"}
BAG_SEEDS = list(range(20))
PLACEBO_N, PLACEBO_BAG = 30, 5
N_BOOT_P = 10000
md = v1.md


def bootstrap_p(real, null, n=N_BOOT_P, seed=0):
    """Bootstrap of the difference in means (real - null): observed difference, 90% interval, one-sided p = share of
    bootstrap differences <= 0."""
    rng = np.random.default_rng(seed)
    real, null = np.asarray(real, float), np.asarray(null, float)
    diffs = np.array([real[rng.integers(0, len(real), len(real))].mean() - null[rng.integers(0, len(null), len(null))].mean() for _ in range(n)])
    return float(real.mean() - null.mean()), (float(np.percentile(diffs, 5)), float(np.percentile(diffs, 95))), float((diffs <= 0).mean())


def placebo_like_for_like(ctx, sc5_first20):
    """30 real 5-seed bags (disjoint seeds 5j..5j+4) vs 30 within-month text shuffles, each trained as a 5-seed bag."""
    need = PLACEBO_N * PLACEBO_BAG
    real_sc = {}
    for d in DIRS:
        c = ctx[d]
        extra = seed_scores(c, "X5", FEATURES_V5, c["p5"], range(len(sc5_first20[d]), need))
        real_sc[d] = list(sc5_first20[d]) + extra
    real = [sum(st.hits_of(ctx[d], bag(real_sc[d][j * PLACEBO_BAG:(j + 1) * PLACEBO_BAG])) for d in DIRS) for j in range(PLACEBO_N)]
    null = []
    for k in range(PLACEBO_N):
        rng = np.random.default_rng(k)
        tot = 0
        for d in DIRS:
            c = ctx[d]
            Xtr = st.shuffle_text_within_month(c["tr"]["X5"], c["tr_months"], TEXT_FEATURES, rng)
            Xte = st.shuffle_text_within_month(c["te"]["X5"], c["months"], TEXT_FEATURES, rng)
            seeds = range(1000 + k * PLACEBO_BAG, 1000 + (k + 1) * PLACEBO_BAG)
            sc = [v1.lgbm_model(c["p5"], FEATURES_V5, seed=s).fit(Xtr[FEATURES_V5], c["tr"]["y"]).predict_proba(Xte[FEATURES_V5])[:, 1] for s in seeds]
            tot += st.hits_of(c, bag(sc))
        null.append(tot)
    return np.array(real), np.array(null)


def assigner_mix(data_dir, pools):
    """Per pool: distinct assigners, share of CVEs from the 5 busiest assigners, zero-history share (descriptive)."""
    a = duckdb.connect().execute(f"SELECT cve_id, assigner FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)").df().set_index("cve_id")["assigner"]
    rows = []
    for name, ids, zero in pools:
        s = a.reindex(ids).fillna("unknown")
        top5 = s.value_counts(normalize=True).head(5).sum()
        rows.append((name, f"{s.nunique():,}", f"{top5:.1%}", f"{zero:.1%}"))
    return rows


def why_high(f: str) -> str:
    if f == "days_to_cutoff":
        return ("a pure function of the snapshot month (days from month end to Nov 4); the 2026 scoreboard has most of its CVEs in July to September, so its month mix "
                "differs from the replicas by construction")
    if f.startswith("assigner_"):
        return ("assigner history is measured to a later cutoff (2025-12-31 vs 2023-12-31 and 2024-12-31) and the 2026 pool has a different assigner mix, so counts, "
                "shares and ranks of history differ by construction (see the assigner-mix table)")
    if f.startswith("vendor_"):
        return "vendor KEV history is measured to a later cutoff and the mix of vendors mentioned changes"
    if f.startswith("txt_") or f in ("kev_text_score", "nearest_kev_sim"):
        return "categorical or score content of the descriptions shifted"
    return "calendar and EPSS-model effects"


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    assert not check_feature_list(FEATURES_V5), check_feature_list(FEATURES_V5)
    assert "epss" not in FEATURES_V5
    data, sb, sb2, ctx = st.prepare(out_dir, data_dir)
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")

    # ---- features: candidates, PSI-based choice, assertion against the recorded decision
    feats = {y: pd.read_parquet(out_dir / f"features_replica_{y}.parquet").reset_index(drop=True) for y in (2024, 2025)}
    for y in (2024, 2025):
        assert feats[y]["cve_id"].tolist() == data[y]["meta"]["cve_id"].tolist()
        x2s = pd.concat([data[y]["X2"], feats[y][SHARE_FEATURES]], axis=1)
        data[y]["X5"] = dfx.to_v5(x2s)
        data[y]["X4"] = dfx.to_v4(data[y]["X2"], PSI_REPLACED)[V4_FEATURES]
    sb2s = pd.concat([sb2.reset_index(drop=True), sb[SHARE_FEATURES].reset_index(drop=True)], axis=1)
    sb5, sb4 = dfx.to_v5(sb2s)[FEATURES_V5], dfx.to_v4(sb2, PSI_REPLACED)[V4_FEATURES]
    cols = V1_FEATURES + SHARE_FEATURES
    chosen, psi_cand = dfx.select_transforms([feats[2024][cols], feats[2025][cols]], sb[cols])
    assert chosen == V5_TRANSFORMS, f"PSI now chooses {chosen}; update schema.V5_TRANSFORMS deliberately"
    rep5 = pd.concat([data[2024]["X5"], data[2025]["X5"]], ignore_index=True)
    rep2 = pd.concat([data[2024]["X2"], data[2025]["X2"]], ignore_index=True)
    psi_final = dfx.psi_table(rep5, sb5, features=FEATURES_V5).set_index("feature")["psi"]
    psi_old = dfx.psi_table(rep2, sb2).set_index("feature")["psi"]            # raw features, step-3d baseline for comparison
    mix = assigner_mix(data_dir, [("replica 2024", data[2024]["meta"]["cve_id"], float((data[2024]["X2"]["assigner_prior_cves"] == 0).mean())),
                                  ("replica 2025", data[2025]["meta"]["cve_id"], float((data[2025]["X2"]["assigner_prior_cves"] == 0).mean())),
                                  ("2026 scoreboard", sb["cve_id"], float((sb2["assigner_prior_cves"] == 0).mean()))])

    # ---- hyper-parameters: the same pre-set rule, training replica only
    for tr, te in DIRS:
        c = ctx[(tr, te)]
        c["p5"], _, c["ap5"] = v1.select_lgbm(c["tr"]["X5"], c["tr"]["y"], c["tr"]["groups"], FEATURES_V5, f"v5 train {tr}")
        c["p4"], _, _ = v1.select_lgbm(c["tr"]["X4"], c["tr"]["y"], c["tr"]["groups"], V4_FEATURES, f"v4 train {tr}")
    print("selection done")

    # ---- directional evaluation
    sc5, h5 = pooled_matrix(ctx, "X5", FEATURES_V5, "p5", BAG_SEEDS)
    sc4, h4 = pooled_matrix(ctx, "X4", V4_FEATURES, "p4", BAG_SEEDS)
    bag5 = {d: bag(sc5[d]) for d in DIRS}
    bag4 = {d: bag(sc4[d]) for d in DIRS}
    lr5 = {d: v1.fit_predict("logreg", None, ctx[d]["tr"]["X5"], ctx[d]["tr"]["y"], ctx[d]["te"]["X5"], FEATURES_V5) for d in DIRS}
    base_dir = [topk_base(ctx[d]) for d in DIRS]
    b5, b4, l5 = ([st.hits_of(ctx[d], x[d]) for d in DIRS] for x in (bag5, bag4, lr5))
    base_pool = sum(base_dir)
    assert sum(b4) == 21 and base_pool == 19, "v4 / baseline numbers differ from the step 3d report"
    print(f"baseline {base_dir} {base_pool}; v5 bag {b5} {sum(b5)}; v4 bag {b4} {sum(b4)}; v5 logreg {l5}; v5 single-seed mean {h5.sum(1).mean():.1f}")

    names = ["baseline", "v5 bag", "v4 bag", "v5 logistic"]
    Bcve, Bev = {}, {}
    for d in DIRS:
        c = ctx[d]
        meta = c["meta"].reset_index(drop=True).assign(b5=bag5[d], b4=bag4[d], l5=lr5[d])
        cols_ = [["exploit_epss"], ["b5", "epss_rank_in_month"], ["b4", "epss_rank_in_month"], ["l5", "epss_rank_in_month"]]
        pos = [v1.rank_pos(meta, cc) for cc in cols_]
        Bcve[d] = paired_bootstrap_hits(meta["label"].to_numpy(), pos, c["k"], n=v1.N_BOOT, seed=0)
        Bev[d] = clustered_paired_bootstrap_hits(meta["label"].to_numpy(), kev_events(meta, kev), pos, c["k"], n=v1.N_BOOT, seed=0)
    ix = {n: i for i, n in enumerate(names)}

    def diff_ci(B, a, b, dirs):
        return ci(sum(B[d][:, ix[a]] - B[d][:, ix[b]] for d in dirs))

    iv = {}
    for label, dirs in [("forward", [DIRS[0]]), ("stability", [DIRS[1]]), ("pooled", list(DIRS))]:
        for a, b in [("v5 bag", "baseline"), ("v5 bag", "v4 bag"), ("v5 logistic", "baseline")]:
            iv[(label, a, b)] = (diff_ci(Bcve, a, b, dirs), diff_ci(Bev, a, b, dirs))

    # ---- placebo (like-for-like)
    real_p, null_p = placebo_like_for_like(ctx, sc5)
    d_obs, d_ci, p_boot = bootstrap_p(real_p, null_p)
    print(f"placebo real mean {real_p.mean():.2f} vs null {null_p.mean():.2f}, p = {p_boot:.3f}")

    # ---- leakage audit (names + description scans, same rules)
    leak_items, leak_tabs = st.leakage_audit(data, data_dir, features=FEATURES_V5)
    leakage_found = any(f for _, _, f in leak_items)

    # ---- final model on both replicas, 20-seed bag
    X_all = pd.concat([data[2024]["X5"], data[2025]["X5"]], ignore_index=True)
    y_all = np.concatenate([data[2024]["y"], data[2025]["y"]])
    g_month = np.array([g[-2:] for g in np.concatenate([data[2024]["groups"], data[2025]["groups"]])])
    params, _, ap_final = v1.select_lgbm(X_all, y_all, g_month, FEATURES_V5, "v5 final (both replicas, month folds)")
    models = [v1.lgbm_model(params, FEATURES_V5, seed=s).fit(X_all[FEATURES_V5], y_all) for s in BAG_SEEDS]
    sbm = sb5.assign(cve_id=sb["cve_id"].to_numpy())
    sbm["s"] = bag([m.predict_proba(sbm[FEATURES_V5])[:, 1] for m in models])
    final_ids = rank_order(sbm, ["s", "epss_rank_in_month"]).head(500)["cve_id"].tolist()
    pd.DataFrame({"cve_id": final_ids}).to_csv(out_dir / "top500_v5.csv", index=False)
    idx = pd.Series(np.arange(len(sbm)), index=sbm["cve_id"]).loc[final_ids].to_numpy()
    contrib = np.mean([m.booster_.predict(sbm.iloc[idx][FEATURES_V5], pred_contrib=True)[:, :-1] for m in models], axis=0)
    pd.DataFrame(contrib, columns=FEATURES_V5).assign(cve_id=final_ids)[["cve_id", *FEATURES_V5]].to_parquet(out_dir / "v5_top500_contrib.parquet", index=False)
    ids = {n: pd.read_csv(out_dir / f"top500_{n}.csv")["cve_id"].tolist() for n in ("v0", "v3", "v4")}
    fl = sbm.set_index("cve_id")
    flagged = lambda lst: int((fl.loc[lst, ["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1) == 1).sum())  # noqa: E731

    update_runlog(out_dir, b5, l5, base_dir, base_pool, ctx, iv, h5, real_p, null_p)
    fwd, pool = iv[("forward", "v5 bag", "baseline")], iv[("pooled", "v5 bag", "baseline")]
    headline = {
        "primary": "v5: 20-seed LightGBM bag, drift-selected feature transformations, no raw EPSS",
        "pooled_hits_bag": int(sum(b5)), "baseline_pooled_hits": int(base_pool),
        "forward_train2024_test2025": {"bag_hits": int(b5[0]), "baseline_hits": int(base_dir[0]),
                                       "diff_cve_level_90": list(fwd[0]), "diff_event_clustered_90": list(fwd[1])},
        "stability_train2025_test2024": {"bag_hits": int(b5[1]), "baseline_hits": int(base_dir[1])},
        "pooled": {"diff_cve_level_90": list(pool[0]), "diff_event_clustered_90": list(pool[1])},
        "seeds": {"bag_seeds": len(BAG_SEEDS), "single_seed_pooled_hits_mean_min_max": [round(float(h5.sum(1).mean()), 2), int(h5.sum(1).min()), int(h5.sum(1).max())],
                  "placebo": f"{PLACEBO_N} real {PLACEBO_BAG}-seed bags vs {PLACEBO_N} shuffled-text {PLACEBO_BAG}-seed bags"},
        "v5_minus_v4_pooled_hits": int(sum(b5) - sum(b4)),
        "placebo_bootstrap_p": p_boot, "positives": {"2024": int(data[2024]["y"].sum()), "2025": int(data[2025]["y"].sum())},
        "note": "LOW POWER (75 positives). Use these numbers for headlines; seed-0 rows and earlier versions are not for headline."}
    (out_dir / "headline.json").write_text(json.dumps(headline, indent=1))

    write_report(locals())
    return headline


def update_runlog(out_dir, b5, l5, base_dir, base_pool, ctx, iv, h5, real_p, null_p):
    path = out_dir / "runlog.csv"
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for i in df.index[df["version"].str.startswith("v4_")]:
        if "superseded by v5" not in df.at[i, "notes"]:
            df.at[i, "notes"] = "superseded by v5 (drift treatment fixed in step 3e); not for headline; " + df.at[i, "notes"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    new = []
    for j, (name, tr, te, _) in enumerate(v1.DIRECTIONS):
        k = ctx[(tr, te)]["k"]
        cv, ev = iv[("forward" if j == 0 else "stability", "v5 bag", "baseline")]
        new.append(dict(timestamp=now, version="v5_bag", replica=name, k=k, hits=b5[j], baseline_exploit_epss_hits=base_dir[j],
                        notes=f"low power; 20-seed bag; {'forward direction' if j == 0 else 'stability check, not forward in time'}; diff vs baseline 90% CVE-level {fmt_ci(cv)}, event-clustered {fmt_ci(ev)}"))
        new.append(dict(timestamp=now, version="v5_logreg", replica=name, k=k, hits=l5[j], baseline_exploit_epss_hits=base_dir[j],
                        notes="low power; robustness line only (deterministic logistic regression on the v5 features); not the final model"))
    cv, ev = iv[("pooled", "v5 bag", "baseline")]
    new.append(dict(timestamp=now, version="v5_bag", replica="pooled", k=sum(ctx[d]["k"] for d in DIRS), hits=sum(b5), baseline_exploit_epss_hits=base_pool,
                    notes=(f"low power; pooled over both directions; 20-seed bag; diff vs best baseline: CVE-level 90% {fmt_ci(cv)}, event-clustered 90% {fmt_ci(ev)}; "
                           f"single-seed pooled mean {h5.sum(1).mean():.1f} (min {h5.sum(1).min()}, max {h5.sum(1).max()}); "
                           f"placebo {PLACEBO_N}x{PLACEBO_BAG}-seed bags: real {real_p.mean():.1f} vs shuffled {null_p.mean():.1f}")))
    new_df = pd.DataFrame(new).astype(str)
    key = lambda d: set(zip(d["version"], d["replica"], d["hits"], d["notes"]))  # noqa: E731
    keep = [kk not in key(df) for kk in zip(new_df["version"], new_df["replica"], new_df["hits"], new_df["notes"])]
    pd.concat([df, new_df[keep]], ignore_index=True).to_csv(path, index=False)


def dist_row(name, x):
    x = np.asarray(x)
    return (name, f"{x.mean():.2f}", f"{x.std(ddof=1):.2f}", int(x.min()), f"{np.percentile(x, 50):.0f}", f"{np.percentile(x, 95):.0f}", int(x.max()))


def write_report(g):
    out_dir, ctx, iv = g["out_dir"], g["ctx"], g["iv"]
    base_dir, base_pool, b5, b4, l5, h5, h4 = g["base_dir"], g["base_pool"], g["b5"], g["b4"], g["l5"], g["h5"], g["h4"]
    psi_cand, psi_final, psi_old, mix = g["psi_cand"], g["psi_final"], g["psi_old"], g["mix"]
    real_p, null_p, d_obs, d_ci, p_boot = g["real_p"], g["null_p"], g["d_obs"], g["d_ci"], g["p_boot"]
    leak_items, leak_tabs, leakage_found = g["leak_items"], g["leak_tabs"], g["leakage_found"]
    params, ap_final, final_ids, ids, flagged = g["params"], g["ap_final"], g["final_ids"], g["ids"], g["flagged"]
    fwd, stab, pool = (iv[(k, "v5 bag", "baseline")] for k in ("forward", "stability", "pooled"))
    ev_pool_lo = pool[1][0]
    L = ["# v5 report: drift treatment fixed by PSI, 20-seed bag", "",
         "> **LOW POWER.** 27 (2024) and 48 (2025) positives. **The forward direction (train 2024 -> test 2025) is reported first; train 2025 -> test 2024 is a "
         "stability check, not forward in time.** Headline numbers are the 20-seed bag or multi-seed means; earlier versions are superseded.", "",
         "## Decision record (declared before the numbers)", "",
         "- Step 3d replaced scale features by within-pool percentile ranks and, for tie-heavy features, **raised** PSI (days_to_cutoff 1.03 -> 2.33, assigner_kev_count 1.17 -> 2.66, "
         "assigner_kev_12m 0.78 -> 2.77).",
         "- **This is the last feature-set change. v5 becomes the final model and the primary list regardless of its hits** (it replaces v4; v5 minus v4 is reported honestly below).",
         "- Rule, decided before running and based on drift only: for each of days_to_cutoff, assigner_prior_cves, assigner_kev_count, assigner_kev_12m, assigner_kev_rate_smooth, "
         "vendor_kev_count_max and vendor_kev_12m_max choose among (a) raw, (b) within-pool percentile rank, (c) a scale-free share (share of all CVEs published / all KEV entries "
         "added by the history cutoff, or in the 12 months before it; vendor equivalents analogously, zero denominators guarded) the transformation with the **lowest PSI** between the "
         "pooled replicas and the 2026 scoreboard; ties go to raw. Raw epss stays removed; epss_rank_in_month and epss_missing are unchanged.", "",
         "## Headline", "",
         f"**Forward direction (train 2024 -> test 2025):** the v5 20-seed bag found **{b5[0]}** exploited CVEs in the top 243 against the baseline's **{base_dir[0]}** "
         f"({b5[0] - base_dir[0]:+d}; 90% interval {fmt_ci(fwd[0])} CVE-level, {fmt_ci(fwd[1])} event-clustered).", "",
         f"**Pooled over both directions:** {sum(b5)} vs {base_pool} ({sum(b5) - base_pool:+d}; {fmt_ci(pool[0])} CVE-level, {fmt_ci(pool[1])} event-clustered). "
         f"Stability check (train 2025 -> test 2024): {b5[1]} vs {base_dir[1]} ({b5[1] - base_dir[1]:+d}; {fmt_ci(stab[0])} / {fmt_ci(stab[1])}). "
         f"Single seeds average {h5.sum(1).mean():.1f} pooled hits (min {h5.sum(1).min()}, max {h5.sum(1).max()}, 20 seeds).", ""]

    chosen_cols = set(psi_cand.loc[psi_cand["chosen"], "column"])
    L += ["## PSI of every candidate transformation (pooled replicas vs 2026 scoreboard)", "",
          "Spike-aware PSI with 10 bins from the replicas (`src/features/drift_fix.py`); ranks are computed within each pool; > 0.25 is a large shift.", "",
          md(["feature", "transform", "column", "PSI", "chosen"],
             [(r.feature, r.transform, r.column, f"{r.psi:.3f}", "**yes**" if r.column in chosen_cols and r.chosen else "") for r in psi_cand.itertuples()]), "",
          "### PSI of every final feature", "",
          md(["feature", "PSI", ""], [(f, f"{p:.3f}", "**above 0.25**" if p > dfx.PSI_LARGE else "") for f, p in psi_final.items()]), ""]
    high = psi_final[psi_final > dfx.PSI_LARGE]
    L += ["Final features above 0.25 and why:", "",
          *([f"- `{f}` ({p:.2f}): {why_high(f)}." for f, p in high.items()] or ["- none."]), "",
          "No text-flag feature is above 0.25 (the largest `txt_` PSI is "
          f"{psi_final[[c for c in psi_final.index if c.startswith('txt_')]].max():.3f}), so there is no categorical content shift to explain; `epss_rank_in_month` is "
          f"{psi_final['epss_rank_in_month']:.3f} and `epss_missing` {psi_final['epss_missing']:.3f}. The remaining shift is concentrated in the assigner-history features and "
          "`days_to_cutoff`, which the rule could not reduce further. The 2026 pool's assigner mix:", "",
          md(["pool", "distinct assigners", "share of CVEs from the 5 busiest assigners", "assigner has zero history"], mix), "",
          "The rule was applied as written; no further adjustment was made after seeing these numbers or any hits.", ""]

    L += ["## Hyper-parameters (same pre-set rule: pooled OOF AP on the training replica)", "",
          md(["training replica", "pooled OOF AP (LightGBM)", "chosen parameters"],
             [(d[0], f"{ctx[d]['ap5']:.4f}", f"`{json.dumps(ctx[d]['p5'])}`") for d in DIRS]), ""]

    def blk(label, j):
        key = "forward" if j == 0 else "stability"
        c5, e5 = iv[(key, "v5 bag", "baseline")]
        c4, e4 = iv[(key, "v5 bag", "v4 bag")]
        cl, el = iv[(key, "v5 logistic", "baseline")]
        return [f"### {label}", "",
                md(["ranking", "hits in top k", "diff vs baseline (90% CVE-level / event-clustered)"],
                   [("Exploit code, then EPSS (baseline)", base_dir[j], ""),
                    ("**v5 20-seed bag**", f"**{b5[j]}**", f"{b5[j] - base_dir[j]:+d}  {fmt_ci(c5)} / {fmt_ci(e5)}"),
                    ("v5 single seeds 0-19, mean", f"{h5[:, j].mean():.1f}", f"{h5[:, j].mean() - base_dir[j]:+.1f}"),
                    ("v4 20-seed bag (superseded)", b4[j], f"{b4[j] - base_dir[j]:+d}"),
                    ("v5 minus v4 (bags)", f"{b5[j] - b4[j]:+d}", f"{fmt_ci(c4)} / {fmt_ci(e4)}"),
                    ("v5 logistic regression (robustness only, not for selection)", l5[j], f"{l5[j] - base_dir[j]:+d}  {fmt_ci(cl)} / {fmt_ci(el)}")]), ""]

    L += ["## Results", ""] + blk(f"Forward direction: {DIR_LABEL[DIRS[0]]}, test 2025, k = 243", 0) + blk(f"Stability check: {DIR_LABEL[DIRS[1]]}, test 2024, k = 198", 1)
    c5, e5 = pool
    c4, e4 = iv[("pooled", "v5 bag", "v4 bag")]
    L += ["### Pooled over both directions", "",
          md(["ranking", "pooled hits", "diff vs baseline (90% CVE-level / event-clustered)"],
             [("baseline", base_pool, ""), ("**v5 20-seed bag**", f"**{sum(b5)}**", f"{sum(b5) - base_pool:+d}  {fmt_ci(c5)} / {fmt_ci(e5)}"),
              ("v5 single seeds, mean / min / max", f"{h5.sum(1).mean():.1f} / {h5.sum(1).min()} / {h5.sum(1).max()}", ""),
              ("v4 20-seed bag (superseded)", sum(b4), f"{sum(b4) - base_pool:+d}"),
              ("v5 minus v4 (bags)", f"{sum(b5) - sum(b4):+d}", f"{fmt_ci(c4)} / {fmt_ci(e4)}"),
              ("v5 logistic regression (robustness only)", sum(l5), f"{sum(l5) - base_pool:+d}")]), "",
          "Hits are counted in the top k of each replica (ties by score, epss_rank_in_month, cve_id). The event-clustered bootstrap treats positives added to KEV by the "
          "same vendor on the same date as one event.", ""]

    L += ["## Placebo, like-for-like", "",
          f"{PLACEBO_N} real {PLACEBO_BAG}-seed bags (disjoint seeds, v5 features) against {PLACEBO_N} within-month shuffles of the 16 text columns, each trained as a "
          f"{PLACEBO_BAG}-seed bag; pooled hits over both directions.", "",
          md(["distribution", "mean", "sd", "min", "median", "95th pct", "max"], [dist_row("real bags", real_p), dist_row("shuffled-text bags", null_p)]), "",
          f"Difference in means (real minus shuffled): **{d_obs:+.2f}** hits, 90% bootstrap interval [{d_ci[0]:+.2f}, {d_ci[1]:+.2f}] (10,000 resamples of each group); "
          f"one-sided bootstrap p-value (share of resampled differences <= 0) = **{('< 0.001' if p_boot < 0.001 else f'{p_boot:.3f}')}**. Counts of pooled hits, real: " +
          ", ".join(f"{int(k)}: {int(v)}" for k, v in pd.Series(real_p).value_counts().sort_index().items()) + "; shuffled: " +
          ", ".join(f"{int(k)}: {int(v)}" for k, v in pd.Series(null_p).value_counts().sort_index().items()) + ".", ""]

    L += ["## Leakage audit (same pre-declared rules, v5 feature list)", "",
          md(["check", "result", "flagged"], [(n, r, "**YES**" if f else "no") for n, r, f in leak_items]), "",
          "Limit: the Granite embeddings are not available locally, so `kev_text_score` and `nearest_kev_sim` were not recomputed; their time-safety rests on Person B's code. "
          "All history features, including the new shares, use KEV rows and CVEs dated on or before December 31 of the year before the pool.", ""]

    L += ["## Final list: `outputs/top500_v5.csv`", "",
          md(["item", "value"],
             [("model", "20-seed LightGBM bag on both replicas, v5 features, parameters from the pooled-AP selection"), ("parameters", f"`{json.dumps(params)}`"),
              ("pooled OOF AP of the selection", f"{ap_final:.4f}"), ("ranking rule", "bag score, then epss_rank_in_month, then cve_id"),
              ("overlap with top500_v4", len(set(final_ids) & set(ids['v4']))), ("overlap with top500_v3", len(set(final_ids) & set(ids['v3']))),
              ("overlap with the baseline top 500", len(set(final_ids) & set(ids['v0']))),
              ("CVEs with an exploit flag: v5 list vs baseline list", f"{flagged(final_ids)} vs {flagged(ids['v0'])}"),
              ("status", "**primary list; replaces v4 regardless of hits**"),
              ("contributions", "`outputs/v5_top500_contrib.parquet` (LightGBM pred_contrib averaged over the 20 seeds, one column per feature)")]), "",
          "## How strong is the evidence?", "",
          f"**{'WEAK' if ev_pool_lo <= 0 else 'MODERATE'}.** The forward direction shows {b5[0]} vs {base_dir[0]} ({b5[0] - base_dir[0]:+d}, event-clustered {fmt_ci(fwd[1])}); "
          f"pooled it is {sum(b5)} vs {base_pool} ({sum(b5) - base_pool:+d}, event-clustered {fmt_ci(pool[1])}). Single seeds range {h5.sum(1).min()}-{h5.sum(1).max()} pooled hits. "
          f"v5 minus v4 is {sum(b5) - sum(b4):+d} pooled hits (event-clustered {fmt_ci(iv[('pooled', 'v5 bag', 'v4 bag')][1])}), i.e. the drift-treatment change "
          f"{'did not hurt' if sum(b5) >= sum(b4) else 'cost hits'} in this sample. The like-for-like placebo gap is {d_obs:+.2f} hits (p {('< 0.001' if p_boot < 0.001 else f'= {p_boot:.3f}')}). "
          "With 75 positives from a few dozen KEV events, any gain over the baseline is uncertain, and the remaining PSI in the assigner-history features means the replicas "
          "are an imperfect guide to 2026."]
    (out_dir / "v5_report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
