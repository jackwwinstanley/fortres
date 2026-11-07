"""Step 3d / 3e: drift-robust v4 (no raw EPSS, PSI-replaced features), 20-seed LightGBM bag, stress tests, final list.
Run:  python -m src.models.train_v4

Decisions made on DRIFT evidence, not on test hits:
  * raw `epss` removed (scale moved ~4x in 2026); epss_rank_in_month and epss_missing kept
  * every scale-type feature with PSI > 0.25 (pooled replicas vs 2026 scoreboard) is replaced by its within-pool
    percentile rank (schema.PSI_REPLACED; recomputed and asserted here)
  * hyper-parameters come from the SAME pre-set rule as before (pooled-AP on the training replica; final model: pooled-AP
    over both replicas with month folds); nothing is tuned on a test replica
  * final model = 20-seed LightGBM bag (each seed's scores rank-normalised within the pool, then averaged), chosen
    because bagging removes seed luck, not because of its hits
Policy: v4 replaces v3 as primary unless (i) placebo p > 0.20, (ii) 20-seed mean of single-seed pooled hits < baseline's
pooled hits, or (iii) leakage is found. LOW POWER: 27 + 48 = 75 positives.
"""
import json
import re
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import ALLOWED_FEATURES, PSI_REPLACED, TEXT_FEATURES, V2_FEATURES, check_feature_list
from src.common.scoring import clustered_paired_bootstrap_hits, paired_bootstrap_hits, rank_order
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v2 import FEATURES_V2

FEATURES_V4 = list(ALLOWED_FEATURES)
DIRS = st.DIRS
BAG_SEEDS = list(range(20))
ABL_SEEDS = list(range(1, 11))
N_PLACEBO = 50
PLACEBO_P_MAX = 0.20
TXT = st.TXT_FLAGS
DROPS = {"full": [], "-kev_text_score": ["kev_text_score"], "-nearest_kev_sim": ["nearest_kev_sim"],
         "-txt_ flags": TXT, "-all text": TEXT_FEATURES}
md = v1.md


# ---- model helpers ----------------------------------------------------------------------------
def seed_scores(c, key, feats, params, seeds):
    """Single-seed LightGBM scores on the test replica for each seed (train frame X[key], test frame X[key])."""
    Xtr, Xte, y = c["tr"][key], c["te"][key], c["tr"]["y"]
    return [v1.lgbm_model(params, feats, seed=s).fit(Xtr[feats], y).predict_proba(Xte[feats])[:, 1] for s in seeds]


def bag(scores) -> np.ndarray:
    """Rank-normalise each seed's scores within the pool (percentile rank), then average."""
    return np.mean([pd.Series(s).rank(pct=True, method="average").to_numpy() for s in scores], axis=0)


def pooled_matrix(ctx, key, feats, pkey, seeds):
    """Scores per direction and per-seed hits: returns ({dir: [scores per seed]}, hits array (seeds, dirs))."""
    sc = {d: seed_scores(ctx[d], key, feats, ctx[d][pkey], seeds) for d in DIRS}
    h = np.array([[st.hits_of(ctx[d], sc[d][i]) for d in DIRS] for i in range(len(seeds))])
    return sc, h


def hits_by_seed(ctx, key, feats, pkey, seeds):
    return pooled_matrix(ctx, key, feats, pkey, seeds)[1]


def kev_events(meta, kev):
    """Event id per row: positives sharing (KEV date_added, KEV vendor) share an id; negatives get -1."""
    ev = np.full(len(meta), -1)
    pos = np.flatnonzero(meta["label"].to_numpy() == 1)
    keys = [(kev.loc[c, "date_added"], kev.loc[c, "vendor"]) for c in meta["cve_id"].to_numpy()[pos]]
    ev[pos] = pd.factorize(pd.Series(keys))[0]
    return ev


def ci(arr, lo=5, hi=95):
    a, b = np.percentile(arr, [lo, hi])
    return float(a), float(b)


def fmt_ci(t):
    return f"[{t[0]:+.0f}, {t[1]:+.0f}]"


# ---- main -------------------------------------------------------------------------------------
def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    assert not check_feature_list(FEATURES_V4), check_feature_list(FEATURES_V4)
    assert "epss" not in FEATURES_V4
    data, sb, sb2, ctx = st.prepare(out_dir, data_dir)
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"]) \
        .drop_duplicates("cve_id").set_index("cve_id")

    # ---- 1-3. PSI, replacement, zero-history share
    rep2 = pd.concat([data[2024]["X2"], data[2025]["X2"]], ignore_index=True)
    psi_before = dfx.psi_table(rep2, sb2)
    replaced = dfx.replaced_features(psi_before)
    assert replaced == PSI_REPLACED, f"PSI now selects {replaced}; update schema.PSI_REPLACED deliberately"
    for y in (2024, 2025):
        data[y]["X4"] = dfx.to_v4(data[y]["X2"], replaced)[FEATURES_V4]
    sb4 = dfx.to_v4(sb2, replaced)[FEATURES_V4]
    rep4 = pd.concat([data[2024]["X4"], data[2025]["X4"]], ignore_index=True)
    psi_after = dfx.psi_table(rep4, sb4, features=FEATURES_V4).set_index("feature")["psi"]
    zero_hist = {"replica 2024": float((data[2024]["X2"]["assigner_prior_cves"] == 0).mean()),
                 "replica 2025": float((data[2025]["X2"]["assigner_prior_cves"] == 0).mean()),
                 "2026 scoreboard": float((sb2["assigner_prior_cves"] == 0).mean())}

    # ---- 4. selection with the same pre-set rule (training replica only)
    sel = {}
    for tr, te in DIRS:
        c = ctx[(tr, te)]
        c["p4"], _, ap_g = v1.select_lgbm(c["tr"]["X4"], c["tr"]["y"], c["tr"]["groups"], FEATURES_V4, f"v4 train {tr}")
        ap_l = average_precision_score(c["tr"]["y"], v1.lomo_oof("logreg", None, c["tr"]["X4"], c["tr"]["y"], c["tr"]["groups"], FEATURES_V4))
        choice, rel, why = v1.decide_model(ap_l, ap_g)
        sel[tr] = dict(ap_lr=ap_l, ap_lgbm=ap_g, choice=choice, rel=rel, params=c["p4"])
    print("selection done", {k: v["choice"] for k, v in sel.items()})

    # ---- directional evaluation: seed matrices, bags, logistic
    sc4, h4 = pooled_matrix(ctx, "X4", FEATURES_V4, "p4", BAG_SEEDS)            # new full model, seeds 0-19
    sc2, h2 = pooled_matrix(ctx, "X2", FEATURES_V2, "p2", BAG_SEEDS)            # old v2 (raw epss), seeds 0-19
    sc1, h1 = pooled_matrix(ctx, "X", v1.FEATURES, "p1", BAG_SEEDS)             # old v1 (raw epss), seeds 0-19
    notext = [f for f in FEATURES_V4 if f not in TEXT_FEATURES]
    notext_old = [f for f in FEATURES_V2 if f not in TEXT_FEATURES]
    _, hnt = pooled_matrix(ctx, "X4", notext, "p4", BAG_SEEDS)                  # new, no text, seeds 0-19
    _, hnt_old = pooled_matrix(ctx, "X2", notext_old, "p2", BAG_SEEDS)          # old, no text, seeds 0-19
    assert h2[0].sum() == 23 and h1[0].sum() == 17, "seed-0 references differ from the earlier reports"
    bag4 = {d: bag(sc4[d]) for d in DIRS}
    bag2 = {d: bag(sc2[d]) for d in DIRS}
    lr4 = {d: v1.fit_predict("logreg", None, ctx[d]["tr"]["X4"], ctx[d]["tr"]["y"], ctx[d]["te"]["X4"], FEATURES_V4) for d in DIRS}
    base_dir = [topk_base(ctx[d]) for d in DIRS]
    base_pool = sum(base_dir)
    bag4_dir = [st.hits_of(ctx[d], bag4[d]) for d in DIRS]
    bag2_dir = [st.hits_of(ctx[d], bag2[d]) for d in DIRS]
    lr4_dir = [st.hits_of(ctx[d], lr4[d]) for d in DIRS]
    s0_dir = list(h4[0])
    s0_old_dir = list(h2[0])
    print(f"baseline {base_pool}; v4 bag {sum(bag4_dir)}; v4 seed0 {sum(s0_dir)}; v4 20-seed mean {h4.sum(1).mean():.1f}; "
          f"old v2 bag {sum(bag2_dir)}, old seed0 {sum(s0_old_dir)}, old 20-seed mean {h2.sum(1).mean():.1f}")

    # ---- bootstrap: CVE-level and event-clustered, paired against the baseline and the previous v2
    names = ["baseline", "v4 bag", "old v2 bag", "old v2 seed 0", "v4 seed 0", "v4 logistic"]
    Bcve, Bev = {}, {}
    for j, d in enumerate(DIRS):
        c = ctx[d]
        meta = c["meta"].reset_index(drop=True).assign(
            bag4=bag4[d], bag2=bag2[d], s0_old=sc2[d][0], s0_new=sc4[d][0], lr4=lr4[d])
        cols = [["exploit_epss"], ["bag4", "epss_rank_in_month"], ["bag2", "epss_rank_in_month"],
                ["s0_old", "epss_rank_in_month"], ["s0_new", "epss_rank_in_month"], ["lr4", "epss_rank_in_month"]]
        pos = [v1.rank_pos(meta, cc) for cc in cols]
        Bcve[d] = paired_bootstrap_hits(meta["label"].to_numpy(), pos, c["k"], n=v1.N_BOOT, seed=0)
        Bev[d] = clustered_paired_bootstrap_hits(meta["label"].to_numpy(), kev_events(meta, kev), pos, c["k"], n=v1.N_BOOT, seed=0)
    ix = {n: i for i, n in enumerate(names)}

    def pdiff(B, a, b):
        return sum(B[d][:, ix[a]] - B[d][:, ix[b]] for d in DIRS)

    iv = {}
    for a, b in [("v4 bag", "baseline"), ("old v2 bag", "baseline"), ("v4 bag", "old v2 bag"), ("v4 bag", "old v2 seed 0"),
                 ("v4 seed 0", "baseline"), ("v4 logistic", "baseline")]:
        iv[(a, b)] = (ci(pdiff(Bcve, a, b)), ci(pdiff(Bev, a, b)))
    n_events = {}
    for d in DIRS:
        ev_ids = kev_events(ctx[d]["meta"].reset_index(drop=True), kev)
        n_events[d[1]] = int(np.unique(ev_ids[ev_ids >= 0]).size)

    # ---- stress tests (3c redone on the new set)
    # ablation: 10-seed means (seeds 1-10), fixed params, no re-tuning; full and no-text come from the 20-seed runs
    def abl_table(ctx_, key, feats_all, pkey, h_full, h_nt):
        rows = {}
        for name, drop in DROPS.items():
            if name == "full":
                m = h_full[ABL_SEEDS]
            elif name == "-all text":
                m = h_nt[ABL_SEEDS]
            else:
                m = hits_by_seed(ctx_, key, [f for f in feats_all if f not in drop], pkey, ABL_SEEDS)
            rows[name] = m
        return rows

    abl_new = abl_table(ctx, "X4", FEATURES_V4, "p4", h4, hnt)
    abl_old = abl_table(ctx, "X2", FEATURES_V2, "p2", h2, hnt_old)
    print("ablation done")

    # placebo: shuffle the 16 text columns jointly within month, train and test frames separately
    null = []
    for rep in range(N_PLACEBO):
        rng = np.random.default_rng(rep)
        h = []
        for d in DIRS:
            c = ctx[d]
            Xtr = st.shuffle_text_within_month(c["tr"]["X4"], c["tr_months"], TEXT_FEATURES, rng)
            Xte = st.shuffle_text_within_month(c["te"]["X4"], c["months"], TEXT_FEATURES, rng)
            m = v1.lgbm_model(c["p4"], FEATURES_V4, seed=0).fit(Xtr[FEATURES_V4], c["tr"]["y"])
            h.append(st.hits_of(c, m.predict_proba(Xte[FEATURES_V4])[:, 1]))
        null.append((rep, h[0], h[1], sum(h)))
    plc = pd.DataFrame(null, columns=["seed", "hits_test2025", "hits_test2024", "pooled_hits"])
    plc.to_csv(out_dir / "v4_placebo.csv", index=False)
    real_mean = float(h4.sum(1).mean())
    p_val = float((plc["pooled_hits"] >= real_mean).mean())
    p_seed0 = float((plc["pooled_hits"] >= h4[0].sum()).mean())
    p_bag = float((plc["pooled_hits"] >= sum(bag4_dir)).mean())
    old_null = pd.read_csv(out_dir / "v2_placebo.csv")
    old_p = float((old_null["pooled_hits"] >= h2.sum(1).mean()).mean())
    print(f"placebo: null mean {plc.pooled_hits.mean():.1f}, p = {p_val:.2f} (old p {old_p:.2f})")

    # mechanism (new bag vs baseline), events
    mech, group_tab = mechanism(ctx, bag4, bag2, sc2, kev)
    mech.to_csv(out_dir / "v4_mechanism.csv", index=False)

    # leakage audit
    leak_items, leak_tabs = st.leakage_audit(data, data_dir, features=FEATURES_V4)
    leakage_found = any(f for _, _, f in leak_items)

    # ---- final model: both replicas, pooled-AP selection, 20-seed bag
    X_all = pd.concat([data[2024]["X4"], data[2025]["X4"]], ignore_index=True)
    y_all = np.concatenate([data[2024]["y"], data[2025]["y"]])
    g_month = np.array([g[-2:] for g in np.concatenate([data[2024]["groups"], data[2025]["groups"]])])
    params, _, ap_final = v1.select_lgbm(X_all, y_all, g_month, FEATURES_V4, "v4 final (both replicas, month folds)")
    models = [v1.lgbm_model(params, FEATURES_V4, seed=s).fit(X_all[FEATURES_V4], y_all) for s in BAG_SEEDS]
    sbm = sb4.assign(cve_id=sb["cve_id"].to_numpy())
    sbm["s"] = bag([m.predict_proba(sbm[FEATURES_V4])[:, 1] for m in models])
    ranked = rank_order(sbm, ["s", "epss_rank_in_month"]).head(500)
    final_ids = ranked["cve_id"].tolist()

    # ---- policy
    vetoes = []
    if p_val > PLACEBO_P_MAX:
        vetoes.append(f"placebo p = {p_val:.2f} > {PLACEBO_P_MAX}")
    if h4.sum(1).mean() < base_pool:
        vetoes.append(f"20-seed mean pooled hits {h4.sum(1).mean():.1f} < best baseline {base_pool}")
    if leakage_found:
        vetoes.append("leakage check flagged: " + "; ".join(n for n, _, f in leak_items if f))
    primary = "v4: 20-seed LightGBM bag, no raw EPSS" if not vetoes else "v3 retained (v4 vetoed)"
    pd.DataFrame({"cve_id": final_ids}).to_csv(out_dir / "top500_v4.csv", index=False)
    idx = pd.Series(np.arange(len(sbm)), index=sbm["cve_id"]).loc[final_ids].to_numpy()
    contrib = np.mean([m.booster_.predict(sbm.iloc[idx][FEATURES_V4], pred_contrib=True)[:, :-1] for m in models], axis=0)
    pd.DataFrame(contrib, columns=FEATURES_V4).assign(cve_id=final_ids)[["cve_id", *FEATURES_V4]].to_parquet(
        out_dir / "v4_top500_contrib.parquet", index=False)
    v3_ids = pd.read_csv(out_dir / "top500_v3.csv")["cve_id"].tolist()
    base_ids = pd.read_csv(out_dir / "top500_v0.csv")["cve_id"].tolist()
    v2_ids = pd.read_csv(out_dir / "top500_v2.csv")["cve_id"].tolist()
    fl = sbm.set_index("cve_id")
    flagged = lambda ids: int((fl.loc[ids, ["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1) == 1).sum())  # noqa: E731

    # ---- run log: relabel old rows, append v4 rows
    update_runlog(out_dir, bag4_dir, lr4_dir, base_dir, base_pool, ctx, iv, h4)
    headline = {
        "primary": primary, "model": "v4 LightGBM, 20-seed rank-averaged bag, no raw EPSS",
        "pooled_hits_bag": int(sum(bag4_dir)), "per_direction_bag": {"test2025": int(bag4_dir[0]), "test2024": int(bag4_dir[1])},
        "baseline_pooled_hits": int(base_pool), "baseline_per_direction": {"test2025": int(base_dir[0]), "test2024": int(base_dir[1])},
        "diff_vs_baseline_cve_level_90": list(iv[("v4 bag", "baseline")][0]),
        "diff_vs_baseline_event_clustered_90": list(iv[("v4 bag", "baseline")][1]),
        "single_seed_pooled_hits_mean_min_max": [round(float(h4.sum(1).mean()), 2), int(h4.sum(1).min()), int(h4.sum(1).max())],
        "placebo_p": p_val, "positives": {"2024": int(data[2024]["y"].sum()), "2025": int(data[2025]["y"].sum())},
        "note": "LOW POWER (75 positives). Use these numbers for headlines; seed-0 rows are not for headline."}
    (out_dir / "headline.json").write_text(json.dumps(headline, indent=1))

    # ---- report
    write_report(locals())
    print(f"policy: {primary}")
    return primary


def topk_base(c):
    return st.topk_hits(c["label"], c["meta"]["exploit_epss"], np.zeros(len(c["meta"])), c["code"], c["k"])


def mechanism(ctx, bag4, bag2, sc2, kev):
    """Hits by group for several rankings plus gained/lost CVEs of the v4 bag vs the baseline, grouped by KEV event."""
    tab, rows = [], []
    for d in DIRS:
        c = ctx[d]
        meta = c["meta"].reset_index(drop=True)
        k = c["k"]
        grp = pd.Series(st.group_of(meta, k), index=meta["cve_id"])
        tops = {"baseline": set(rank_order(meta, ["exploit_epss"]).head(k)["cve_id"])}
        for name, s in [("old v2 seed 0", sc2[d][0]), ("old v2 bag", bag2[d]), ("v4 bag", bag4[d])]:
            tops[name] = set(rank_order(meta.assign(s=s), ["s", "epss_rank_in_month"]).head(k)["cve_id"])
        pos = meta.loc[meta["label"] == 1, "cve_id"]
        for g in ["flagged", "unflagged, EPSS-visible", "blind-spot"]:
            ids = set(grp.loc[pos][grp.loc[pos] == g].index)
            tab.append((d[1], g, len(ids), *[len(ids & tops[n]) for n in ("baseline", "old v2 seed 0", "old v2 bag", "v4 bag")]))
        tab.append((d[1], "all positives", len(pos), *[len(set(pos) & tops[n]) for n in ("baseline", "old v2 seed 0", "old v2 bag", "v4 bag")]))
        eom = pd.to_datetime(meta.set_index("cve_id")["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0)
        posset = set(pos)
        for kind, ids in [("gained", (tops["v4 bag"] - tops["baseline"]) & posset), ("lost", (tops["baseline"] - tops["v4 bag"]) & posset)]:
            for cid in sorted(ids):
                rows.append(dict(test_replica=d[1], kind=kind, cve_id=cid, group=grp[cid], kev_vendor=kev.loc[cid, "vendor"],
                                 kev_date_added=kev.loc[cid, "date_added"],
                                 days_to_kev=(pd.Timestamp(kev.loc[cid, "date_added"]) - eom[cid]).days))
    return pd.DataFrame(rows), tab


def update_runlog(out_dir, bag4_dir, lr4_dir, base_dir, base_pool, ctx, iv, h4):
    path = out_dir / "runlog.csv"
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    for i in df.index[df["version"].str.startswith(("v1_", "v2_"))]:
        notes, v = df.at[i, "notes"], df.at[i, "version"]
        pre = []
        if "pre-drift-fix" not in notes:
            pre.append("pre-drift-fix (raw epss included)")
        if v.endswith("lgbm") and "seed0 only" not in notes:
            pre.append("seed0 only, not for headline")
        elif v.endswith("logreg") and "not for headline" not in notes:
            pre.append("not for headline")
        df.at[i, "notes"] = "; ".join(pre + [notes]) if pre else notes
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (cv, ev) = iv[("v4 bag", "baseline")]
    new = []
    for j, (name, tr, te, _) in enumerate(v1.DIRECTIONS):
        k = ctx[(tr, te)]["k"]
        new.append(dict(timestamp=now, version="v4_bag", replica=name, k=k, hits=bag4_dir[j], baseline_exploit_epss_hits=base_dir[j],
                        notes="low power; 20-seed LightGBM bag, no raw epss, rank-averaged; headline model"))
        new.append(dict(timestamp=now, version="v4_logreg", replica=name, k=k, hits=lr4_dir[j], baseline_exploit_epss_hits=base_dir[j],
                        notes="low power; v4 features, deterministic logistic regression; not the final model"))
    new.append(dict(timestamp=now, version="v4_bag", replica="pooled", k=sum(ctx[d]["k"] for d in DIRS), hits=sum(bag4_dir),
                    baseline_exploit_epss_hits=base_pool,
                    notes=(f"low power; pooled over both directions; 20-seed bag; diff vs best baseline: CVE-level 90% {fmt_ci(cv)}, "
                           f"event-clustered 90% {fmt_ci(ev)}; single-seed pooled mean {h4.sum(1).mean():.1f} "
                           f"(min {h4.sum(1).min()}, max {h4.sum(1).max()})")))
    new_df = pd.DataFrame(new).astype(str)
    key = lambda d: set(zip(d["version"], d["replica"], d["hits"], d["notes"]))  # noqa: E731
    keep = [kk not in key(df) for kk in zip(new_df["version"], new_df["replica"], new_df["hits"], new_df["notes"])]
    pd.concat([df, new_df[keep]], ignore_index=True).to_csv(path, index=False)


def write_report(g):
    """Assemble outputs/v4_report.md from the locals of main()."""
    out_dir, FEATURES_V4_, ctx, sel = g["out_dir"], FEATURES_V4, g["ctx"], g["sel"]
    h4, h2, h1, hnt, hnt_old = g["h4"], g["h2"], g["h1"], g["hnt"], g["hnt_old"]
    base_dir, base_pool, bag4_dir, bag2_dir, lr4_dir = g["base_dir"], g["base_pool"], g["bag4_dir"], g["bag2_dir"], g["lr4_dir"]
    iv, plc, p_val, vetoes, primary = g["iv"], g["plc"], g["p_val"], g["vetoes"], g["primary"]
    abl_new, abl_old, old_p, old_null = g["abl_new"], g["abl_old"], g["old_p"], g["old_null"]
    psi_before, psi_after, zero_hist, replaced = g["psi_before"], g["psi_after"], g["zero_hist"], g["replaced"]
    mech, group_tab, leak_items, leak_tabs, leakage_found = g["mech"], g["group_tab"], g["leak_items"], g["leak_tabs"], g["leakage_found"]
    params, ap_final, data = g["params"], g["ap_final"], g["data"]
    final_ids, v3_ids, base_ids, v2_ids, flagged = g["final_ids"], g["v3_ids"], g["base_ids"], g["v2_ids"], g["flagged"]
    n_events, p_seed0, p_bag = g["n_events"], g["p_seed0"], g["p_bag"]
    real_mean = h4.sum(1).mean()

    def stats(h):
        t = h.sum(1)
        return f"{t.mean():.1f} / {t.min()} / {t.max()}"

    def seedmean(m):
        return f"{m.sum(1).mean():.1f}"

    cv, ev = iv[("v4 bag", "baseline")]
    cv_old, ev_old = iv[("old v2 bag", "baseline")]
    pts = (p_val <= 0.05) + (int(h4.sum(1).min()) >= base_pool) + (ev[0] > 0)
    strength = ["WEAK", "WEAK", "MODERATE", "STRONG"][int(pts)]
    L = ["# v4 report: drift-robust feature set, 20-seed bag, stress tests redone", "",
         "> **LOW POWER.** 27 (2024) and 48 (2025) positives, 75 in total. Directions: train 2024 -> test 2025 (forward in time) and "
         "train 2025 -> test 2024 (stability check, not forward in time). Hits are in the top k (198 for 2024, 243 for 2025). "
         "Headline numbers are the 20-seed bag or multi-seed means; seed-0 single runs are labelled and not for headline. "
         "**Everything labelled 'pre-drift-fix' (raw epss included) is superseded and must not be used in a headline.**", "",
         "## Decisions and policy (declared before the numbers)", "",
         "1. Raw `epss` is removed (it moved ~4x in 2026); `epss_rank_in_month` and `epss_missing` stay.",
         f"2. Scale-type features with PSI > 0.25 (pooled replicas vs 2026 scoreboard) are replaced by their within-pool percentile rank: "
         f"**{', '.join(replaced)}**.",
         "3. Hyper-parameters use the same pre-set rule (pooled-AP on the training replica; final model pooled-AP over both replicas); nothing is tuned on a test replica.",
         "4. The final model is a 20-seed LightGBM bag (each seed's scores rank-normalised within the pool, then averaged). It is chosen because bagging "
         "removes seed luck, not because of its hits. `kev_text_score` and `nearest_kev_sim` stay in the set (neutral within noise, see the ablation).",
         f"5. v4 replaces v3 as primary unless: (i) placebo p > {PLACEBO_P_MAX}; (ii) the 20-seed mean of single-seed pooled hits is below the baseline's ({base_pool}); "
         "(iii) leakage is found. v3 vs v4 is not decided by comparing test hits.", "",
         md(["veto condition", "value", "triggered?"],
            [(f"(i) placebo p (fraction of {N_PLACEBO} null runs with pooled hits >= the 20-seed mean {real_mean:.1f})", f"{p_val:.2f}", "YES" if p_val > PLACEBO_P_MAX else "no"),
             (f"(ii) 20-seed mean single-seed pooled hits vs baseline {base_pool}", f"{real_mean:.1f}", "YES" if real_mean < base_pool else "no"),
             ("(iii) leakage found", "yes" if leakage_found else "no", "YES" if leakage_found else "no")]), "",
         f"**Policy outcome: {primary}.** " + ("No veto condition was triggered." if not vetoes else "Vetoes: " + "; ".join(vetoes) + "."), "",
         "## Headline (20-seed bag; use these numbers, not seed-0 rows)", "",
         f"The v4 bag has **{sum(bag4_dir)} pooled hits** ({bag4_dir[0]} on test 2025, {bag4_dir[1]} on test 2024) against the baseline's **{base_pool}** "
         f"({base_dir[0]} + {base_dir[1]}): {sum(bag4_dir) - base_pool:+d}, with a 90% interval of {fmt_ci(cv)} (CVE-level paired bootstrap) and {fmt_ci(ev)} "
         f"(event-clustered bootstrap). Single seeds average {h4.sum(1).mean():.1f} (min {h4.sum(1).min()}, max {h4.sum(1).max()}). Evidence strength: **{strength}**.", ""]

    L += ["## Drift: PSI of every v2 feature (pooled replicas vs 2026 scoreboard)", "",
          "10 bins from the replicas (spike-aware: a value holding >= 10% of the replica rows, usually 0, gets its own bin; binary flags use one bin per value). "
          "PSI > 0.25 is a large shift. Scale-type = counts or raw scores (not binary flags, not an existing percentile rank). "
          "`b/drift.py` reports raw EPSS PSI 1.70 against the 2025 replica alone; pooled replicas give 2.87 here.", "",
          md(["feature", "type", "PSI before", "decision", "PSI after (v4 column)"],
             [(r.feature, r.kind, f"{r.psi:.3f}",
               "**removed**" if r.feature in ("epss",) else ("**replaced by percentile rank**" if r.feature in replaced else "kept"),
               f"{psi_after[dfx.rank_name(r.feature)]:.3f}" if r.feature in replaced else (f"{psi_after[r.feature]:.3f}" if r.feature in psi_after.index else "")) for r in psi_before.itertuples()]), "",
          *(["**The percentile-rank replacement did not reduce PSI for every replaced feature:** " +
             ", ".join(f"{f} ({psi_before.set_index('feature').loc[f, 'psi']:.2f} -> {psi_after[dfx.rank_name(f)]:.2f})" for f in replaced
                       if psi_after[dfx.rank_name(f)] > psi_before.set_index('feature').loc[f, 'psi']) +
             " got worse. These features are tie-heavy (zeros, or one value per snapshot month for days_to_cutoff), so a within-pool rank moves the pile "
             "of tied values to a different position in each pool instead of removing the difference. The replacement was applied as pre-specified; "
             "it should not be read as having fixed the shift for these columns.", ""]
            if any(psi_after[dfx.rank_name(f)] > psi_before.set_index("feature").loc[f, "psi"] for f in replaced) else []),
          "### Share of CVEs whose assigner has zero history (`assigner_prior_cves == 0`)", "",
          md(["pool", "share"], [(k, f"{v:.1%}") for k, v in zero_hist.items()]), "",
          "The 2024 replica has far more CVEs from assigners with no prior CVEs than either the 2025 replica or the 2026 scoreboard, so a model trained on 2024 "
          "sees an assigner-history regime the 2026 pool does not have; the 2025 replica resembles 2026.", ""]

    L += ["## Selection (same pre-set rule, training replica only)", "",
          md(["training replica", "OOF AP logreg", "OOF AP LightGBM", "relative gap", "rule would pick", "LightGBM params"],
             [(y, f"{s['ap_lr']:.4f}", f"{s['ap_lgbm']:.4f}", f"{s['rel']:.0%}", s["choice"], json.dumps(s["params"])) for y, s in sel.items()]), "",
          "The final model is the LightGBM bag by pre-declaration (see policy); the rule's pick is shown for information.", ""]

    L += ["## Directional results on the new feature set", "",
          md(["ranking", "test 2025", "test 2024", "pooled", "diff vs baseline (90%: CVE-level / event-clustered)"],
             [("Exploit code, then EPSS (baseline)", *base_dir, base_pool, ""),
              ("**v4 20-seed bag (headline)**", *bag4_dir, sum(bag4_dir), f"{sum(bag4_dir) - base_pool:+d}  {fmt_ci(cv)} / {fmt_ci(ev)}"),
              ("v4 single seeds 0-19, mean per direction", f"{h4[:, 0].mean():.1f}", f"{h4[:, 1].mean():.1f}", f"{h4.sum(1).mean():.1f}", f"{h4.sum(1).mean() - base_pool:+.1f}"),
              ("v4 logistic regression (deterministic)", *lr4_dir, sum(lr4_dir), f"{sum(lr4_dir) - base_pool:+d}  {fmt_ci(iv[('v4 logistic', 'baseline')][0])} / {fmt_ci(iv[('v4 logistic', 'baseline')][1])}"),
              ("previous v2 20-seed bag (pre-drift-fix)", *bag2_dir, sum(bag2_dir), f"{sum(bag2_dir) - base_pool:+d}  {fmt_ci(cv_old)} / {fmt_ci(ev_old)}"),
              ("v4 seed 0 only (not for headline)", *[int(x) for x in h4[0]], int(h4[0].sum()), ""),
              ("previous v2 seed 0 only (pre-drift-fix, not for headline)", *[int(x) for x in h2[0]], int(h2[0].sum()), "")]), "",
          "The deterministic logistic regression has more pooled hits than the bag; choosing it now would be selecting by test hits, which the policy forbids. "
          "If the team wants a different final model type, decide it by a rule fixed in advance. "
          f"Paired differences of the v4 bag (pooled; CVE-level / event-clustered 90% intervals): vs the previous v2 bag (pre-drift-fix) "
          f"{sum(bag4_dir) - sum(bag2_dir):+d} {fmt_ci(iv[('v4 bag', 'old v2 bag')][0])} / {fmt_ci(iv[('v4 bag', 'old v2 bag')][1])}; "
          f"vs the previous v2 seed 0 (pre-drift-fix, not for headline) {sum(bag4_dir) - int(h2[0].sum()):+d} "
          f"{fmt_ci(iv[('v4 bag', 'old v2 seed 0')][0])} / {fmt_ci(iv[('v4 bag', 'old v2 seed 0')][1])}. "
          f"The event-clustered bootstrap groups the positives into {sum(n_events.values())} KEV events "
          f"({n_events.get(2025, '?')} in the 2025 replica, {n_events.get(2024, '?')} in 2024) by (KEV date added, KEV vendor), resamples events "
          "together and resamples negatives iid; it is the more conservative interval.", ""]

    # single comparison table old vs new
    def abl_row(name):
        return (name, seedmean(abl_old[name]), seedmean(abl_new[name]))

    L += ["## Old vs new in one table (does removing raw EPSS change anything?)", "",
          "Old = pre-drift-fix (legacy v2 set with raw epss, 34 features). New = v4 set (33 features, no raw epss, 5 features rank-replaced). "
          "Fixed parameters from the pre-set rule on each set; same seeds; same directions.", "",
          md(["quantity", "old (pre-drift-fix)", "new (v4)"],
             [("features", len(V2_FEATURES), len(FEATURES_V4_)),
              ("20-seed bag pooled hits (test 2025 + test 2024)", f"{sum(bag2_dir)} ({bag2_dir[0]} + {bag2_dir[1]})", f"**{sum(bag4_dir)}** ({bag4_dir[0]} + {bag4_dir[1]})"),
              ("bag minus baseline, CVE-level 90% interval", f"{sum(bag2_dir) - base_pool:+d} {fmt_ci(cv_old)}", f"{sum(bag4_dir) - base_pool:+d} {fmt_ci(cv)}"),
              ("bag minus baseline, event-clustered 90% interval", f"{sum(bag2_dir) - base_pool:+d} {fmt_ci(ev_old)}", f"{sum(bag4_dir) - base_pool:+d} {fmt_ci(ev)}"),
              ("single-seed pooled hits, 20 seeds: mean / min / max", stats(h2), stats(h4)),
              ("seed 0 pooled hits (not for headline)", int(h2[0].sum()), int(h4[0].sum())),
              ("v1-style (no text) 20-seed pooled hits: mean / min / max", f"{stats(h1)} (legacy v1, own params)", f"{stats(hnt)} (v4 minus text)"),
              ("ablation 10-seed mean: full", *abl_row("full")[1:]), ("ablation: -kev_text_score", *abl_row("-kev_text_score")[1:]),
              ("ablation: -nearest_kev_sim", *abl_row("-nearest_kev_sim")[1:]), ("ablation: -txt_ flags", *abl_row("-txt_ flags")[1:]),
              ("ablation: -all text", *abl_row("-all text")[1:]),
              ("placebo null mean / 95th percentile", f"{old_null['pooled_hits'].mean():.1f} / {old_null['pooled_hits'].quantile(0.95):.0f}",
               f"{plc['pooled_hits'].mean():.1f} / {plc['pooled_hits'].quantile(0.95):.0f}"),
              ("placebo p vs the 20-seed mean of real single-seed hits", f"{old_p:.2f}", f"{p_val:.2f}"),
              ("leakage flags", "none", "none" if not leakage_found else "FLAGGED")]), "",
          "Baseline for reference: " + f"{base_pool} pooled hits ({base_dir[0]} on 2025, {base_dir[1]} on 2024).", ""]

    L += ["## Stress tests on the new feature set", "", "### Seed distribution (single seeds 0-19, fixed parameters) next to the baseline", "",
          md(["model", "mean pooled", "min", "max"],
             [("baseline (no seeds)", base_pool, base_pool, base_pool),
              ("legacy v1 (raw epss; pre-drift-fix)", f"{h1.sum(1).mean():.1f}", h1.sum(1).min(), h1.sum(1).max()),
              ("legacy v2 (raw epss; pre-drift-fix)", f"{h2.sum(1).mean():.1f}", h2.sum(1).min(), h2.sum(1).max()),
              ("v1-style new: v4 minus text", f"{hnt.sum(1).mean():.1f}", hnt.sum(1).min(), hnt.sum(1).max()),
              ("**v4 (full new set)**", f"{h4.sum(1).mean():.1f}", h4.sum(1).min(), h4.sum(1).max()),
              ("v4 20-seed bag", sum(bag4_dir), sum(bag4_dir), sum(bag4_dir))]), "",
          "### Text ablation on the new set (10-seed means, seeds 1-10, fixed parameters, no re-tuning)", "",
          md(["variant", "mean pooled", "min", "max", "mean test 2025", "mean test 2024"],
             [(n, seedmean(m), m.sum(1).min(), m.sum(1).max(), f"{m[:, 0].mean():.1f}", f"{m[:, 1].mean():.1f}") for n, m in abl_new.items()]), "",
          "### Placebo: the 16 text columns shuffled jointly within snapshot month (50 repeats)", "",
          md(["quantity", "value"],
             [("null mean of pooled hits", f"{plc['pooled_hits'].mean():.2f}"), ("null 95th percentile", f"{plc['pooled_hits'].quantile(0.95):.1f}"),
              ("null min / max", f"{plc['pooled_hits'].min()} / {plc['pooled_hits'].max()}"),
              ("real: 20-seed mean of single-seed pooled hits (veto reference)", f"{real_mean:.1f}"),
              ("p = fraction of null runs >= that mean", f"{p_val:.2f}"),
              ("p vs seed-0 real / vs the bag's hits (for context)", f"{p_seed0:.2f} / {p_bag:.2f}"),
              ("no-text model next to the null: 10-seed mean / 20-seed mean", f"{seedmean(abl_new['-all text'])} / {hnt.sum(1).mean():.1f}")]), "",
          "Shuffled text columns act as noise features, so the null is expected at or below the no-text model; p therefore measures 'real text beats noise text', "
          "a more lenient test than 'text beats no text' (compare the no-text row to the full model). The bag's own hits are matched by "
          f"{p_bag:.0%} of the single-seed null runs, which is not a like-for-like comparison but shows how little room there is. Null distribution (counts): " +
          ", ".join(f"{int(k)}: {int(v)}" for k, v in plc["pooled_hits"].value_counts().sort_index().items()) + ".", "",
          "### Mechanism: where do the hits come from? (test replicas; models trained on the other replica)", "",
          "Groups: flagged = any public exploit flag; blind-spot = no flag and within-month EPSS rank below the cut a top-k EPSS list makes; "
          "unflagged-EPSS-visible = no flag but above that cut.", "",
          md(["test replica", "group of positives", "positives", "baseline", "previous v2 seed 0", "previous v2 bag", "v4 bag"], group_tab), ""]
    ev_rows = []
    for (te, kind, vendor, date), d in mech.groupby(["test_replica", "kind", "kev_vendor", "kev_date_added"], sort=True):
        ev_rows.append((te, kind, vendor, date, len(d), d["group"].iloc[0], ", ".join(d["cve_id"].head(3)) + (" ..." if len(d) > 3 else "")))
    L += ["Hits gained (in the v4 bag's top k, not the baseline's) and lost (the reverse), grouped by KEV event (same vendor and date added); "
          "full CVE list in `outputs/v4_mechanism.csv`. Vendor and dates are post-snapshot facts shown for description only.", "",
          md(["test replica", "kind", "KEV vendor", "date added", "CVEs", "group", "CVE ids"], ev_rows), ""]
    n_g = {(t, k): len(d) for (t, k), d in mech.groupby(["test_replica", "kind"])}
    e_g = {(t, k): d[["kev_vendor", "kev_date_added"]].drop_duplicates().shape[0] for (t, k), d in mech.groupby(["test_replica", "kind"])}
    L += ["(CVEs, events): " + "; ".join(f"test {t} {k}: ({n_g[(t, k)]}, {e_g[(t, k)]})" for (t, k) in sorted(n_g)) + ".", ""]

    L += ["### Leakage audit (same pre-declared rules as step 3c, new feature list)", "",
          md(["check", "result", "flagged"], [(n, r, "**YES**" if f else "no") for n, r, f in leak_items]), "",
          "Limit: the Granite embeddings are not available locally, so `kev_text_score` and `nearest_kev_sim` were not recomputed; their time-safety rests on "
          "Person B's code (classifier for pool year Y trains only on CVEs published before Y-01-01 labelled with KEV `date_added` <= (Y-1)-12-31; "
          "`nearest_kev_sim` uses KEV rows with `date_added` <= (Y-1)-12-31). Descriptions are the current NVD text.", ""]

    L += ["## Final list: `outputs/top500_v4.csv`", "",
          md(["item", "value"],
             [("model", "20-seed LightGBM bag on both replicas, v4 features, parameters from the pooled-AP selection"),
              ("parameters", f"`{json.dumps(params)}`"), ("pooled OOF AP of the selection", f"{ap_final:.4f}"),
              ("ranking rule", "bag score, then epss_rank_in_month, then cve_id"),
              ("overlap with top500_v3", len(set(final_ids) & set(v3_ids))), ("overlap with the baseline top 500", len(set(final_ids) & set(base_ids))),
              ("overlap with top500_v2 (two-channel hybrid)", len(set(final_ids) & set(v2_ids))),
              ("CVEs with an exploit flag: v4 list vs baseline list", f"{flagged(final_ids)} vs {flagged(base_ids)}"),
              ("contributions", "`outputs/v4_top500_contrib.parquet` (LightGBM pred_contrib averaged over the 20 seeds, one column per feature)")]), "",
          "## How strong is the evidence?", "",
          f"**{strength}.** The v4 20-seed bag has {sum(bag4_dir)} pooled hits against the baseline's {base_pool} "
          f"({sum(bag4_dir) - base_pool:+d}; CVE-level 90% interval {fmt_ci(cv)}, event-clustered {fmt_ci(ev)}). "
          f"Single seeds average {h4.sum(1).mean():.1f} (min {h4.sum(1).min()}, max {h4.sum(1).max()}), and the placebo null mean is {plc['pooled_hits'].mean():.1f} with p = {p_val:.2f}. "
          f"Removing raw EPSS moved the bag from {sum(bag2_dir)} to {sum(bag4_dir)} pooled hits ({sum(bag4_dir) - sum(bag2_dir):+d}) and the single-seed mean from "
          f"{h2.sum(1).mean():.1f} to {h4.sum(1).mean():.1f}. "
          f"The event-clustered interval {'excludes' if ev[0] > 0 else 'includes'} zero, so a gain over the baseline "
          f"{'is' if ev[0] > 0 else 'is not'} established at 90% once correlated KEV events are respected. "
          f"Text ablation (10-seed means): full {seedmean(abl_new['full'])}, without kev_text_score {seedmean(abl_new['-kev_text_score'])}, without nearest_kev_sim "
          f"{seedmean(abl_new['-nearest_kev_sim'])}, without the txt_ flags {seedmean(abl_new['-txt_ flags'])}, without any text {seedmean(abl_new['-all text'])}; "
          "differences of 1-2 hits are within seed noise. With 75 positives from a handful of KEV events, treat any improvement over the baseline as uncertain."]
    (out_dir / "v4_report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
