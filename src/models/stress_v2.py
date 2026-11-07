"""Step 3c: stress-test v2 LightGBM and write the final candidate list.  Run: python -m src.models.stress_v2

No hyper-parameter is tuned on test data. Directional checks use the parameters already selected by the pre-set
rule on each TRAINING replica (cached in outputs/.cache); the final model uses the pooled-AP selection on both
replicas (month folds), as v1 did. LOW POWER: 27 + 48 = 75 positives.

Pre-declared final-list policy (decided before these checks ran):
  primary candidate = v2 LightGBM trained on BOTH replicas with the pooled-AP-selected parameters.
  vetoed only if (i) placebo p-value > 0.20, or (ii) the 10-seed mean of pooled hits is below the best
  baseline's pooled hits, or (iii) any leakage is found. If vetoed, fall back to the two-channel hybrid
  (outputs/top500_v2.csv). Candidates are never chosen by comparing their test hits.
"""
import json
import re

import duckdb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from src.b.phrases import POST_ATTACK, strip_post_attack
from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import TEXT_FEATURES, check_feature_list
from src.common.scoring import k_for_pool, rank_order
from src.models import train_v1 as v1
from src.models.train_v2 import FEATURES_V2, load_with_text

DIRS = [(2024, 2025), (2025, 2024)]  # (train replica, test replica)
SEEDS = list(range(1, 11))  # seed 0 is the reference run used everywhere else
N_PLACEBO = 50
PLACEBO_P_MAX, SMD_FLAG, AUC_FLAG = 0.20, 0.5, 0.95
TXT_FLAGS = [c for c in TEXT_FEATURES if c.startswith("txt_")]
DROPS = {"none (full v2)": [], "-kev_text_score": ["kev_text_score"], "-nearest_kev_sim": ["nearest_kev_sim"],
         "-txt_ flags": TXT_FLAGS, "-all text": TEXT_FEATURES}


# ---- helpers ----------------------------------------------------------------------------------
def topk_hits(label, score, tie_rank, cve_code, k) -> int:
    """Hits in the top k, ordering by score desc, tie_rank desc, then cve_id asc (same rule as rank_order)."""
    order = np.lexsort((cve_code, -np.asarray(tie_rank), -np.asarray(score)))
    return int(np.asarray(label)[order[:k]].sum())


def within_month_permutation(months, rng) -> np.ndarray:
    """perm such that row i takes the values of row perm[i]; perm[i] is always in the same month as i."""
    months = np.asarray(months)
    perm = np.arange(len(months))
    for m in np.unique(months):
        idx = np.flatnonzero(months == m)
        perm[idx] = rng.permutation(idx)
    return perm


def shuffle_text_within_month(X, months, cols, rng):
    """Shuffle the given columns JOINTLY (one permutation for all of them) across rows within each month."""
    perm = within_month_permutation(months, rng)
    X = X.copy()
    for c in cols:
        X[c] = X[c].to_numpy()[perm]
    return X


def smd(a: pd.Series, b: pd.Series) -> float:
    """Standardised mean difference (b - a) / pooled sd, NaN-safe; 0 when both are constant."""
    sd = np.sqrt((a.var() + b.var()) / 2)
    return 0.0 if not sd or np.isnan(sd) else float((b.mean() - a.mean()) / sd)


def md_table(headers, rows):
    return v1.md(headers, rows)


# ---- context ----------------------------------------------------------------------------------
def prepare(out_dir, data_dir):
    data, sb, sb2 = load_with_text(out_dir, data_dir)
    ctx = {}
    for tr, te in DIRS:
        dtr, dte = data[tr], data[te]
        p1 = v1.select_lgbm(dtr["X"], dtr["y"], dtr["groups"], v1.FEATURES, f"train {tr}")[0]
        p2 = v1.select_lgbm(dtr["X2"], dtr["y"], dtr["groups"], FEATURES_V2, f"v2 train {tr}")[0]
        meta = dte["meta"]
        ids = meta["cve_id"].to_numpy()
        ctx[(tr, te)] = dict(
            tr=dtr, te=dte, p1=p1, p2=p2, meta=meta, label=dte["y"], rank=meta["epss_rank_in_month"].to_numpy(),
            code=np.argsort(np.argsort(ids)), k=k_for_pool(len(meta)), months=dte["groups"], tr_months=dtr["groups"])
    return data, sb, sb2, ctx


def fit_scores(c, feats, params, tag, seed=0, Xtr=None, Xte=None):
    Xtr = c["tr"]["X2"] if Xtr is None else Xtr
    Xte = c["te"]["X2"] if Xte is None else Xte
    m = v1.lgbm_model(params, feats, seed=seed).fit(Xtr[feats], c["tr"]["y"])
    return m.predict_proba(Xte[feats])[:, 1]


def hits_of(c, score):
    return topk_hits(c["label"], score, c["rank"], c["code"], c["k"])


def pooled(ctx, fn):
    """fn(c) -> hits for one direction; returns (per-direction list, pooled sum)."""
    per = [fn(ctx[d]) for d in DIRS]
    return per, sum(per)


# ---- checks -----------------------------------------------------------------------------------
def group_of(meta, k):
    flags = meta[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1)
    blind = (flags == 0) & (meta["epss_rank_in_month"] < 1 - k / len(meta))
    return np.where(flags == 1, "flagged", np.where(blind, "blind-spot", "unflagged, EPSS-visible"))


def mechanism(ctx, preds, kev):
    rows, tables = [], []
    for (tr, te) in DIRS:
        c = ctx[(tr, te)]
        meta = c["meta"].reset_index(drop=True)
        k = c["k"]
        grp = group_of(meta, k)
        p = preds[preds["test_year"] == te].set_index("cve_id").reindex(meta["cve_id"])
        tops = {"baseline": set(rank_order(meta, ["exploit_epss"]).head(k)["cve_id"])}
        for name, col in [("v1_lgbm", "lgbm_v1"), ("v2_lgbm", "lgbm_v2")]:
            d = meta.assign(s=p[col].to_numpy())
            tops[name] = set(rank_order(d, ["s", "epss_rank_in_month"]).head(k)["cve_id"])
        pos = meta[meta["label"] == 1]
        pos_grp = pd.Series(grp, index=meta["cve_id"]).loc[pos["cve_id"]]
        for g in ["flagged", "unflagged, EPSS-visible", "blind-spot"]:
            ids = set(pos_grp[pos_grp == g].index)
            tables.append((te, g, len(ids), len(ids & tops["baseline"]), len(ids & tops["v1_lgbm"]), len(ids & tops["v2_lgbm"])))
        tables.append((te, "all positives", len(pos), *[len(set(pos["cve_id"]) & tops[n]) for n in ("baseline", "v1_lgbm", "v2_lgbm")]))
        eom = pd.to_datetime(meta.set_index("cve_id")["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0)
        for comp, new in [("v2_lgbm_vs_baseline", "v2_lgbm"), ("v1_lgbm_vs_baseline", "v1_lgbm")]:
            posset = set(pos["cve_id"])
            for kind, ids in [("gained", (tops[new] - tops["baseline"]) & posset), ("lost", (tops["baseline"] - tops[new]) & posset)]:
                for cid in sorted(ids):
                    kv = kev.loc[cid] if cid in kev.index else None
                    rows.append(dict(test_replica=te, comparison=comp, kind=kind, cve_id=cid, group=pos_grp[cid],
                                     kev_vendor=None if kv is None else kv["vendor"],
                                     kev_date_added=None if kv is None else kv["date_added"],
                                     days_to_kev=None if kv is None else (pd.Timestamp(kv["date_added"]) - eom[cid]).days))
    return pd.DataFrame(rows), tables


def leakage_audit(data, data_dir):
    """Returns (list of (check, result, flagged)) plus detail tables. Flags are pre-declared rules."""
    items, tables = [], {}
    probs = check_feature_list(FEATURES_V2)
    items.append(("feature names pass the allowed/banned guard", "OK" if not probs else "; ".join(probs), bool(probs)))
    desc = duckdb.connect().execute(
        f"SELECT cve_id, description FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)").df().set_index("cve_id")["description"]
    pool = pd.concat([data[2024]["meta"], data[2025]["meta"]], ignore_index=True)
    raw = desc.reindex(pool["cve_id"]).fillna("").to_numpy()
    stripped = np.array([strip_post_attack(t) for t in raw])
    lab = pool["label"].to_numpy()
    n_pos, n_neg = int(lab.sum()), int((1 - lab).sum())
    scans = [("post-attack phrases in RAW text (what stripping removed)", POST_ATTACK, raw, False),
             ("post-attack phrases left after stripping (must be 0)", POST_ATTACK, stripped, True),
             ("ransomware", re.compile(r"ransomware", re.I), stripped, True),
             ("botnet", re.compile(r"botnet", re.I), stripped, True),
             ("threat actor", re.compile(r"threat actors?", re.I), stripped, True),
             ("in the wild", re.compile(r"in the wild", re.I), stripped, True),
             ("CISA / KEV / known exploited", re.compile(r"\bcisa\b|\bkev\b|known exploited", re.I), stripped, True),
             ("exploitation wording (mass/active/ongoing exploitation, widely exploited)",
              re.compile(r"(mass|widespread|active|ongoing) exploitation|widely exploited|exploited by", re.I), stripped, True)]
    rows = []
    for name, rx, text, rule in scans:
        hit = np.fromiter((bool(rx.search(t)) for t in text), dtype=bool, count=len(text))
        pn, nn = int(hit[lab == 1].sum()), int(hit[lab == 0].sum())
        pr, nr = pn / n_pos, nn / n_neg
        flagged = bool(rule and pn >= 3 and pr >= 5 * max(nr, 1e-4))
        rows.append((name, f"{pn} / {n_pos} ({pr:.1%})", f"{nn} / {n_neg} ({nr:.2%})", "**FLAG**" if flagged else "ok"))
        if rule:
            items.append((f"description scan: {name}", f"positives {pr:.1%} vs negatives {nr:.2%}", flagged))
    tables["scan"] = rows
    auc_rows = []
    for c in TEXT_FEATURES:
        a = []
        for y in (2024, 2025):
            d = data[y]
            a.append(roc_auc_score(d["y"], d["X2"][c]) if d["X2"][c].nunique() > 1 else 0.5)
        flagged = any(x > AUC_FLAG or x < 1 - AUC_FLAG for x in a)
        auc_rows.append((c, f"{a[0]:.3f}", f"{a[1]:.3f}", "**FLAG**" if flagged else "ok"))
        if flagged:
            items.append((f"univariate AUC of {c}", f"{a[0]:.3f} / {a[1]:.3f} (threshold {AUC_FLAG})", True))
    tables["auc"] = auc_rows
    items.append((f"univariate AUC of every text feature within [{1 - AUC_FLAG:.2f}, {AUC_FLAG:.2f}] on both replicas",
                  "yes" if not any(r[3] != "ok" for r in auc_rows) else "no", any(r[3] != "ok" for r in auc_rows)))
    return items, tables


def shift_table(data, sb2):
    rep = pd.concat([data[2024]["X2"], data[2025]["X2"]], ignore_index=True)
    rows = []
    for f in FEATURES_V2:
        a, b = rep[f].astype(float), sb2[f].astype(float)
        s = smd(a, b)
        rows.append((f, f"{a.mean():.4g}", f"{b.mean():.4g}", f"{a.median():.4g}", f"{b.median():.4g}",
                     f"{a.isna().mean():.1%}", f"{b.isna().mean():.1%}", f"{s:+.2f}", "**SHIFT**" if abs(s) > SMD_FLAG else ""))
    return rows


# ---- main -------------------------------------------------------------------------------------
def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, sb, sb2, ctx = prepare(out_dir, data_dir)
    preds = pd.read_parquet(out_dir / ".cache" / "test_preds.parquet")
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")

    # reference runs + consistency with the cached evaluation
    ref_v2 = [fit_scores(ctx[d], FEATURES_V2, ctx[d]["p2"], "v2") for d in DIRS]
    ref_v1 = [fit_scores(ctx[d], v1.FEATURES, ctx[d]["p1"], "v1", Xtr=ctx[d]["tr"]["X"], Xte=ctx[d]["te"]["X"]) for d in DIRS]
    for d, s2, s1 in zip(DIRS, ref_v2, ref_v1):
        cached = preds[preds["test_year"] == d[1]].set_index("cve_id").reindex(ctx[d]["meta"]["cve_id"])
        assert np.allclose(cached["lgbm_v2"], s2) and np.allclose(cached["lgbm_v1"], s1), "refit does not match cached evaluation"
    base_per = [topk_hits(ctx[d]["label"], ctx[d]["meta"]["exploit_epss"], np.zeros(len(ctx[d]["meta"])), ctx[d]["code"], ctx[d]["k"]) for d in DIRS]
    base_pool = sum(base_per)
    v2_per = [hits_of(ctx[d], s) for d, s in zip(DIRS, ref_v2)]
    v1_per = [hits_of(ctx[d], s) for d, s in zip(DIRS, ref_v1)]
    print(f"reference pooled hits: baseline {base_pool}, v1 LightGBM {sum(v1_per)}, v2 LightGBM {sum(v2_per)}")

    # 1. mechanism
    mech, mech_tab = mechanism(ctx, preds, kev)
    mech.to_csv(out_dir / "v2_mechanism.csv", index=False)

    # 2. seed stability
    seed_rows = []
    for s in SEEDS:
        h2 = [hits_of(ctx[d], fit_scores(ctx[d], FEATURES_V2, ctx[d]["p2"], "v2", seed=s)) for d in DIRS]
        h1 = [hits_of(ctx[d], fit_scores(ctx[d], v1.FEATURES, ctx[d]["p1"], "v1", seed=s, Xtr=ctx[d]["tr"]["X"], Xte=ctx[d]["te"]["X"])) for d in DIRS]
        seed_rows.append((s, *h1, sum(h1), *h2, sum(h2)))
    sd = pd.DataFrame(seed_rows, columns=["seed", "v1_2025", "v1_2024", "v1_pooled", "v2_2025", "v2_2024", "v2_pooled"])
    print(f"seed stability: v1 mean {sd.v1_pooled.mean():.1f}  v2 mean {sd.v2_pooled.mean():.1f}")

    # 3. text ablation inside v2 (fixed params)
    abl = []
    for name, drop in DROPS.items():
        feats = [f for f in FEATURES_V2 if f not in drop]
        h0 = [hits_of(ctx[d], fit_scores(ctx[d], feats, ctx[d]["p2"], "v2")) for d in DIRS]
        hs = [sum(hits_of(ctx[d], fit_scores(ctx[d], feats, ctx[d]["p2"], "v2", seed=s)) for d in DIRS) for s in SEEDS]
        abl.append((name, len(feats), h0[0], h0[1], sum(h0), f"{np.mean(hs):.1f}", f"{min(hs)}-{max(hs)}"))
    print("ablation done")

    # 4. placebo
    pl = []
    for rep in range(N_PLACEBO):
        rng = np.random.default_rng(rep)
        h = []
        for d in DIRS:
            c = ctx[d]
            Xtr = shuffle_text_within_month(c["tr"]["X2"], c["tr_months"], TEXT_FEATURES, rng)
            Xte = shuffle_text_within_month(c["te"]["X2"], c["months"], TEXT_FEATURES, rng)
            h.append(hits_of(c, fit_scores(c, FEATURES_V2, c["p2"], "v2", Xtr=Xtr, Xte=Xte)))
        pl.append((rep, h[0], h[1], sum(h)))
    plc = pd.DataFrame(pl, columns=["seed", "hits_test2025", "hits_test2024", "pooled_hits"])
    plc.to_csv(out_dir / "v2_placebo.csv", index=False)
    real = sum(v2_per)
    p_val = float((plc["pooled_hits"] >= real).mean())
    p_adj = float(((plc["pooled_hits"] >= real).sum() + 1) / (len(plc) + 1))
    p_mean = float((plc["pooled_hits"] >= sd["v2_pooled"].mean()).mean())
    print(f"placebo: mean {plc.pooled_hits.mean():.1f}, 95th pct {plc.pooled_hits.quantile(0.95):.1f}, p = {p_val:.2f}")

    # 5. ensemble (evaluation only)
    ens_h = []
    for d in DIRS:
        c = ctx[d]
        p = preds[preds["test_year"] == d[1]].set_index("cve_id").reindex(c["meta"]["cve_id"])
        e = (p["logreg_v2"].rank(pct=True) + p["lgbm_v2"].rank(pct=True)).to_numpy() / 2
        ens_h.append(hits_of(c, e))

    # 6. shift
    shift = shift_table(data, sb2)

    # leakage audit
    leak_items, leak_tabs = leakage_audit(data, data_dir)
    leakage_found = any(f for _, _, f in leak_items)

    # final model: v2 LightGBM on BOTH replicas, pooled-AP selection (month folds across both replicas)
    X_all = pd.concat([data[2024]["X2"], data[2025]["X2"]], ignore_index=True)
    y_all = np.concatenate([data[2024]["y"], data[2025]["y"]])
    g_month = np.array([g[-2:] for g in np.concatenate([data[2024]["groups"], data[2025]["groups"]])])
    params, _, ap_final = v1.select_lgbm(X_all, y_all, g_month, FEATURES_V2, "v2 final (both replicas, month folds)")
    final = v1.lgbm_model(params, FEATURES_V2).fit(X_all[FEATURES_V2], y_all)
    sbm = sb2.assign(cve_id=sb["cve_id"].to_numpy())
    sbm["s"] = final.predict_proba(sbm[FEATURES_V2])[:, 1]
    ranked = rank_order(sbm, ["s", "epss_rank_in_month"]).head(500)
    top_ref = set(ranked["cve_id"])
    seed_overlap = []
    for sd_ in SEEDS:  # how much the final list moves with the LightGBM random seed (information only)
        m_ = v1.lgbm_model(params, FEATURES_V2, seed=sd_).fit(X_all[FEATURES_V2], y_all)
        t_ = rank_order(sbm.assign(s=m_.predict_proba(sbm[FEATURES_V2])[:, 1]), ["s", "epss_rank_in_month"]).head(500)
        seed_overlap.append(len(top_ref & set(t_["cve_id"])))

    # policy
    vetoes = []
    if p_val > PLACEBO_P_MAX:
        vetoes.append(f"placebo p = {p_val:.2f} > {PLACEBO_P_MAX}")
    if sd["v2_pooled"].mean() < base_pool:
        vetoes.append(f"10-seed mean pooled hits {sd['v2_pooled'].mean():.1f} < best baseline {base_pool}")
    if leakage_found:
        vetoes.append("leakage check flagged: " + "; ".join(n for n, _, f in leak_items if f))
    v2_list = pd.read_csv(out_dir / "top500_v2.csv")["cve_id"].tolist()
    base_list = pd.read_csv(out_dir / "top500_v0.csv")["cve_id"].tolist()
    if vetoes:
        final_ids, chosen = v2_list, "two-channel hybrid (outputs/top500_v2.csv), v2 LightGBM VETOED"
    else:
        final_ids, chosen = ranked["cve_id"].tolist(), "v2 LightGBM trained on both replicas"
    pd.DataFrame({"cve_id": final_ids}).to_csv(out_dir / "top500_v3.csv", index=False)
    idx = pd.Series(np.arange(len(sbm)), index=sbm["cve_id"]).loc[final_ids].to_numpy()
    contrib = final.booster_.predict(sbm.iloc[idx][FEATURES_V2], pred_contrib=True)[:, :-1]
    pd.DataFrame(contrib, columns=FEATURES_V2).assign(cve_id=final_ids)[["cve_id", *FEATURES_V2]].to_parquet(
        out_dir / "v3_top500_contrib.parquet", index=False)
    overlap_base, overlap_v2 = len(set(final_ids) & set(base_list)), len(set(final_ids) & set(v2_list))
    lgbm_vs_base = len(set(ranked["cve_id"]) & set(base_list))
    fl = sbm.set_index("cve_id")
    flagged_final = int((fl.loc[final_ids, ["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1) == 1).sum())
    flagged_base = int((fl.loc[base_list, ["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1) == 1).sum())

    # ---- report
    two = json.loads((out_dir / ".cache" / "v2_two_channel.json").read_text())
    row = {r[0]: r for r in two["rows"]}["LightGBM, v2 (+text)"]
    ci = re.search(r"\[(-?\d+), \+?(-?\d+)\]", row[5])
    ci_lo = int(ci.group(1)) if ci else None
    pts = (p_val <= 0.05) + (int(sd["v2_pooled"].min()) >= base_pool) + (ci_lo is not None and ci_lo > 0)
    strength = ["WEAK", "WEAK", "MODERATE", "STRONG"][int(pts)]
    L = ["# v3 report: stress tests of v2 LightGBM and the final candidate list", "",
         "> **LOW POWER.** 27 (2024) and 48 (2025) positives, 75 in total. Directions: train 2024 -> test 2025 (forward in time) "
         "and train 2025 -> test 2024 (stability check, not forward in time). Hits are in the top k "
         "(k = 198 for 2024, 243 for 2025), ties broken by score, epss_rank_in_month, cve_id. No hyper-parameter was tuned on test data.", "",
         "## Pre-declared policy (fixed before the checks ran)", "",
         "Primary candidate: v2 LightGBM trained on BOTH replicas with the pooled-AP-selected parameters. It is vetoed only if "
         f"(i) the placebo p-value is greater than {PLACEBO_P_MAX}, (ii) the 10-seed mean of pooled hits is below the best baseline's "
         f"pooled hits ({base_pool}), or (iii) any leakage is found. If vetoed, fall back to the two-channel hybrid (`top500_v2.csv`). "
         "Candidates are not chosen by comparing their test hits.", "",
         "| condition | value | triggers veto? |", "|---|---|---|",
         f"| (i) placebo p-value (fraction of {N_PLACEBO} null runs with pooled hits >= {real}) | {p_val:.2f} | {'YES' if p_val > PLACEBO_P_MAX else 'no'} |",
         f"| (ii) 10-seed mean pooled hits vs best baseline ({base_pool}) | {sd['v2_pooled'].mean():.1f} | {'YES' if sd['v2_pooled'].mean() < base_pool else 'no'} |",
         f"| (iii) leakage found | {'yes' if leakage_found else 'no'} | {'YES' if leakage_found else 'no'} |", "",
         f"**Policy outcome: {chosen}.** " + ("Vetoes: " + "; ".join(vetoes) + "." if vetoes else "No veto condition was triggered."), ""]

    L += ["## Pooled hits per candidate (reference run, random_state 0)", "",
          md_table(["ranking", "test 2025", "test 2024", "pooled"],
                   [("Exploit code, then EPSS (baseline)", *base_per, base_pool), ("v1 LightGBM", *v1_per, sum(v1_per)),
                    ("v2 LightGBM", *v2_per, sum(v2_per)), ("v2 rank-average of logreg + LightGBM (evaluation only)", *ens_h, sum(ens_h))]), "",
          f"The two-channel hybrid is `top500_v2.csv` (pooled 20, optimistic: s chosen on the data it is scored on). v2 LightGBM vs the baseline from the v2 report: "
          f"{row[5]} (90% paired bootstrap).", ""]

    L += ["## 1. Mechanism: where do the hits come from?", "",
          "Positives are labelled **flagged** (any public exploit flag), **blind-spot** (no flag and within-month EPSS rank below the cut a top-k EPSS list makes) "
          "or **unflagged, EPSS-visible** (no flag but above that EPSS cut: a third group the two-way split leaves out). Models are trained on the other replica.", "",
          md_table(["test replica", "group of positives", "positives", "baseline hits", "v1 LightGBM hits", "v2 LightGBM hits"], mech_tab), ""]
    g = mech[mech["comparison"] == "v2_lgbm_vs_baseline"]
    ev = g.groupby(["test_replica", "kind"]).apply(lambda d: (len(d), d[["kev_vendor", "kev_date_added"]].drop_duplicates().shape[0]), include_groups=False)
    n_third = sum(r[2] for r in mech_tab if r[1] == "unflagged, EPSS-visible")
    if n_third == 0:
        L += ["No positive in either replica is unflagged but EPSS-visible, so the flagged / blind-spot split is exhaustive here.", ""]
    L += ["Hits gained (in v2's top k, not the baseline's) and lost (the reverse); full list in `outputs/v2_mechanism.csv`:", "",
          md_table(["test replica", "kind", "cve_id", "group", "KEV vendor", "days to KEV"],
                   [(r.test_replica, r.kind, r.cve_id, r.group, r.kev_vendor, "" if pd.isna(r.days_to_kev) else int(r.days_to_kev)) for r in g.itertuples()]), "",
          "Vendor and days-to-KEV are post-snapshot facts shown for description only; they are never features. "
          "Distinct KEV events (same vendor and date added) behind these hits, as (CVEs, events): " +
          "; ".join(f"test {a} {b}: {c}" for (a, b), c in ev.items()) +
          ". CVEs added to KEV together are one correlated event, so the effective gain is smaller than the CVE count.", ""]

    L += ["## 2. Seed stability (fixed parameters, seeds 1-10)", "",
          md_table(["model", "mean pooled", "min", "max", "reference (seed 0)"],
                   [("v1 LightGBM", f"{sd.v1_pooled.mean():.1f}", sd.v1_pooled.min(), sd.v1_pooled.max(), sum(v1_per)),
                    ("v2 LightGBM", f"{sd.v2_pooled.mean():.1f}", sd.v2_pooled.min(), sd.v2_pooled.max(), sum(v2_per))]), "",
          md_table(["seed", "v1 test 2025", "v1 test 2024", "v1 pooled", "v2 test 2025", "v2 test 2024", "v2 pooled"], seed_rows), ""]

    L += ["## 3. Text ablation inside v2 (fixed parameters, no re-tuning)", "",
          "Hits per direction use seed 0; the last two columns summarise seeds 1-10.", "",
          md_table(["variant", "features", "test 2025", "test 2024", "pooled (seed 0)", "mean pooled (seeds 1-10)", "range"], abl), ""]

    L += [f"## 4. Placebo: the 16 text columns shuffled jointly within snapshot month ({N_PLACEBO} repeats)", "",
          "Each repeat shuffles the text columns (one permutation for all 16, so their rows stay together) across rows within each snapshot month, "
          "separately in the training frame and the test frame, then refits v2 LightGBM (fixed parameters, seed 0) in both directions.", "",
          md_table(["quantity", "value"],
                   [("null mean of pooled hits", f"{plc.pooled_hits.mean():.2f}"), ("null 95th percentile", f"{plc.pooled_hits.quantile(0.95):.1f}"),
                    ("null min / max", f"{plc.pooled_hits.min()} / {plc.pooled_hits.max()}"), ("real v2 LightGBM pooled hits", real),
                    ("p = fraction of null runs >= real", f"{p_val:.2f}"), ("p with +1 correction, (count+1)/(n+1)", f"{p_adj:.3f}"),
                    ("for context: fraction of null runs >= 10-seed mean of real", f"{p_mean:.2f}")]), "",
          f"Caveat: the shuffled-text null (mean {plc.pooled_hits.mean():.1f}) sits below the model with no text at all "
          f"(10-seed mean {float(abl[4][5]):.1f}) because shuffled columns act as noise features. So p measures 'real text beats noise text', "
          f"a more lenient test than 'text beats no text' (full v2 {sd['v2_pooled'].mean():.1f} vs no text {float(abl[4][5]):.1f} on 10-seed means).", "",
          "Null distribution of pooled hits (counts): " + ", ".join(f"{int(k)}: {int(v)}" for k, v in plc["pooled_hits"].value_counts().sort_index().items()) + ". Saved in `outputs/v2_placebo.csv`.", ""]

    L += ["## 5. Ensemble (evaluation only, not used for selection)", "",
          f"Rank average of v2 logistic regression and v2 LightGBM: test 2025 = {ens_h[0]}, test 2024 = {ens_h[1]}, pooled = {sum(ens_h)}.", ""]

    L += ["## 6. Shift: replicas (pooled) vs the 2026 scoreboard", "",
          f"Standardised mean difference (scoreboard minus replicas) above {SMD_FLAG} in absolute value is flagged.", "",
          md_table(["feature", "mean (replicas)", "mean (2026)", "median (replicas)", "median (2026)", "missing (replicas)", "missing (2026)", "SMD", ""], shift), ""]

    L += ["## Leakage audit", "",
          "Pre-declared rules: the feature guard must pass; for each description pattern left after post-attack stripping, a flag is raised if at least 3 positives match and "
          "the positive rate is at least 5 times the negative rate; a text feature is flagged if its univariate AUC on a replica exceeds 0.95 (or is below 0.05). "
          "Limit: the Granite embeddings are not available locally, so `kev_text_score` and `nearest_kev_sim` were not recomputed; their time-safety rests on "
          "Person B's code, which I read: the classifier for pool year Y trains only on CVEs published before Y-01-01 labelled with KEV `date_added` <= (Y-1)-12-31, and "
          "`nearest_kev_sim` uses only KEV rows with `date_added` <= (Y-1)-12-31. Descriptions are the current NVD text and could have been edited after publication.", "",
          md_table(["check", "result", "flagged"], [(n, r, "**YES**" if f else "no") for n, r, f in leak_items]), "",
          "Description scan (pooled replicas):", "", md_table(["pattern", "positives", "negatives", ""], leak_tabs["scan"]), "",
          "Univariate AUC of each text feature:", "", md_table(["feature", "AUC replica 2024", "AUC replica 2025", ""], leak_tabs["auc"]), ""]

    L += ["## Final list", "", f"**Selected by the policy: {chosen}.**", "",
          md_table(["item", "value"],
                   [("file", "`outputs/top500_v3.csv` (500 unique ids)"), ("final-model parameters (pooled-AP selection, month folds)", f"`{json.dumps(params)}`"),
                    ("pooled OOF AP of the selection", f"{ap_final:.4f}"),
                    ("overlap with baseline top 500 (`top500_v0.csv`)", overlap_base), ("overlap with `top500_v2.csv`", overlap_v2),
                    ("v2 LightGBM (both replicas) top 500 overlap with baseline", lgbm_vs_base),
                    ("CVEs with an exploit flag in the final list vs the baseline list", f"{flagged_final} vs {flagged_base}"),
                    ("list stability: overlap of the seed-0 top 500 with the top 500 from seeds 1-10 (information only)",
                     f"mean {np.mean(seed_overlap):.0f}, min {min(seed_overlap)}, max {max(seed_overlap)} of 500"),
                    ("contributions", "`outputs/v3_top500_contrib.parquet` (LightGBM pred_contrib, one column per feature)")]), "",
          "## How strong is the evidence?", "",
          f"**{strength}.** With 75 positives, results are noisy. v2 LightGBM has {sum(v2_per)} pooled hits against the baseline's {base_pool} "
          f"(seed 0; paired-bootstrap difference {row[5]}), a 10-seed mean of {sd['v2_pooled'].mean():.1f} (range {sd['v2_pooled'].min()}-{sd['v2_pooled'].max()}), "
          f"and a placebo null mean of {plc.pooled_hits.mean():.1f} with p = {p_val:.2f}. "
          f"The bootstrap interval {'excludes' if ci_lo is not None and ci_lo > 0 else 'includes'} zero, so a gain over the baseline "
          f"{'is' if ci_lo is not None and ci_lo > 0 else 'is not'} established at 90%. "
          f"Seed 0, the reference run, is at the top of the seed range, so the single-seed margin overstates the typical gain: the 10-seed mean is "
          f"{sd['v2_pooled'].mean() - base_pool:+.1f} hits against the baseline. In the ablation (10-seed means) the full model scores {sd['v2_pooled'].mean():.1f}, "
          f"dropping kev_text_score gives {float(abl[1][5]):.1f}, dropping nearest_kev_sim {float(abl[2][5]):.1f}, dropping the txt_ flags {float(abl[3][5]):.1f} and dropping all text "
          f"{float(abl[4][5]):.1f}: the ablation points to the plain regex flags, not the Granite embedding scores, as the source of any lift (differences of 1-2 hits are within seed noise). "
          "Several of the extra hits are CVEs added to KEV together (see section 1). The placebo shows how often noise text would do as well; its caveat is in section 4. "
          f"Leakage checks: {'a flag was raised' if leakage_found else 'none raised'}, within the limits stated above. "
          + ("Treat the list as a modest, uncertain improvement at best." if strength != "STRONG" else "")]
    (out_dir / "v3_report.md").write_text("\n".join(L) + "\n")
    print("\n".join(L[:30]))
    print(f"policy: {chosen}")
    return dict(chosen=chosen, vetoes=vetoes)


if __name__ == "__main__":
    main()
