"""v1 models (logistic regression + LightGBM) on allowed features only.  Run: python -m src.models.train_v1

LOW POWER: the replicas have 27 and 48 positives, so every number here is noisy.
Rules (decided before looking at test results):
  * hyper-parameters are chosen by leave-one-snapshot-month-out CV on the TRAINING replica only
    (pooled out-of-fold average precision); nothing is tuned on the test replica
  * model choice: if pooled OOF AP of logreg and LightGBM are within 10% of each other pick the
    simpler logreg, otherwise the higher AP; both models are always reported
  * model tie-break: score, then epss_rank_in_month, then cve_id; baselines keep their own rule
"""
import hashlib
import itertools
import json
from datetime import datetime, timezone

import duckdb
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.baselines import add_scores, load_cvss
from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import FEATURE_GROUPS, MONOTONE_UP, V1_FEATURES, check_feature_list
from src.common.scoring import expected_hits_at_k, k_for_pool, paired_bootstrap_hits, rank_order

FEATURES = list(V1_FEATURES)
GRID = dict(num_leaves=[4, 7], min_child_samples=[30, 100], n_estimators=[150, 400],
            reg_lambda=[1, 10], scale_pos_weight=[1, 10])
FIXED = dict(learning_rate=0.03, subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
             random_state=0, n_jobs=4, deterministic=True, force_row_wise=True, verbose=-1)
LR_C = 1.0  # fixed, not tuned
SAME_AP = 0.10  # within 10% -> choose the simpler model
N_BOOT = 1000
BASELINES = {"CVSS 3 first": ["cvss3_score"], "EPSS first": ["epss"], "Exploit code, then EPSS": ["exploit_epss"]}
MODEL_COLS = ["epss_rank_in_month"]  # second sort key for models (after the score)
DIRECTIONS = [("train2024_test2025", 2024, 2025, "primary (forward in time)"),
              ("train2025_test2024", 2025, 2024, "stability check (NOT forward in time)")]
MODELS = {"logreg": "Logistic regression", "lgbm": "LightGBM"}


# ---- models -----------------------------------------------------------------------------------
def lgbm_model(params, feats):
    mono = [1 if f in MONOTONE_UP else 0 for f in feats]
    return lgb.LGBMClassifier(monotone_constraints=mono, **FIXED, **params)


def lr_model():
    return Pipeline([("scale", StandardScaler()), ("lr", LogisticRegression(C=LR_C, max_iter=2000))])


def fit_predict(kind, params, Xtr, ytr, Xte, feats):
    if kind == "lgbm":
        return lgbm_model(params, feats).fit(Xtr[feats], ytr).predict_proba(Xte[feats])[:, 1]
    # NaN epss imputed as rank 0 (epss_missing carries the information)
    return lr_model().fit(Xtr[feats].fillna(0), ytr).predict_proba(Xte[feats].fillna(0))[:, 1]


def lomo_oof(kind, params, X, y, groups, feats):
    """Leave-one-group-out out-of-fold predictions (groups = snapshot months)."""
    oof = np.zeros(len(X))
    for g in sorted(set(groups)):
        te = np.asarray(groups) == g
        oof[te] = fit_predict(kind, params, X[~te], y[~te], X[te], feats)
    return oof


def _cache_path(X, y, groups, feats, tag):
    h = hashlib.md5()
    for part in (tag, repr(feats), repr(GRID), repr(sorted(FIXED.items())), repr(N_BOOT)):
        h.update(part.encode())
    for a in (X[feats].to_numpy(dtype="float64"), np.asarray(y), np.asarray(groups).astype(str)):
        h.update(np.ascontiguousarray(a).tobytes())
    return OUT_DIR / ".cache" / f"sel_{h.hexdigest()[:16]}.json"


def select_lgbm(X, y, groups, feats, tag=""):
    """Grid search by pooled leave-one-month-out AP. Results are cached (deterministic) in outputs/.cache."""
    cp = _cache_path(X, y, groups, feats, tag)
    if cp.exists():
        c = json.loads(cp.read_text())
        print(f"  [{tag}] LightGBM selection loaded from cache: AP={c['ap']:.4f} params={c['params']}")
        return c["params"], np.array(c["oof"]), c["ap"]
    best = None
    combos = [dict(zip(GRID, v)) for v in itertools.product(*GRID.values())]
    for i, p in enumerate(combos):
        oof = lomo_oof("lgbm", p, X, y, groups, feats)
        ap = average_precision_score(y, oof)
        if best is None or ap > best[0]:
            best = (ap, p, oof)
    print(f"  [{tag}] LightGBM grid ({len(combos)} combos) best AP={best[0]:.4f} params={best[1]}")
    cp.parent.mkdir(exist_ok=True)
    cp.write_text(json.dumps({"ap": best[0], "params": best[1], "oof": best[2].tolist()}))
    return best[1], best[2], best[0]


def decide_model(ap_lr, ap_lgbm):
    rel = abs(ap_lr - ap_lgbm) / max(ap_lr, ap_lgbm)
    if rel <= SAME_AP:
        return "logreg", rel, "within 10% -> simpler model (logreg)"
    return ("logreg" if ap_lr > ap_lgbm else "lgbm"), rel, "AP differs by more than 10% -> higher AP"


# ---- evaluation -------------------------------------------------------------------------------
def rank_pos(df, cols):
    r = rank_order(df, cols)
    pos = np.empty(len(df), dtype=np.int64)
    pos[r.index.to_numpy()] = np.arange(len(df))
    return pos


def eval_frame(df, scores):
    """df: RangeIndex frame with cve_id, label, snapshot_month, epss, exploit_epss, cvss3_score,
    epss_rank_in_month. scores: {model_name: array}. Returns (results, bootstrap array, names)."""
    k = k_for_pool(len(df))
    d = df.copy()
    rankings = dict(BASELINES)
    for m, s in scores.items():
        d[f"s_{m}"] = s
        rankings[m] = [f"s_{m}"] + MODEL_COLS
    res, pos = {}, []
    for name, cols in rankings.items():
        e = expected_hits_at_k(d, cols, k)
        r = rank_order(d, cols).head(k)
        e["by_month"] = r.groupby("snapshot_month")["label"].sum().to_dict()
        e["ap"] = float(average_precision_score(d["label"], d[cols[0]].fillna(-1)))
        res[name] = e
        pos.append(rank_pos(d, cols))
    B = paired_bootstrap_hits(d["label"].to_numpy(), pos, k, n=N_BOOT, seed=0)
    names = list(rankings)
    for j, name in enumerate(names):
        res[name]["ci"] = (float(np.percentile(B[:, j], 5)), float(np.percentile(B[:, j], 95)))
    return res, B, names, k


def best_baseline(per_dir):
    """Single best baseline by summed tie-aware expected hits over the evaluated test replicas."""
    tot = {b: sum(r[b]["expected"] for r in per_dir) for b in BASELINES}
    return max(tot, key=tot.get), tot


# ---- data -------------------------------------------------------------------------------------
def load(out_dir=OUT_DIR, data_dir=DATA_DIR):
    cvss = load_cvss(data_dir)
    data = {}
    for y in (2024, 2025):
        f = pd.read_parquet(out_dir / f"features_replica_{y}.parquet").reset_index(drop=True)
        meta = add_scores(f.merge(cvss, on="cve_id", how="left")[["cve_id", "snapshot_month", "label", "epss",
                          "exploitdb", "metasploit", "nuclei", "poc_github", "epss_rank_in_month", "cvss3_score"]])
        data[y] = dict(X=f[FEATURES], y=f["label"].to_numpy(), groups=f["snapshot_month"].to_numpy(), meta=meta)
    sb = pd.read_parquet(out_dir / "features_scoreboard.parquet").reset_index(drop=True)
    return data, sb


# ---- md helpers -------------------------------------------------------------------------------
def md(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def ci_str(ci):
    return f"[{ci[0]:.0f}-{ci[1]:.0f}]"


def tie_str(e):
    return f"{e['tie_size']} ({e['slots_in_tie']} slots)" if e["tie_size"] > 1 else "1"


# ---- main -------------------------------------------------------------------------------------
def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    assert not check_feature_list(FEATURES), check_feature_list(FEATURES)
    data, sb = load(out_dir, data_dir)
    L = ["# v1 report: allowed features, logistic regression and LightGBM", "",
         "> **LOW POWER.** The replicas have 27 (2024) and 48 (2025) positives, 75 in total. Every number "
         "below is noisy; intervals are wide and small differences mean little.", ""]
    L += ["## History-cutoff rule", "",
          "KEV-based history features use a fixed cutoff of December 31 of the year before the pool year: replica 2024 "
          "uses KEV rows added on or before 2023-12-31, replica 2025 on or before 2024-12-31, and the 2026 scoreboard on "
          "or before 2025-12-31. No 2026 KEV information is used anywhere.", ""]
    L += ["## Features (allowed columns only)", ""]
    L += [md(["group", "columns"], [(g, ", ".join(c)) for g, c in FEATURE_GROUPS.items()]), "",
          "Monotone +1 constraints (LightGBM): " + ", ".join(MONOTONE_UP) + ". "
          "No CVSS, nvd_status, n_affected_cpes, n_references, references, affected_products or cwe_ids are model inputs. "
          "CVSS is joined only to score the CVSS baseline.", ""]

    # --- hyper-parameters & model choice per training replica
    sel, oofs = {}, {}
    for y in (2024, 2025):
        d = data[y]
        params, oof_lgbm, ap_lgbm = select_lgbm(d["X"], d["y"], d["groups"], FEATURES, f"train {y}")
        oof_lr = lomo_oof("logreg", None, d["X"], d["y"], d["groups"], FEATURES)
        ap_lr = average_precision_score(d["y"], oof_lr)
        choice, rel, why = decide_model(ap_lr, ap_lgbm)
        sel[y] = dict(params=params, ap_lgbm=ap_lgbm, ap_lr=ap_lr, choice=choice, rel=rel, why=why)
        oofs[y] = dict(logreg=oof_lr, lgbm=oof_lgbm)

    L += ["## Hyper-parameter selection and model choice", "",
          "Rule (fixed before looking at any test result): choose between logistic regression and LightGBM by pooled "
          "out-of-fold average precision (AP) on the TRAINING replica only (leave-one-snapshot-month-out, 9 folds). "
          "If the two AP values are within 10% of each other, choose the simpler model (logistic regression). "
          "LightGBM grid: num_leaves {4,7}, min_child_samples {30,100}, n_estimators {150,400}, reg_lambda {1,10}, "
          "scale_pos_weight {1,10}; learning_rate 0.03, subsample 0.8, colsample_bytree 0.8. Logistic regression: "
          f"C={LR_C} (fixed).", ""]
    L += [md(["training replica", "OOF AP logreg", "OOF AP LightGBM", "relative gap", "decision", "chosen LightGBM params"],
             [(y, f"{s['ap_lr']:.4f}", f"{s['ap_lgbm']:.4f}", f"{s['rel']:.0%}", f"**{s['choice']}** ({s['why']})",
               json.dumps(s["params"])) for y, s in sel.items()]), ""]

    # --- directional evaluation
    dir_res, dir_B, dir_names, dir_k = {}, {}, {}, {}
    for name, tr, te, label in DIRECTIONS:
        scores = {m: fit_predict(m, sel[tr]["params"], data[tr]["X"], data[tr]["y"], data[te]["X"], FEATURES)
                  for m in MODELS}
        res, B, names, k = eval_frame(data[te]["meta"], scores)
        dir_res[name], dir_B[name], dir_names[name], dir_k[name] = res, B, names, k

    bb, tot = best_baseline([dir_res[n] for n, *_ in DIRECTIONS])
    bidx = {n: i for i, n in enumerate(dir_names[DIRECTIONS[0][0]])}

    L += ["## Headline: pooled cross-replica hits (LOW POWER, 75 positives)", "",
          "Sum of hits over the two test replicas (train 2024 -> test 2025, plus train 2025 -> test 2024), each in the top k "
          "for that replica. The comparison baseline is the single best baseline by summed tie-aware expected hits "
          f"(**{bb}**). The difference interval is a paired bootstrap (1000 resamples within each replica, seed 0, same "
          "resample for model and baseline, 90% interval of the summed difference).", ""]
    rows = []
    for b in BASELINES:
        rows.append((b, sum(dir_res[n][b]["arbitrary"] for n, *_ in DIRECTIONS), f"{sum(dir_res[n][b]['expected'] for n, *_ in DIRECTIONS):.1f}", "", ""))
    for m, mname in MODELS.items():
        pooled = sum(dir_res[n][m]["arbitrary"] for n, *_ in DIRECTIONS)
        pooled_e = sum(dir_res[n][m]["expected"] for n, *_ in DIRECTIONS)
        diff = sum(dir_B[n][:, bidx[m]] - dir_B[n][:, bidx[bb]] for n, *_ in DIRECTIONS)
        lo, hi = np.percentile(diff, [5, 95])
        base_a = sum(dir_res[n][bb]["arbitrary"] for n, *_ in DIRECTIONS)
        rows.append((f"**{mname}**", pooled, f"{pooled_e:.1f}", f"{pooled - base_a:+d}", f"[{lo:+.0f}, {hi:+.0f}]"))
    L += [md(["ranking", "pooled hits (arbitrary order)", "pooled expected hits (ties)", f"diff vs {bb}", "90% paired-bootstrap interval of diff"], rows), ""]

    for name, tr, te, label in DIRECTIONS:
        res, B, names, k = dir_res[name], dir_B[name], dir_names[name], dir_k[name]
        pos = int(data[te]["y"].sum())
        L += [f"## {name}: {label} (LOW POWER)", "",
              f"Test replica {te}: pool {len(data[te]['y']):,}, {pos} positives, k = {k}. "
              f"Hits in the top k with 90% bootstrap interval; expected hits average over ties at the cutoff; "
              f"'tie group' is the size of the tie group straddling the cutoff.", ""]
        rows = []
        for n in names:
            e = res[n]
            diff = B[:, names.index(n)] - B[:, names.index(bb)]
            dstr = "" if n == bb else f"{e['arbitrary'] - res[bb]['arbitrary']:+d} [{np.percentile(diff, 5):+.0f}, {np.percentile(diff, 95):+.0f}]"
            rows.append((MODELS.get(n, n) if n in MODELS else n, e["arbitrary"], f"{e['expected']:.2f}", ci_str(e["ci"]),
                         tie_str(e), f"{e['ap']:.4f}", dstr))
        L += [md(["ranking", "hits (arbitrary)", "expected hits", "90% boot", "tie group at cutoff", "AP", f"diff vs {bb} [90% paired]"], rows), ""]
        months = sorted(data[te]["meta"]["snapshot_month"].unique())
        pm = data[te]["meta"].groupby("snapshot_month")["label"].sum()
        rows = [("positives in pool", *[int(pm.get(m, 0)) for m in months])]
        for n in [*MODELS, "Exploit code, then EPSS"]:
            rows.append((MODELS.get(n, n), *[res[n]["by_month"].get(m, 0) for m in months]))
        L += [f"Per-month hits in the top k ({te}):", "", md(["", *[m[-2:] for m in months]], rows), ""]

    # --- pooled leave-one-month-out (optimistic)
    lomo_res = {}
    L += ["## Pooled leave-one-month-out within each replica (OPTIMISTIC, LOW POWER)", "",
          "Out-of-fold predictions from the same CV used for selection, so parameters were chosen on these folds and "
          "related CVEs in adjacent months can leak across folds. Treat as an upper bound.", ""]
    for y in (2024, 2025):
        res, B, names, k = eval_frame(data[y]["meta"], oofs[y])
        lomo_res[y] = res
        rows = [(MODELS.get(n, n), res[n]["arbitrary"], f"{res[n]['expected']:.2f}", ci_str(res[n]["ci"]), tie_str(res[n]))
                for n in names]
        L += [f"Replica {y} (k = {k}, {int(data[y]['y'].sum())} positives):", "",
              md(["ranking", "hits (arbitrary)", "expected hits", "90% boot", "tie group at cutoff"], rows), ""]

    # --- ablation
    L += ["## Ablation: drop one feature group (LOW POWER)", "",
          "Refit with the parameters chosen on the full feature set (no re-tuning). Hits in the top k (arbitrary / expected).", ""]
    abl_rows = []
    for group in ["none", *FEATURE_GROUPS]:
        feats = [f for f in FEATURES if group == "none" or f not in FEATURE_GROUPS[group]]
        row = [group if group == "none" else f"-{group}"]
        for name, tr, te, _ in DIRECTIONS:
            for m in MODELS:
                s = fit_predict(m, sel[tr]["params"], data[tr]["X"], data[tr]["y"], data[te]["X"], feats)
                d = data[te]["meta"].assign(s=s)
                e = expected_hits_at_k(d, ["s", *MODEL_COLS], dir_k[name])
                row.append(f"{e['arbitrary']} / {e['expected']:.1f}")
        abl_rows.append(row)
    L += [md(["dropped group", *[f"{n.replace('train', '').replace('_test', '->')} {m}" for n, *_ in DIRECTIONS for m in MODELS]],
             abl_rows), ""]

    # --- blind spots
    L += ["## Blind spots (Discovery table, LOW POWER)", "",
          "Positives with no public exploit flag AND within-month EPSS rank below the cut a top-k EPSS ranking would make "
          "(percentile < 1 - k/pool). The last columns count how many of those the v1 model puts in its own top k.", ""]
    rows = []
    for name, tr, te, _ in DIRECTIONS:
        meta = data[te]["meta"]
        k = dir_k[name]
        thr = 1 - k / len(meta)
        blind = (meta["label"] == 1) & (meta[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1) == 0) & (meta["epss_rank_in_month"] < thr)
        cells = []
        for m in MODELS:
            s = fit_predict(m, sel[tr]["params"], data[tr]["X"], data[tr]["y"], data[te]["X"], FEATURES)
            top = rank_order(meta.assign(s=s), ["s", *MODEL_COLS]).head(k).index
            cells.append(int(blind[blind].index.isin(top).sum()))
        rows.append((te, int(meta["label"].sum()), int(blind.sum()), f"{thr:.4f}", cells[0], cells[1]))
    L += [md(["replica", "positives", "blind-spot positives", "EPSS-rank threshold", "caught by logreg", "caught by LightGBM"], rows), ""]

    # --- CVSS >= 9.8
    L += ["## CVSS >= 9.8 does not find attacks (Discovery table)", "",
          "CVSS is used here only to describe the pool, never as a model input.", ""]
    rows = []
    for y in (2024, 2025):
        m = data[y]["meta"]
        hi = m["cvss3_score"] >= 9.8
        n_hi, p_hi, n_lo, p_lo = int(hi.sum()), int(m.loc[hi, "label"].sum()), int((~hi).sum()), int(m.loc[~hi, "label"].sum())
        rows.append((y, f"{n_hi / len(m):.1%}", n_hi, p_hi, f"{p_hi / n_hi:.3%}", n_lo, p_lo, f"{p_lo / n_lo:.3%}",
                     f"{(p_hi / n_hi) / (p_lo / n_lo):.2f}x"))
    L += [md(["replica", "share of pool CVSS>=9.8", "CVEs inside", "positives inside", "rate inside", "CVEs outside",
              "positives outside", "rate outside", "lift"], rows), ""]

    # --- no-EPSS prior info
    con = duckdb.connect()
    L += ["## Candidate positives for a no-EPSS prior model (informational only)", "",
          "CVEs published Jan-Sep of 2022 and 2023 labelled with the same rule (KEV date_added after the end of the publish "
          "month and on or before Nov 4 of that year). No EPSS or flag columns exist for those years; nothing was built.", ""]
    rows = []
    for y in (2022, 2023):
        r = con.execute(f"""
        WITH v AS (SELECT cve_id, CAST(published AS DATE) p FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)
                   WHERE CAST(published AS DATE) BETWEEN DATE '{y}-01-01' AND DATE '{y}-09-30'),
             k AS (SELECT cve_id, MIN(CAST(date_added AS DATE)) d FROM read_csv_auto('{data_dir}/known_exploited.csv', all_varchar=true) GROUP BY 1)
        SELECT count(*), count(k.d), count(*) FILTER (WHERE k.d > last_day(v.p) AND k.d <= DATE '{y}-11-04'),
               count(*) FILTER (WHERE k.d IS NULL OR k.d > last_day(v.p))
        FROM v LEFT JOIN k USING (cve_id)""").fetchone()
        rows.append((y, f"{r[0]:,}", f"{r[3]:,}", r[1], f"**{r[2]}**"))
    L += [md(["publish year", "CVEs published Jan-Sep", "pool (not on KEV by end of publish month)", "have a KEV entry (any date)",
              "candidate positives"], rows), ""]

    # --- final model
    X_all = pd.concat([data[2024]["X"], data[2025]["X"]], ignore_index=True)
    y_all = np.concatenate([data[2024]["y"], data[2025]["y"]])
    g_all = np.concatenate([data[2024]["groups"], data[2025]["groups"]])
    g_month = np.array([g[-2:] for g in g_all])
    params, _, ap_lgbm = select_lgbm(X_all, y_all, g_month, FEATURES, "final (both replicas, month folds)")
    ap_lr = average_precision_score(y_all, lomo_oof("logreg", None, X_all, y_all, g_month, FEATURES))
    choice, rel, why = decide_model(ap_lr, ap_lgbm)
    s_final = {m: fit_predict(m, params, X_all, y_all, sb, FEATURES) for m in MODELS}
    sbm = sb[["cve_id", "epss_rank_in_month"]].assign(s=s_final[choice])
    top = rank_order(sbm, ["s", *MODEL_COLS]).head(500)
    top[["cve_id"]].to_csv(out_dir / "top500_v1.csv", index=False)
    final_gbm = lgbm_model(params, FEATURES).fit(X_all, y_all)
    contrib = final_gbm.booster_.predict(sb.loc[top.index, FEATURES], pred_contrib=True)[:, :-1]
    pd.DataFrame(contrib, columns=FEATURES).assign(cve_id=top["cve_id"].to_numpy())[["cve_id", *FEATURES]].to_parquet(
        out_dir / "v1_top500_contrib.parquet", index=False)
    lr_final = lr_model().fit(X_all.fillna(0), y_all)
    imp = pd.DataFrame({"feature": FEATURES,
                        "lgbm_gain": final_gbm.booster_.feature_importance("gain"),
                        "logreg_coef_standardized": lr_final.named_steps["lr"].coef_[0]})
    imp["lgbm_gain_share"] = imp["lgbm_gain"] / imp["lgbm_gain"].sum()
    imp.sort_values("lgbm_gain", ascending=False).round(6).to_csv(out_dir / "v1_importances.csv", index=False)
    L += ["## Final model (fit on both replicas)", "",
          f"Pooled OOF AP (month folds across both replicas): logreg {ap_lr:.4f}, LightGBM {ap_lgbm:.4f}, relative gap {rel:.0%} "
          f"-> **{choice}** ({why}). LightGBM params: `{json.dumps(params)}`. Scored `features_scoreboard.parquet`; "
          f"wrote `outputs/top500_v1.csv` ({choice} ranking). `v1_top500_contrib.parquet` holds LightGBM pred_contrib values "
          f"for those 500 CVEs (from the LightGBM fit, whichever model ranked them). Top LightGBM gain importances:", "",
          md(["feature", "gain share", "logreg coef (standardised)"],
             [(r.feature, f"{r.lgbm_gain_share:.1%}", f"{r.logreg_coef_standardized:+.2f}")
              for r in imp.sort_values("lgbm_gain", ascending=False).head(8).itertuples()]), ""]

    # --- verdict
    L += ["## Does v1 beat the best baseline? (honest read, LOW POWER)", ""]
    lines = []
    for m, mname in MODELS.items():
        parts, wins = [], 0
        for name, tr, te, label in DIRECTIONS:
            r = dir_res[name]
            mh, bh = r[m]["arbitrary"], r[bb]["arbitrary"]
            me, be = r[m]["expected"], r[bb]["expected"]
            wins += mh > bh
            parts.append(f"{name}: {mh} hits vs {bh} for {bb} (expected {me:.1f} vs {be:.1f})")
        both = "YES" if wins == 2 else "NO"
        lines.append(f"- **{mname}** has more hits than {bb} in {wins} of 2 directions (beats it in BOTH: **{both}**). "
                     + "; ".join(parts) + ".")
    pooled_sel = {}
    for m in MODELS:
        diff = sum(dir_B[n][:, bidx[m]] - dir_B[n][:, bidx[bb]] for n, *_ in DIRECTIONS)
        lo, hi = np.percentile(diff, [5, 95])
        pooled_sel[m] = (lo, hi)
        lines.append(f"- Pooled paired-bootstrap difference vs {bb} for {MODELS[m]}: [{lo:+.0f}, {hi:+.0f}] hits. "
                     + ("The interval excludes zero." if lo > 0 else "The interval includes zero, so the evidence is inconclusive at this sample size."))
    L += lines + ["", "With 75 positives in total, differences of a few hits are within noise. No parameters or features were tuned "
                  "on the test replicas to change this outcome."]
    (out_dir / "v1_report.md").write_text("\n".join(L) + "\n")

    # --- run log (append-only, skip exact duplicates)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    log = []
    ver = {"logreg": "v1_logreg", "lgbm": "v1_lgbm"}
    for name, tr, te, label in DIRECTIONS:
        r = dir_res[name]
        for m in MODELS:
            note = (f"low power; {label}; expected={r[m]['expected']:.1f}; boot90={ci_str(r[m]['ci'])}; "
                    f"params={json.dumps(sel[tr]['params']) if m == 'lgbm' else 'C=' + str(LR_C)}")
            log.append(dict(timestamp=now, version=ver[m], replica=name, k=dir_k[name], hits=r[m]["arbitrary"],
                            baseline_exploit_epss_hits=r["Exploit code, then EPSS"]["arbitrary"], notes=note))
    for y in (2024, 2025):
        r = lomo_res[y]
        for m in MODELS:
            log.append(dict(timestamp=now, version=ver[m], replica=f"lomo{y}", k=k_for_pool(len(data[y]["y"])),
                            hits=r[m]["arbitrary"], baseline_exploit_epss_hits=r["Exploit code, then EPSS"]["arbitrary"],
                            notes=f"low power; optimistic pooled leave-one-month-out; expected={r[m]['expected']:.1f}; boot90={ci_str(r[m]['ci'])}"))
    path = out_dir / "runlog.csv"
    old = pd.read_csv(path, dtype=str) if path.exists() else pd.DataFrame()
    new = pd.DataFrame(log)
    if len(old):
        key = lambda d: set(zip(d["version"], d["replica"], d["hits"].astype(str), d["notes"]))  # noqa: E731
        new = new[[kk not in key(old) for kk in zip(new["version"], new["replica"], new["hits"].astype(str), new["notes"])]]
    new.to_csv(path, mode="a", header=not path.exists(), index=False)
    print("\n".join(L[-14:]))
    print(f"wrote v1_report.md, top500_v1.csv, v1_top500_contrib.parquet, v1_importances.csv; runlog +{len(new)} rows")


if __name__ == "__main__":
    main()
