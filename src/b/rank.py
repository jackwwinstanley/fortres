"""Ranking-method tests on the frozen v5 features (Jack's request, 2026-11-08). Run:  python -m src.b.rank [step]

Steps: noise | cand | vendor | report | all.  Writes outputs/rank_noise_floor.csv, outputs/rank_eval.csv (EVERY attempted run,
including inner-CV combos, failures and skipped candidates), outputs/rank_vendor_cv.csv, outputs/rank_report.md.
Never writes top500*, headline.json, runlog.csv, docs/, site/, app/ or README.md.

PROTOCOL (fixed before any result):
- Features: FEATURES_V5 exactly as frozen; replicas, k and tie-breaks from the existing replica code (stress_v2.prepare).
  b/outside Part 1 flagged no leaky v5 feature, so there is no "feature removed" re-run.
- Every candidate: a 20-seed (seeds 0-19) rank-averaged bag, like v5. Forward (train 2024 -> test 2025) first, then stability
  (train 2025 -> test 2024), then pooled. Paired bootstrap (1,000 draws, seed = direction index) of candidate minus v5.
- Hyper-parameters only by leave-one-month-out CV INSIDE the training year (the v5 rule). Criterion: pooled OOF average precision
  for binary objectives (exactly v5's criterion); for ranking objectives, OOF scores are first turned into percentile ranks
  within each held-out month (ranker scores from different folds are not on one scale), then pooled AP. Test year never used.
- Noise floor: the frozen v5 bag (v5's own selected parameters) with 3 new master seed sets (1000-1019, 2000-2019, 3000-3019).
  Noise floor = max - min pooled hits over those 3 bags.
- Candidates (v5's monotone constraints and fixed settings unless stated):
  H  monotone increasing ONLY in epss_rank_in_month and the four public-exploit flags (exploitdb, metasploit, nuclei,
     poc_github); everything else unconstrained (v5 also constrains n_flags and any_exploit). Parameters = v5's.
  I  regularised v5: grid num_leaves {2,3} x min_child_samples {200,400} x colsample_bytree {0.4,0.6} x reg_lambda {30,100};
     n_estimators and scale_pos_weight inherited from v5's selection.
  F  positive weighting: scale_pos_weight in {1,3,10,30,100,300}, everything else = v5's selection.
  D  LGBMRanker lambdarank, the whole training pool (or CV training fold) as ONE query group, label = 1 for positives
     (LightGBM caps a query at 10,000 rows and the pools have 29-35k, so this is attempted, logged as failed, and the run falls
     back to one query group per snapshot month),
     lambdarank_truncation_level = 500; grid num_leaves {4,7} x min_child_samples {30,100} x n_estimators {150,400} x reg_lambda {1,10}.
  E  LGBMRanker rank_xendcg, same grid and setup as D.
  J  rank-average of the v5, D, F and H bags (members fixed now).
  K  XGBoost rank:ndcg: only if xgboost is installed (it is not in requirements.txt; nothing is installed for it).
- Adoption (fixed): forward >= v5 forward AND stability >= v5 stability AND pooled gain >= 2 AND >= noise floor.
  If several qualify, the earliest of H, I, F, D, E, J, K.
- Diagnostic (does not change anything): v5 within each replica, 5-fold CV holding out whole vendors (vendor = most frequent
  CPE vendor of the CVE in affected_products.csv, used ONLY as a grouping key, never as a feature; assigner if none) vs
  ordinary stratified 5-fold CV; same v5 parameters, 5-seed bag; OOF AP and OOF hits in the top k.
LOW POWER: 27 + 48 = 75 positives.
"""
import itertools
import json
import sys
import time
from datetime import datetime, timezone

import duckdb
import lightgbm as lgb
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupKFold, StratifiedKFold

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import MONOTONE_UP, SHARE_FEATURES
from src.common.scoring import k_for_pool, paired_bootstrap_hits
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v4 import bag
from src.models.train_v5 import FEATURES_V5

F5 = list(FEATURES_V5)
DIRS = st.DIRS
DNAME = {DIRS[0]: "forward (train 2024 -> test 2025)", DIRS[1]: "stability (train 2025 -> test 2024)"}
SEEDS = list(range(20))
NOISE_SETS = {"seeds 1000-1019": range(1000, 1020), "seeds 2000-2019": range(2000, 2020), "seeds 3000-3019": range(3000, 3020)}
H_MONO = ["epss_rank_in_month", "exploitdb", "metasploit", "nuclei", "poc_github"]
GRID_I = dict(num_leaves=[2, 3], min_child_samples=[200, 400], colsample_bytree=[0.4, 0.6], reg_lambda=[30, 100])
GRID_F = dict(scale_pos_weight=[1, 3, 10, 30, 100, 300])
GRID_RANK = dict(num_leaves=[4, 7], min_child_samples=[30, 100], n_estimators=[150, 400], reg_lambda=[1, 10])
ORDER = ["H", "I", "F", "D", "E", "J", "K"]
CACHE = OUT_DIR / ".cache" / "rank"
EVAL = OUT_DIR / "rank_eval.csv"
JOBS = 4


# ---------------------------------------------------------------------------------------------------------------- logging
def log(**row):
    row = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), **row}
    for k, v in list(row.items()):
        if isinstance(v, (dict, list)):
            row[k] = json.dumps(v)
    df = pd.DataFrame([row])
    df.to_csv(EVAL, mode="a", header=not EVAL.exists(), index=False)
    print("LOG", {k: row[k] for k in ("candidate", "stage", "direction", "status") if k in row}, row.get("hits", ""), row.get("cv_ap", ""), flush=True)


# ---------------------------------------------------------------------------------------------------------------- data
def load():
    data, sb, sb2, ctx = st.prepare(OUT_DIR, DATA_DIR)
    for y in (2024, 2025):
        f = pd.read_parquet(OUT_DIR / f"features_replica_{y}.parquet").reset_index(drop=True)
        assert f["cve_id"].tolist() == data[y]["meta"]["cve_id"].tolist()
        data[y]["X5"] = dfx.to_v5(pd.concat([data[y]["X2"], f[SHARE_FEATURES]], axis=1)).reset_index(drop=True)
    for d in DIRS:
        c = ctx[d]
        c["p5"] = v1.select_lgbm(c["tr"]["X5"], c["tr"]["y"], c["tr"]["groups"], F5, f"v5 train {d[0]}")[0]
    return data, ctx


# ---------------------------------------------------------------------------------------------------------------- models
def fit_predict(spec, params, Xtr, ytr, Xte, seed, gtr=None):
    """spec: dict(kind=binary|lambdarank|rank_xendcg, mono=list of constrained features, query=pool|month).
    gtr: snapshot month of each training row (used for query groups when query == "month")."""
    mono = [1 if f in spec["mono"] else 0 for f in F5]
    base = {**v1.FIXED, "random_state": int(seed)}
    if spec["kind"] == "binary":
        m = lgb.LGBMClassifier(monotone_constraints=mono, **{**base, **params})  # a grid value overrides the fixed default
        m.fit(Xtr[F5], ytr)
        return m.predict_proba(Xte[F5])[:, 1]
    extra = {"lambdarank_truncation_level": 500} if spec["kind"] == "lambdarank" else {}
    m = lgb.LGBMRanker(objective=spec["kind"], monotone_constraints=mono, **{**base, **extra, **params})
    ytr = np.asarray(ytr).astype(int)
    if spec.get("query", "pool") == "pool":
        m.fit(Xtr[F5], ytr, group=[len(Xtr)])
    else:  # one query per snapshot month; LightGBM needs each query's rows to be contiguous
        g = np.asarray(gtr).astype(str)
        o = np.argsort(g, kind="stable")
        m.fit(Xtr[F5].iloc[o], ytr[o], group=pd.Series(g[o]).value_counts(sort=False).reindex(pd.unique(g[o])).to_numpy())
    return m.predict(Xte[F5])


def inner_cv_ap(spec, params, X, y, groups):
    """Leave-one-month-out inside the training year. Binary: pooled OOF AP (v5's rule). Rankers: within-month pct rank first."""
    groups = np.asarray(groups)
    oof = np.zeros(len(X))
    for g in sorted(set(groups)):
        te = groups == g
        s = fit_predict(spec, params, X[~te].reset_index(drop=True), np.asarray(y)[~te], X[te].reset_index(drop=True), 0, groups[~te])
        oof[te] = s if spec["kind"] == "binary" else pd.Series(s).rank(pct=True).to_numpy()
    return float(average_precision_score(y, oof))


def select(cand, spec, base_params, grid, c, d):
    combos = [{**base_params, **dict(zip(grid, v))} for v in itertools.product(*grid.values())]
    cp = CACHE / f"sel_{cand}_{d[0]}.json"
    if cp.exists():
        return json.loads(cp.read_text())["params"]
    X, y, g = c["tr"]["X5"], c["tr"]["y"], c["tr"]["groups"]
    t = time.time()
    res = Parallel(n_jobs=JOBS)(delayed(_safe_cv)(spec, p, X, y, g) for p in combos)
    ok = [(ap, i) for i, (ap, err) in enumerate(res) if err is None]
    best = max(ok)[1] if ok else None
    for i, (p, (ap, err)) in enumerate(zip(combos, res)):
        log(candidate=cand, stage="inner_cv (train year only)", direction=DNAME[d], params=p, cv_ap=ap,
            status="failed" if err else ("selected" if i == best else "not selected (discarded variant)"),
            notes=err or f"leave-one-month-out inside train {d[0]}; {len(combos)} combos; {time.time() - t:.0f}s for the grid")
    if best is None:
        raise RuntimeError(f"all inner-CV combos failed for {cand}")
    cp.write_text(json.dumps({"params": combos[best], "ap": res[best][0]}))
    return combos[best]


def _safe_cv(spec, p, X, y, g):
    try:
        return inner_cv_ap(spec, p, X, y, g), None
    except Exception as e:  # logged, never dropped
        return None, f"{type(e).__name__}: {e}"


def bag_scores(tag, spec, params, c, seeds):
    cp = CACHE / f"bag_{tag}.npy"
    if cp.exists():
        return np.load(cp)
    Xtr, ytr, Xte = c["tr"]["X5"], c["tr"]["y"], c["te"]["X5"]
    sc = Parallel(n_jobs=JOBS)(delayed(fit_predict)(spec, params, Xtr, ytr, Xte, s, c["tr_months"]) for s in seeds)
    b = bag(sc)
    np.save(cp, b)
    return b


def positions(c, score):
    order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
    pos = np.empty(len(order), dtype=np.int64)
    pos[order] = np.arange(len(order))
    return pos


def iv(x):
    return f"[{np.percentile(x, 5):+.0f}, {np.percentile(x, 95):+.0f}]"


V5_SPEC = dict(kind="binary", mono=[f for f in F5 if f in MONOTONE_UP])


# ---------------------------------------------------------------------------------------------------------------- steps
def noise(ctx):
    rows = []
    for name, seeds in {"seeds 0-19 (the headline bag)": SEEDS, **NOISE_SETS}.items():
        h = []
        for d in DIRS:
            c = ctx[d]
            b = bag_scores(f"v5_{name.split()[1]}_{d[0]}", V5_SPEC, c["p5"], c, list(seeds))
            h.append(st.hits_of(c, b))
        rows.append({"seed_set": name, "forward_hits": h[0], "stability_hits": h[1], "pooled_hits": sum(h),
                     "used_for_noise_floor": "no (reference)" if "headline" in name else "yes"})
        log(candidate="v5 frozen", stage="noise floor", direction="both", params={"seeds": name}, hits=f"{h[0]} / {h[1]} / {sum(h)}", status="ok",
            notes="v5's own selected parameters; forward / stability / pooled")
    df = pd.DataFrame(rows)
    used = df[df["used_for_noise_floor"] == "yes"]
    spread = {k: int(used[k].max() - used[k].min()) for k in ("forward_hits", "stability_hits", "pooled_hits")}
    df.loc[len(df)] = {"seed_set": "spread (max - min over the 3 new sets)", **spread, "used_for_noise_floor": "noise floor = pooled spread"}
    df.to_csv(OUT_DIR / "rank_noise_floor.csv", index=False)
    print(df.to_string())
    return spread["pooled_hits"]


def candidates(ctx):
    have_xgb = __import__("importlib").util.find_spec("xgboost") is not None
    specs = {
        "H": (dict(kind="binary", mono=H_MONO), None, None),
        "I": (V5_SPEC, GRID_I, None),
        "F": (V5_SPEC, GRID_F, None),
        "D": (dict(kind="lambdarank", mono=V5_SPEC["mono"]), GRID_RANK, {}),
        "E": (dict(kind="rank_xendcg", mono=V5_SPEC["mono"]), GRID_RANK, {}),
    }
    scores = {d: {"v5": bag_scores(f"v5_0-19_{d[0]}", V5_SPEC, ctx[d]["p5"], ctx[d], SEEDS)} for d in DIRS}
    for cand in ("D", "E"):
        spec = specs[cand][0]
        for d in DIRS:
            c = ctx[d]
            try:  # the setup as specified: the whole training pool as ONE query (fit on training data only, nothing scored)
                fit_predict({**spec, "query": "pool"}, dict(num_leaves=4, min_child_samples=30, n_estimators=5, reg_lambda=1),
                            c["tr"]["X5"], c["tr"]["y"], c["tr"]["X5"].head(5), 0)
                log(candidate=cand, stage="setup check: one query per pool", direction=DNAME[d], status="ok", notes="single query accepted")
            except Exception as e:
                log(candidate=cand, stage="setup check: one query per pool", direction=DNAME[d], status="failed",
                    notes=f"{type(e).__name__}: {e}. Fallback (deviation from the spec): one query group per snapshot month (9 per pool, 3-4k rows each)")
                specs[cand] = ({**spec, "query": "month"}, *specs[cand][1:])
    for cand, (spec, grid, base) in specs.items():
        for d in DIRS:
            c = ctx[d]
            try:
                params = dict(c["p5"]) if grid is None else select(cand, spec, dict(c["p5"]) if base is None else base, grid, c, d)
                scores[d][cand] = bag_scores(f"{cand}_{d[0]}", spec, params, c, SEEDS)
                log(candidate=cand, stage="test (20-seed bag)", direction=DNAME[d], params=params, hits=st.hits_of(c, scores[d][cand]), status="ok",
                    notes=f"monotone: {spec['mono']}; objective {spec['kind']}")
            except Exception as e:
                log(candidate=cand, stage="test (20-seed bag)", direction=DNAME[d], status="failed", notes=f"{type(e).__name__}: {e}")
    for d in DIRS:
        if all(m in scores[d] for m in ("v5", "D", "F", "H")):
            scores[d]["J"] = bag([scores[d][m] for m in ("v5", "D", "F", "H")])
            log(candidate="J", stage="test (rank-average of v5, D, F, H bags)", direction=DNAME[d], hits=st.hits_of(ctx[d], scores[d]["J"]), status="ok",
                notes="members fixed in advance")
        else:
            log(candidate="J", stage="test", direction=DNAME[d], status="failed", notes="a member is missing")
    if not have_xgb:
        log(candidate="K", stage="test", direction="both", status="skipped", notes="xgboost is not installed (not in requirements.txt); not installed for this optional candidate")
    return scores


def summarise(ctx, scores, floor):
    rows, draws = [], {}
    names = ["v5"] + [n for n in ORDER if all(n in scores[d] for d in DIRS)]
    for j, d in enumerate(DIRS):
        c = ctx[d]
        B = paired_bootstrap_hits(c["label"], [positions(c, scores[d][n]) for n in names], c["k"], n=v1.N_BOOT, seed=j)
        for i, n in enumerate(names):
            diff = B[:, i] - B[:, 0]
            draws[n] = draws.get(n, 0) + diff
            rows.append({"candidate": n, "test": DNAME[d], "k": c["k"], "hits": st.hits_of(c, scores[d][n]),
                         "diff_vs_v5": None if n == "v5" else st.hits_of(c, scores[d][n]) - st.hits_of(c, scores[d]["v5"]),
                         "diff_vs_v5_90": None if n == "v5" else iv(diff)})
    df = pd.DataFrame(rows)
    out = []
    for n in names:
        h = df[df["candidate"] == n]["hits"].tolist()
        out.append({"candidate": n, "test": "pooled", "k": None, "hits": sum(h), "diff_vs_v5": None if n == "v5" else sum(h) - (df[df["candidate"] == "v5"]["hits"].sum()),
                    "diff_vs_v5_90": None if n == "v5" else iv(draws[n])})
    df = pd.concat([df, pd.DataFrame(out)], ignore_index=True)
    v5h = df[df["candidate"] == "v5"].set_index("test")["hits"]
    verdict, adopted = [], None
    for n in names[1:]:
        h = df[df["candidate"] == n].set_index("test")["hits"]
        ok1, ok2 = h[DNAME[DIRS[0]]] >= v5h[DNAME[DIRS[0]]], h[DNAME[DIRS[1]]] >= v5h[DNAME[DIRS[1]]]
        gain = h["pooled"] - v5h["pooled"]
        ok3 = gain >= 2 and gain >= floor
        q = ok1 and ok2 and ok3
        if q and adopted is None:
            adopted = n
        verdict.append({"candidate": n, "forward_ok": ok1, "stability_ok": ok2, "pooled_gain": int(gain), "noise_floor": floor, "gain_ok": ok3, "qualifies": q})
    for r in verdict:
        log(candidate=r["candidate"], stage="adoption check", direction="both", hits=f"pooled gain {r['pooled_gain']:+d}", status="qualifies" if r["qualifies"] else "does not qualify",
            notes=json.dumps({k: bool(v) if isinstance(v, (bool, np.bool_)) else v for k, v in r.items()}))
    return df, pd.DataFrame(verdict), adopted


def vendor_of(ids):
    con = duckdb.connect()
    ap = pd.read_csv(DATA_DIR / "affected_products.csv", usecols=["cve_id", "vendor"], dtype=str).dropna()
    ap = ap[ap["cve_id"].isin(set(ids))]
    v = ap.assign(vendor=ap["vendor"].str.lower()).groupby("cve_id")["vendor"].agg(lambda x: x.value_counts().index[0])
    a = con.execute(f"SELECT cve_id, assigner FROM read_csv_auto('{DATA_DIR}/vulnerabilities.csv', all_varchar=true)").df().set_index("cve_id")["assigner"]
    ids = pd.Index(ids)
    return v.reindex(ids).fillna("assigner:" + a.reindex(ids).fillna("unknown")).to_numpy(), float(v.reindex(ids).notna().mean())


def vendor_cv(data, ctx):
    rows = []
    for d in DIRS:
        y_ = d[0]
        X, y, meta = data[y_]["X5"], np.asarray(data[y_]["y"]), data[y_]["meta"].reset_index(drop=True)
        c = ctx[d]
        k = k_for_pool(len(meta))
        vend, cov = vendor_of(meta["cve_id"])
        rank = meta["epss_rank_in_month"].to_numpy()
        code = np.argsort(np.argsort(meta["cve_id"].to_numpy()))
        cc = {"label": y, "rank": rank, "code": code, "k": k}
        for scheme, splits in (("ungrouped (stratified 5-fold)", StratifiedKFold(5, shuffle=True, random_state=0).split(X, y)),
                               ("vendor-grouped (whole vendors held out, 5-fold)", GroupKFold(5).split(X, y, vend))):
            oof = np.zeros(len(X))
            for tr, te in splits:
                sc = Parallel(n_jobs=JOBS)(delayed(fit_predict)(V5_SPEC, c["p5"], X.iloc[tr], y[tr], X.iloc[te], s) for s in range(5))
                oof[te] = np.mean(sc, axis=0)
            r = {"replica": y_, "scheme": scheme, "positives": int(y.sum()), "k": k, "oof_ap": round(float(average_precision_score(y, oof)), 4),
                 "oof_hits_top_k": st.hits_of(cc, oof), "vendor_known_share": round(cov, 3)}
            rows.append(r)
            log(candidate="v5 (diagnostic)", stage="vendor-grouped CV", direction=f"within replica {y_}", params=c["p5"], hits=r["oof_hits_top_k"], cv_ap=r["oof_ap"], status="ok", notes=scheme)
    df = pd.DataFrame(rows)
    df.to_csv(OUT_DIR / "rank_vendor_cv.csv", index=False)
    print(df.to_string())
    return df


def main(step="all"):
    CACHE.mkdir(parents=True, exist_ok=True)
    data, ctx = load()
    if step in ("noise", "all"):
        noise(ctx)
    if step in ("cand", "all"):
        floor = int(pd.read_csv(OUT_DIR / "rank_noise_floor.csv").iloc[-1]["pooled_hits"])
        scores = candidates(ctx)
        df, ver, adopted = summarise(ctx, scores, floor)
        df.to_csv(OUT_DIR / "rank_summary.csv", index=False)
        ver.to_csv(OUT_DIR / "rank_adoption.csv", index=False)
        print(df.to_string())
        print(ver.to_string())
        print("ADOPTED:", adopted or "none -> v5 stays")
    if step in ("vendor", "all"):
        vendor_cv(data, ctx)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "all")
