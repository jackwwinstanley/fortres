"""Method zoo: the ONE shared harness (Jack's spec, step 1). Frozen with its own commit before any method is run.

Every method module (src/b/zoo/mNN_<name>.py) calls only `evaluate(...)` (or `run_method`, a thin loop over evaluate), so
all numbers are comparable. One row per call is appended to outputs/zoo/<method>.csv.

PROTOCOL (fixed before any method result):
- Features: the frozen v5 features (FEATURES_V5) built exactly as in src/b/rank.py (stress_v2.prepare + drift_fix.to_v5).
- Splits: forward = train replica 2024 -> test replica 2025; stability = train 2025 -> test 2024. Pooled = sum of the two.
- Hits: top k of the test pool (k from k_for_pool, 243 forward / 198 stability), ordered by score desc, then EPSS rank desc,
  then cve_id asc (the repo's tie rule). Tie-aware: every row also reports `*_hits_random_ties`, the expected hits if rows
  tied on score at the k boundary were ordered at random (so a method cannot gain from the EPSS tie-break silently).
- Baselines, each a 20-seed rank-averaged bag with per-seed scores cached (outputs/.cache/zoo/base_*.npy):
    v5 frozen = v5's own selected parameters (cached v5 selection per training year);
    I         = b/rank's regularised v5, settings per training year (b/rank's inner-CV selection, copied below and checked
                against outputs/.cache/rank/sel_I_<year>.json when present).
  Seed sets: 0-19 (main), 1000-1019, 2000-2019, 3000-3019 (confirmation). I's spread = max - min pooled hits over the 4 sets,
  measured here and written to outputs/zoo/baselines.csv.
- Paired bootstrap: 1,000 row resamples per direction (seed = direction index 0/1, the b/rank rule), same draws for the method
  and I (and v5); pooled draws = forward draw + stability draw; interval = 5th-95th percentile of (method - I).
- Variants: "standalone" (the method's own score; stochastic methods bagged over the seed set like v5);
  "blend_I" (0.5 x percentile rank of the method + 0.5 x percentile rank of I's bag for the SAME seed set);
  "I_plus_feature" (the method returns feature columns; I is refit with I's settings on v5 features + those columns, 20-seed
  bag, v5 monotone constraints kept on the v5 columns, new columns unconstrained). Training-row features are computed
  leave-one-snapshot-month-out INSIDE the training year (fit on the other 8 months), test rows from a fit on the whole
  training year, so a label-dependent feature never sees its own row's label and never sees the test year.
- Leak rules: a Pool only carries cve_id, v5 features, snapshot month, description text, CWE ids, the snapshot EPSS rank,
  timing and KEV date (for time-to-event only, training rows). It carries NO affected_products, references, nvd_status,
  n_affected_cpes, n_references or CVSS. nvd_status is exposed only through `nvd_status_check_only()` for m02's check.
- Coverage: for feature variants (and any standalone run given a coverage_fn) the features are computed on the 2026
  scoreboard from a fit on replica 2025; coverage = share of scoreboard rows where the feature is present and differs from
  its most common training value. A run whose features all have coverage 0 gets status "rejected (coverage)".
- Failures: any exception becomes a row with status=failed and the reason. The runner (run.py) adds failed rows for
  timeouts (40 min cap) and crashes, so no run is dropped.
"""
import argparse
import json
import os
import time
import traceback
from datetime import datetime, timezone
from functools import lru_cache

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import MONOTONE_UP, SHARE_FEATURES
from src.common.scoring import paired_bootstrap_hits
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v4 import bag
from src.models.train_v5 import FEATURES_V5

ZOO = OUT_DIR / "zoo"
CACHE = OUT_DIR / ".cache" / "zoo"
F5 = list(FEATURES_V5)
MONO = [f for f in F5 if f in MONOTONE_UP]
DIRS = st.DIRS  # [(2024, 2025), (2025, 2024)]: forward first
DNAME = {DIRS[0]: "forward", DIRS[1]: "stability"}
SEED_SETS = {"0-19": list(range(0, 20)), "1000-1019": list(range(1000, 1020)),
             "2000-2019": list(range(2000, 2020)), "3000-3019": list(range(3000, 3020))}
MAIN_SET = "0-19"
CONFIRM_SETS = ["1000-1019", "2000-2019", "3000-3019"]
VARIANTS = ("standalone", "blend_I", "I_plus_feature")
N_BOOT = 1000
LGB_JOBS = int(os.environ.get("ZOO_LGB_JOBS", "2"))  # deterministic=True in v1.FIXED, so thread count does not change scores
# b/rank's I selection (inner leave-one-month-out CV on the training year only), per TRAINING year
I_PARAMS = {2024: {"num_leaves": 2, "min_child_samples": 200, "n_estimators": 150, "reg_lambda": 30, "scale_pos_weight": 10, "colsample_bytree": 0.4},
            2025: {"num_leaves": 3, "min_child_samples": 200, "n_estimators": 150, "reg_lambda": 30, "scale_pos_weight": 10, "colsample_bytree": 0.6}}
BANNED_IN_POOL = ("affected", "reference", "nvd_status", "n_affected_cpes", "n_references", "cvss")


def log(*a):
    print(datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------------------------------------------------------- pools
class Pool:
    """One pool of CVEs (a replica year or the 2026 scoreboard). Only leak-safe columns."""

    def __init__(self, name, cve_id, X, y, months, rank, desc, cwe, days_to_cutoff, days_to_kev):
        self.name, self.cve_id, self.X = name, np.asarray(cve_id), X.reset_index(drop=True)
        self.y = None if y is None else np.asarray(y).astype(int)
        self.months, self.rank = np.asarray(months).astype(str), np.asarray(rank, float)
        self.desc, self.cwe = np.asarray(desc, dtype=object), list(cwe)
        self.days_to_cutoff, self.days_to_kev = np.asarray(days_to_cutoff, float), np.asarray(days_to_kev, float)
        assert not any(b in c.lower() for c in self.X.columns for b in BANNED_IN_POOL)

    def __len__(self):
        return len(self.cve_id)

    def subset(self, mask):
        m = np.asarray(mask)
        return Pool(self.name, self.cve_id[m], self.X[m].reset_index(drop=True), None if self.y is None else self.y[m], self.months[m],
                    self.rank[m], self.desc[m], [c for c, k in zip(self.cwe, m) if k], self.days_to_cutoff[m], self.days_to_kev[m])

    def emb(self):
        """Granite embeddings (ibm-granite/granite-embedding-30m-english, L2-normalised) of the descriptions, row-aligned."""
        e, idx = _emb()
        return np.asarray(e[[idx[c] for c in self.cve_id]])


@lru_cache(None)
def _emb():
    ids = pd.read_csv(OUT_DIR / "emb_ids.csv")["cve_id"].tolist()
    return np.load(OUT_DIR / "emb_small.npy", mmap_mode="r"), {c: i for i, c in enumerate(ids)}


@lru_cache(None)
def _vuln():
    v = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "cwe_ids", "nvd_status"], dtype=str)
    return v.drop_duplicates("cve_id").set_index("cve_id")


def nvd_status_check_only(cve_ids):
    """For m02's missingness CHECK only. Never a feature."""
    return _vuln()["nvd_status"].reindex(cve_ids).fillna("unknown").to_numpy()


def _cwes(ids):
    s = _vuln()["cwe_ids"].reindex(ids)
    return [[] if (not isinstance(x, str) or not x.strip()) else sorted({t.strip() for t in x.replace(";", ",").replace("|", ",").split(",") if t.strip()})
            for x in s]


@lru_cache(None)
def load():
    """Returns (pools {2024, 2025, 'sb'}, ctx {dir: rank-style context}, p5 {train year: v5 params})."""
    data, sb, sb2, ctx = st.prepare(OUT_DIR, DATA_DIR)
    texts = pd.read_parquet(OUT_DIR / "b_texts.parquet", columns=["cve_id", "description"]).drop_duplicates("cve_id").set_index("cve_id")["description"]
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")["date_added"]
    pools, p5 = {}, {}
    for y in (2024, 2025):
        f = pd.read_parquet(OUT_DIR / f"features_replica_{y}.parquet").reset_index(drop=True)
        assert f["cve_id"].tolist() == data[y]["meta"]["cve_id"].tolist()
        X5 = dfx.to_v5(pd.concat([data[y]["X2"], f[SHARE_FEATURES]], axis=1)).reset_index(drop=True)[F5]
        data[y]["X5"] = X5
        rep = pd.read_parquet(OUT_DIR / f"replica_{y}.parquet").drop_duplicates("cve_id").set_index("cve_id")
        ids = f["cve_id"].to_numpy()
        end = (pd.PeriodIndex(f["snapshot_month"], freq="M").end_time.normalize()).to_numpy()
        kd = pd.to_datetime(kev.reindex(ids)).to_numpy()
        dk = (kd - end) / np.timedelta64(1, "D")
        y_ = data[y]["y"]
        dk = np.where(np.asarray(y_) == 1, dk, np.nan)  # time to KEV only for positives (inside the label window)
        pools[y] = Pool(str(y), ids, X5, y_, f["snapshot_month"], data[y]["meta"]["epss_rank_in_month"], texts.reindex(ids).fillna("").to_numpy(),
                        _cwes(ids), rep["days_to_cutoff"].reindex(ids).to_numpy(), dk)
    sb2s = pd.concat([sb2.reset_index(drop=True), sb[SHARE_FEATURES].reset_index(drop=True)], axis=1)
    sb5 = dfx.to_v5(sb2s)[F5].reset_index(drop=True)
    sid = sb["cve_id"].to_numpy()
    pools["sb"] = Pool("scoreboard 2026", sid, sb5, None, sb["snapshot_month"], sb["epss_rank_in_month"], texts.reindex(sid).fillna("").to_numpy(),
                       _cwes(sid), sb["days_to_cutoff"] if "days_to_cutoff" in sb else np.full(len(sb), np.nan), np.full(len(sb), np.nan))
    for d in DIRS:
        c = ctx[d]
        p5[d[0]] = v1.select_lgbm(data[d[0]]["X5"], data[d[0]]["y"], data[d[0]]["groups"], F5, f"v5 train {d[0]}")[0]
        assert np.array_equal(pools[d[1]].y, np.asarray(c["label"]))
    for y in (2024, 2025):  # I's settings must be b/rank's
        f = OUT_DIR / ".cache" / "rank" / f"sel_I_{y}.json"
        if f.exists():
            assert json.loads(f.read_text())["params"] == I_PARAMS[y], f"I params differ from b/rank for {y}"
    return pools, ctx, p5


# ---------------------------------------------------------------------------------------------------------------- models
def lgb_fit_predict(params, Xtr, ytr, Xte, seed, mono_cols=None):
    """LightGBM binary with v1.FIXED + params; monotone +1 on the v5 MONO columns present."""
    mono_cols = MONO if mono_cols is None else mono_cols
    cols = list(Xtr.columns)
    m = lgb.LGBMClassifier(monotone_constraints=[1 if c in mono_cols else 0 for c in cols],
                           **{**v1.FIXED, "random_state": int(seed), "n_jobs": LGB_JOBS, **params})
    m.fit(Xtr, ytr)
    return m.predict_proba(Xte[cols])[:, 1]


def pct(s):
    return pd.Series(np.asarray(s, float)).rank(pct=True, method="average").to_numpy()


def baseline_seed_scores(name, d, seed_set):
    """Per-seed test scores (20, n_test) of baseline 'v5' or 'I' for direction d and a seed set; cached on disk."""
    CACHE.mkdir(parents=True, exist_ok=True)
    cp = CACHE / f"base_{name}_{seed_set}_{d[0]}.npy"
    if cp.exists():
        return np.load(cp)
    pools, ctx, p5 = load()
    tr, te = pools[d[0]], pools[d[1]]
    params = p5[d[0]] if name == "v5" else I_PARAMS[d[0]]
    sc = np.array([lgb_fit_predict(params, tr.X, tr.y, te.X, s) for s in SEED_SETS[seed_set]])
    np.save(cp, sc)
    return sc


def baseline_bag(name, d, seed_set):
    return bag(list(baseline_seed_scores(name, d, seed_set)))


def positions(c, score):
    order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
    pos = np.empty(len(order), dtype=np.int64)
    pos[order] = np.arange(len(order))
    return pos


def hits_random_ties(c, score):
    s, lab, k = np.asarray(score, float), np.asarray(c["label"]), c["k"]
    sk = np.sort(s)[::-1][k - 1]
    above = s > sk
    tied = s == sk
    slots = k - above.sum()
    return float(lab[above].sum() + lab[tied].sum() * slots / tied.sum())


def baselines_table():
    """I and v5 hits for every seed set; I's spread over the 4 sets. Writes outputs/zoo/baselines.csv."""
    pools, ctx, _ = load()
    rows = []
    for name in ("v5", "I"):
        for ss in SEED_SETS:
            h = [st.hits_of(ctx[d], baseline_bag(name, d, ss)) for d in DIRS]
            rows.append({"baseline": name, "seed_set": ss, "forward": h[0], "stability": h[1], "pooled": sum(h)})
    df = pd.DataFrame(rows)
    ZOO.mkdir(parents=True, exist_ok=True)
    df.to_csv(ZOO / "baselines.csv", index=False)
    return df


def i_spread():
    df = baselines_table()
    p = df[df["baseline"] == "I"]["pooled"]
    return int(p.max() - p.min())


# ---------------------------------------------------------------------------------------------------------------- features
def oof_features(fn, tr, seed, env):
    """Training-row features leave-one-snapshot-month-out inside the training year."""
    parts = [None] * len(tr)
    out = None
    for m in sorted(set(tr.months)):
        te_mask = tr.months == m
        f = fn(tr.subset(~te_mask), tr.subset(te_mask), seed, env).reset_index(drop=True)
        if out is None:
            out = pd.DataFrame(index=range(len(tr)), columns=f.columns, dtype=float)
        out.loc[np.flatnonzero(te_mask), f.columns] = f.to_numpy(dtype=float)
    del parts
    return out.astype(float)


def coverage(fn, seed, env):
    pools, _, _ = load()
    fsb = fn(pools[2025], pools["sb"], seed, env).reset_index(drop=True)
    ftr = fn(pools[2024], pools[2025], seed, env).reset_index(drop=True)  # 'training value' reference distribution
    cov = {}
    for c in fsb.columns:
        mode = pd.Series(ftr[c]).round(9).mode()
        mode = mode.iloc[0] if len(mode) else np.nan
        v = pd.Series(fsb[c]).astype(float).round(9)
        cov[c] = round(float((v.notna() & (v != mode)).mean()), 4)
    return cov


# ---------------------------------------------------------------------------------------------------------------- evaluate
def evaluate(method_name, fit_predict_fn, variant, seed_set=MAIN_SET, deterministic=False, coverage_fn=None, notes="", params=None):
    """Score one method variant on forward then stability, paired bootstrap vs I, append ONE row to outputs/zoo/<method>.csv.

    fit_predict_fn(train: Pool, apply: Pool, seed: int, env: dict):
      variant standalone / blend_I -> 1-D array of scores for `apply` rows (higher = more likely KEV);
      variant I_plus_feature       -> DataFrame of feature columns for `apply` rows (fit on `train` only).
    deterministic: call once per direction with the first seed of the set instead of bagging over the set.
    env: {"direction", "seed_set", "seeds", "I_seed_scores" (20, n_apply) for the test pool, "I_params", "v5_params"}.
    """
    assert variant in VARIANTS
    ZOO.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    row = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "method": method_name, "variant": variant,
           "seed_set": seed_set, "deterministic": deterministic, "status": "ok", "reason": "", "params": json.dumps(params or {}), "notes": notes}
    try:
        pools, ctx, p5 = load()
        seeds = SEED_SETS[seed_set]
        draws_I, draws_v5 = 0, 0
        for j, d in enumerate(DIRS):
            c, tr, te, nm = ctx[d], pools[d[0]], pools[d[1]], DNAME[d]
            env = {"direction": d, "seed_set": seed_set, "seeds": seeds, "I_seed_scores": baseline_seed_scores("I", d, seed_set),
                   "I_params": I_PARAMS[d[0]], "v5_params": p5[d[0]]}
            Ib, v5b = baseline_bag("I", d, seed_set), baseline_bag("v5", d, seed_set)
            use = seeds[:1] if deterministic else seeds
            if variant in ("standalone", "blend_I"):
                score = bag([np.asarray(fit_predict_fn(tr, te, s, env), float) for s in use])
                if variant == "blend_I":
                    score = 0.5 * pct(score) + 0.5 * pct(Ib)
            else:
                ftr = oof_features(fit_predict_fn, tr, use[0], env)
                fte = fit_predict_fn(tr, te, use[0], env).reset_index(drop=True).astype(float)
                ftr.columns = fte.columns = [f"zoo_{x}" for x in fte.columns]
                Xtr, Xte = pd.concat([tr.X, ftr], axis=1), pd.concat([te.X, fte], axis=1)
                score = bag([lgb_fit_predict(I_PARAMS[d[0]], Xtr, tr.y, Xte, s) for s in seeds])
                row["n_new_features"] = fte.shape[1]
            assert len(score) == len(te) and np.isfinite(score).all(), "scores must be finite, one per test row"
            h, hI, h5 = st.hits_of(c, score), st.hits_of(c, Ib), st.hits_of(c, v5b)
            B = paired_bootstrap_hits(c["label"], [positions(c, score), positions(c, Ib), positions(c, v5b)], c["k"], n=N_BOOT, seed=j)
            draws_I = draws_I + (B[:, 0] - B[:, 1])
            draws_v5 = draws_v5 + (B[:, 0] - B[:, 2])
            row.update({f"{nm}": h, f"{nm}_I": hI, f"{nm}_v5": h5, f"{nm}_delta_I": h - hI,
                        f"{nm}_delta_I_90": f"[{np.percentile(B[:, 0] - B[:, 1], 5):+.0f}, {np.percentile(B[:, 0] - B[:, 1], 95):+.0f}]",
                        f"{nm}_hits_random_ties": round(hits_random_ties(c, score), 2), f"{nm}_k": c["k"]})
            log(method_name, variant, seed_set, nm, h, "I", hI)
        row["pooled"] = row["forward"] + row["stability"]
        row["pooled_I"] = row["forward_I"] + row["stability_I"]
        row["pooled_v5"] = row["forward_v5"] + row["stability_v5"]
        row["pooled_delta_I"] = row["pooled"] - row["pooled_I"]
        row["pooled_delta_I_90"] = f"[{np.percentile(draws_I, 5):+.0f}, {np.percentile(draws_I, 95):+.0f}]"
        row["pooled_delta_I_p_le0"] = round(float((draws_I <= 0).mean()), 3)
        row["pooled_delta_v5"] = row["pooled"] - row["pooled_v5"]
        cf = fit_predict_fn if variant == "I_plus_feature" else coverage_fn
        if cf is not None:
            env = {"direction": (2025, "sb"), "seed_set": seed_set, "seeds": seeds, "I_seed_scores": None, "I_params": I_PARAMS[2025], "v5_params": p5[2025]}
            cov = coverage(cf, seeds[0], env)
            row["coverage_2026"] = json.dumps(cov)
            if max(cov.values(), default=0) == 0:
                row["status"], row["reason"] = "rejected (coverage)", "no feature fires on the 2026 scoreboard"
    except Exception as e:
        row["status"], row["reason"] = "failed", f"{type(e).__name__}: {e}"
        traceback.print_exc()
    row["runtime_s"] = round(time.time() - t0, 1)
    out = ZOO / f"{method_name}.csv"
    df = pd.DataFrame([row])
    if out.exists():
        df = pd.concat([pd.read_csv(out), df], ignore_index=True)
    df.to_csv(out, index=False)
    log("ROW", method_name, variant, seed_set, row["status"], row.get("forward"), row.get("stability"), row.get("pooled"), row.get("pooled_delta_I"), row["reason"])
    return row


def run_method(method_name, score_fn=None, feature_fn=None, deterministic=False, variants=None, coverage_fn=None, params=None, notes=""):
    """CLI loop: python -m src.b.zoo.mNN_x [--seed-set S] [--variants a,b]. Calls evaluate once per variant."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-set", default=MAIN_SET)
    ap.add_argument("--variants", default=None)
    a = ap.parse_args()
    vs = a.variants.split(",") if a.variants else (variants or [v for v in VARIANTS if (v != "I_plus_feature" or feature_fn is not None)])
    for v in vs:
        fn = feature_fn if v == "I_plus_feature" else score_fn
        evaluate(method_name, fn, v, seed_set=a.seed_set, deterministic=deterministic, coverage_fn=coverage_fn if v == "standalone" else None,
                 params=params, notes=notes)


if __name__ == "__main__":  # python -m src.b.zoo.harness  -> build and cache the baselines, write outputs/zoo/baselines.csv
    print(baselines_table().to_string())
    print("I spread (pooled, 4 seed sets):", i_spread())
