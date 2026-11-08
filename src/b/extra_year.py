"""An older year the model never saw (2023). The plan was committed before any result: outputs/extra_year_plan.md (8c19afb).

Run:  python -m src.b.extra_year fidelity   # rebuild 2024 signals from outside data, compare with data/exploit_signals_2024.csv
      python -m src.b.extra_year run        # build 2023, train on 2024 + 2025 with v6's settings, one run
Outside downloads stay in the gitignored data/outside/ and ~/ibm/ext/. Never writes any list, model file or headline.json.
"""
import glob
import gzip
import json
import os
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR

MSF_REPO = Path(os.environ.get("MSF_REPO", Path.home() / "ibm" / "ext" / "metasploit-framework"))
POC_DIR = DATA_DIR / "outside" / "poc-in-github"
EDB_CSV = DATA_DIR / "outside" / "files_exploits.csv"
EPSS_DIRS = [DATA_DIR / "outside" / "epss2023", DATA_DIR / "outside" / "epss"]
WORK = DATA_DIR / "outside" / "extra_year"
EMB_DIR = Path(os.environ.get("EXTRA_EMB_DIR", OUT_DIR.parents[1] / "ibm-breach" / "outputs"))
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


# ---- the as-of rule ----------------------------------------------------------------------------------------------------------------
def month_end(months) -> pd.Series:
    return (pd.to_datetime(pd.Series(months).astype(str) + "-01", utc=True) + pd.offsets.MonthEnd(0)
            + pd.Timedelta(hours=23, minutes=59, seconds=59))


def dated_flag(pool: pd.DataFrame, records: pd.DataFrame) -> np.ndarray:
    """pool: cve_id, snapshot_month. records: cve_id, date (UTC). 1 only if a record is dated on or before the snapshot-month end."""
    d = pool[["cve_id", "snapshot_month"]].reset_index(drop=True).copy()
    d["end"] = month_end(d["snapshot_month"]).to_numpy()
    m = records.dropna(subset=["cve_id", "date"]).merge(d[["cve_id", "end"]], on="cve_id")
    ok = set(m.loc[m["date"] <= m["end"], "cve_id"])
    return d["cve_id"].isin(ok).astype(int).to_numpy()


# ---- outside records ---------------------------------------------------------------------------------------------------------------
def exploitdb_records() -> pd.DataFrame:
    e = pd.read_csv(EDB_CSV, usecols=["codes", "date_published", "date_added"], dtype=str)
    pub = pd.to_datetime(e["date_published"], errors="coerce", utc=True)
    add = pd.to_datetime(e["date_added"], errors="coerce", utc=True)
    e["date"] = pd.concat([pub, add], axis=1).max(axis=1)      # the later of the two: never early
    e["cve_id"] = e["codes"].fillna("").map(lambda s: [c.upper() for c in CVE_RE.findall(s)])
    return e.explode("cve_id")[["cve_id", "date"]].dropna()


def nuclei_records() -> pd.DataFrame:
    n = pd.read_csv(OUT_DIR / "newdata_nuclei_first_added.csv")
    return pd.DataFrame({"cve_id": n["cve_id"], "date": pd.to_datetime(n["first_added_date"], utc=True)})


def poc_records(wanted: set) -> pd.DataFrame:
    rows = []
    for path in glob.glob(str(POC_DIR / "*" / "CVE-*.json")):
        cve = os.path.basename(path)[:-5]
        if cve in wanted:
            rows += [(cve, r.get("created_at")) for r in json.load(open(path))]
    d = pd.DataFrame(rows, columns=["cve_id", "date"])
    d["date"] = pd.to_datetime(d["date"], utc=True, errors="coerce")
    return d


def metasploit_records(wanted: set) -> pd.DataFrame:
    from src.b import new_data as nd
    t = nd.templates(MSF_REPO, "metasploit")
    pairs = t[t["cve_id"].isin(wanted) & t["at_head"]][["cve_id", "path"]].drop_duplicates().reset_index(drop=True)
    r = nd.reference_added(MSF_REPO, pairs)
    return pd.DataFrame({"cve_id": pairs["cve_id"], "date": pd.to_datetime(r.str.split("|").str[0], utc=True)})


def epss_for(month: str) -> pd.Series:
    """EPSS scores on the last day of the month; if that file is missing, the nearest earlier day, never later."""
    last = pd.Timestamp(f"{month}-01") + pd.offsets.MonthEnd(0)
    for back in range(0, 15):
        day = (last - pd.Timedelta(days=back)).strftime("%Y-%m-%d")
        for d in EPSS_DIRS:
            f = d / f"epss_scores-{day}.csv.gz"
            if f.exists():
                with gzip.open(f, "rt") as fh:
                    fh.readline()
                    return pd.read_csv(fh).set_index("cve")["epss"]
    raise FileNotFoundError(f"no EPSS file for {month}")


def rebuild_signals(pool: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    """One row per pool CVE at its snapshot month, in the layout of data/exploit_signals_Y.csv."""
    wanted = set(pool["cve_id"])
    out = pool[["cve_id", "snapshot_month"]].rename(columns={"snapshot_month": "month"}).reset_index(drop=True).copy()
    e = pd.Series(np.nan, index=out.index, dtype=float)
    for m, g in out.groupby("month"):
        e.loc[g.index] = epss_for(m).reindex(g["cve_id"]).to_numpy()
    out["epss"] = e
    p = pool[["cve_id", "snapshot_month"]]
    out["exploitdb"] = dated_flag(p, exploitdb_records())
    out["metasploit"] = dated_flag(p, metasploit_records(wanted))
    out["nuclei"] = dated_flag(p, nuclei_records())
    out["poc_github"] = dated_flag(p, poc_records(wanted))
    k = kev.assign(date=pd.to_datetime(kev["date_added"], utc=True))[["cve_id", "date"]]
    out["in_kev"] = dated_flag(p, k)
    return out


# ---- fidelity ----------------------------------------------------------------------------------------------------------------------
def fidelity(kev: pd.DataFrame) -> dict:
    pool = pd.read_parquet(OUT_DIR / "replica_2024.parquet")
    rec = rebuild_signals(pool, kev).set_index("cve_id")
    p = pool.set_index("cve_id")
    res = {"pool": len(pool)}
    both = rec["epss"].notna() & p["epss"].notna()
    res["epss_present_in_both"] = int(both.sum())
    res["epss_equal_5dp_share"] = round(float((rec.loc[both, "epss"].round(5) == p.loc[both, "epss"].round(5)).mean()), 4)
    res["epss_spearman"] = round(float(rec.loc[both, "epss"].rank().corr(p.loc[both, "epss"].rank())), 4)
    for f in FLAGS:
        a, b = rec[f].to_numpy() > 0, p[f].to_numpy() > 0
        res[f] = {"datathon": int(b.sum()), "rebuilt": int(a.sum()), "both": int((a & b).sum()), "agreement": round(float((a == b).mean()), 5),
                  "share_of_datathon_found": round(float((a & b).sum() / max(b.sum(), 1)), 3)}
    a, b = rec[FLAGS].max(axis=1).to_numpy() > 0, p[FLAGS].max(axis=1).to_numpy() > 0
    res["any_flag"] = {"datathon": int(b.sum()), "rebuilt": int(a.sum()), "both": int((a & b).sum()), "agreement": round(float((a == b).mean()), 5),
                       "share_of_datathon_found": round(float((a & b).sum() / max(b.sum(), 1)), 3)}
    pos = p["label"].to_numpy() == 1
    res["positives_any_flag"] = {"datathon": int(b[pos].sum()), "rebuilt": int(a[pos].sum()), "of": int(pos.sum())}
    return res


# ---- 2023 features -----------------------------------------------------------------------------------------------------------------
def text_features_2023(pool: pd.DataFrame) -> pd.DataFrame:
    """Same recipe as src.b.text_features for target year 2023, embedding any 2023 description that has no stored vector.
    Runs in its own process (step `text`) and is cached: PyTorch and LightGBM crash when loaded together in one process on this Mac."""
    cache = WORK / "text_2023.parquet"
    if cache.exists():
        out = pd.read_parquet(cache)
        assert set(pool["cve_id"]) <= set(out["cve_id"]), "cached text features do not cover the pool"
        return out.set_index("cve_id").reindex(pool["cve_id"]).reset_index()
    from sklearn.linear_model import LogisticRegression
    from sentence_transformers import SentenceTransformer
    from src.b.embed import MODEL
    from src.b.phrases import POST_ATTACK, strip_post_attack
    from src.b.text_features import FLAGS as TXT
    texts = pd.read_parquet(EMB_DIR / "b_texts.parquet")
    emb = np.load(EMB_DIR / "emb_small.npy")
    ids = pd.read_csv(EMB_DIR / "emb_ids.csv")["cve_id"]
    row = pd.Series(np.arange(len(ids)), index=ids)
    texts = texts.set_index("cve_id").loc[ids].reset_index()
    texts["published"] = pd.to_datetime(texts["published"])
    texts["kev_date_added"] = pd.to_datetime(texts["kev_date_added"])
    v = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "description"]).set_index("cve_id")["description"]
    desc = [strip_post_attack(str(x)) for x in v.reindex(pool["cve_id"]).fillna("")]
    have = pool["cve_id"].isin(row.index).to_numpy()
    X = np.empty((len(pool), emb.shape[1]), dtype="float32")
    X[have] = emb[row.loc[pool["cve_id"][have]].to_numpy()]
    if (~have).any():
        m = SentenceTransformer(MODEL)
        X[~have] = m.encode([d for d, h in zip(desc, have) if not h], batch_size=64, normalize_embeddings=True, show_progress_bar=False).astype("float32")
    targets = set(pool["cve_id"])
    cut_pub, cut_kev = pd.Timestamp("2023-01-01"), pd.Timestamp("2022-12-31")
    tr = texts[(texts["published"] < cut_pub) & ~texts["cve_id"].isin(targets)]
    ytr = (tr["kev_date_added"].notna() & (tr["kev_date_added"] <= cut_kev)).astype(int)
    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000).fit(emb[row.loc[tr["cve_id"]].to_numpy()], ytr)
    k = texts[texts["kev_date_added"].notna() & (texts["kev_date_added"] <= cut_kev) & ~texts["cve_id"].isin(targets)]
    out = pd.DataFrame({"cve_id": pool["cve_id"].to_numpy(), "kev_text_score": clf.predict_proba(X)[:, 1],
                        "nearest_kev_sim": (X @ emb[row.loc[k["cve_id"]].to_numpy()].T).max(axis=1)})
    low = [d.lower() for d in desc]
    for name, pat in TXT.items():
        rx = re.compile(pat, re.I)
        out[name] = np.fromiter((bool(rx.search(d)) for d in low), dtype=bool, count=len(low)).astype("int8")
    assert not any(POST_ATTACK.search(d) for d in low), "post-attack phrases left in the 2023 descriptions"
    print(f"text: trained on {len(tr):,} CVEs before 2023 ({int(ytr.sum())} KEV-positive), nearest-KEV against {len(k):,}; embedded {int((~have).sum()):,} new")
    out.to_parquet(cache, index=False)
    return out


def build_2023(kev_raw: pd.DataFrame):
    import duckdb
    from src.common.schema import SHARE_FEATURES, TEXT_FEATURES, V1_FEATURES
    from src.features import build as fb
    from src.features import drift_fix as dfx
    from src.models.train_v5 import FEATURES_V5
    from src.replicas import build_replica
    WORK.mkdir(parents=True, exist_ok=True)
    v = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published"])
    p = pd.to_datetime(v["published"], errors="coerce")
    base = v[(p >= "2023-01-01") & (p < "2023-10-01")].copy()
    base["snapshot_month"] = pd.to_datetime(base["published"]).dt.strftime("%Y-%m")
    sig = rebuild_signals(base, kev_raw)
    csv = WORK / "exploit_signals_2023.csv"
    sig[["month", "cve_id", "epss", "in_kev", "exploitdb", "metasploit", "nuclei", "poc_github"]].to_csv(csv, index=False)
    con = duckdb.connect()
    pool, stats = build_replica(2023, DATA_DIR / "vulnerabilities.csv", DATA_DIR / "known_exploited.csv", csv, con)
    vuln = con.execute(f"SELECT cve_id, CAST(published AS DATE) AS published, assigner, description FROM read_csv_auto('{DATA_DIR}/vulnerabilities.csv', all_varchar=true)").df()
    kev = con.execute(f"SELECT cve_id, vendor, CAST(date_added AS DATE) AS date_added FROM read_csv_auto('{DATA_DIR}/known_exploited.csv', all_varchar=true)").df()
    feats, _ = fb.build_features(pool, vuln, kev, "2022-12-31")
    feats = feats.reset_index(drop=True)
    text = text_features_2023(pool[["cve_id"]].reset_index(drop=True)).set_index("cve_id").reindex(feats["cve_id"]).reset_index(drop=True)
    x2 = pd.concat([feats[list(V1_FEATURES)], text[list(TEXT_FEATURES)]], axis=1)
    x5 = dfx.to_v5(pd.concat([x2, feats[list(SHARE_FEATURES)]], axis=1))[list(FEATURES_V5)]
    return pool.reset_index(drop=True), feats, x5, stats


# ---- the one run -------------------------------------------------------------------------------------------------------------------
def run(kev_raw: pd.DataFrame) -> dict:
    from joblib import Parallel, delayed
    from src.b import rank as R
    from src.baselines import add_scores, load_cvss
    from src.common import primary
    from src.common.scoring import clustered_paired_bootstrap_hits, k_for_pool, paired_bootstrap_hits, rank_order
    from src.models import train_v1 as v1
    from src.models.train_v4 import bag, kev_events
    from src.models.train_v5 import FEATURES_V5, bootstrap_p
    F5 = list(FEATURES_V5)
    pool, feats, X23, stats = build_2023(kev_raw)
    data, _ctx = R.load()
    Xtr = pd.concat([data[2024]["X5"], data[2025]["X5"]], ignore_index=True)[F5]
    ytr = np.concatenate([data[2024]["y"], data[2025]["y"]])
    months = np.concatenate([data[2024]["groups"], data[2025]["groups"]])
    g_month = np.array([g[-2:] for g in months])
    p6 = json.loads((OUT_DIR / "headline.json").read_text())["final_params"]
    p5 = v1.select_lgbm(Xtr, ytr, g_month, F5, "v5 final (both replicas, month folds)")[0]

    def fit(p, y, seed):
        return primary.lgbm(p, F5, seed).fit(Xtr, y).predict_proba(X23)[:, 1]

    def bag_of(p, y, seeds):
        return bag(Parallel(n_jobs=4)(delayed(fit)(p, y, s) for s in seeds))

    b6, b5 = bag_of(p6, ytr, range(20)), bag_of(p5, ytr, range(20))
    meta = add_scores(feats.merge(load_cvss(DATA_DIR), on="cve_id", how="left")[["cve_id", "snapshot_month", "label", "epss", "exploitdb", "metasploit", "nuclei", "poc_github", "epss_rank_in_month", "cvss3_score"]])
    meta = meta.assign(b6=b6, b5=b5, c3=meta["cvss3_score"].fillna(-1))
    k = k_for_pool(len(meta))
    orders = {"v6": ["b6", "epss_rank_in_month"], "v5": ["b5", "epss_rank_in_month"], "simple rule": ["exploit_epss"], "EPSS alone": ["epss_rank_in_month"], "severity (CVSS)": ["c3"]}
    names = list(orders)
    pos = [v1.rank_pos(meta, c) for c in orders.values()]
    labels = meta["label"].to_numpy()
    n, P = len(meta), int(labels.sum())
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")
    ev = kev_events(meta, kev)
    Bc = paired_bootstrap_hits(labels, pos, k, n=1000, seed=0)
    Be = clustered_paired_bootstrap_hits(labels, ev, pos, k, n=1000, seed=0)
    hits = {nm: int(labels[np.argsort(p, kind="stable")[:k]].sum()) for nm, p in zip(names, pos)}
    rows = []
    for i, nm in enumerate(names):
        h = hits[nm]
        order = np.argsort(pos[i], kind="stable")
        idx = np.flatnonzero(labels[order])
        depth = int(idx[hits["v6"] - 1]) + 1 if hits["v6"] and hits["v6"] <= len(idx) else None
        r = {"method": nm, "hits": h, "k": k, "pool": n, "positives": P, "recall": round(h / P, 4) if P else None, "precision": round(h / k, 4),
             "lift_vs_chance": round((h / k) / (P / n), 1) if P else None, "depth_to_match_v6_hits": depth}
        if i:
            r["v6_minus_this"] = hits["v6"] - h
            for lab, B in (("cve_level_90", Bc), ("event_clustered_90", Be)):
                d = B[:, 0] - B[:, i]
                r[lab] = f"[{np.percentile(d, 5):+.0f}, {np.percentile(d, 95):+.0f}]"
        rows.append(r)
    rows.append({"method": "random (expected)", "hits": round(k * P / n, 2), "k": k, "pool": n, "positives": P, "recall": round(k / n, 4), "precision": round(P / n, 5), "lift_vs_chance": 1.0})
    real, null = [], []
    hit = lambda s: int(labels[np.argsort(v1.rank_pos(meta.assign(z=s), ["z", "epss_rank_in_month"]), kind="stable")[:k]].sum())  # noqa: E731
    for j in range(30):
        real.append(hit(bag_of(p6, ytr, range(100 + 5 * j, 105 + 5 * j))))
        rng = np.random.default_rng(j)
        y = ytr.copy()
        for m in np.unique(months):
            ix = np.where(months == m)[0]
            y[ix] = y[rng.permutation(ix)]
        null.append(hit(bag_of(p6, y, range(1000 + 5 * j, 1005 + 5 * j))))
    d_obs, d_ci, pv = bootstrap_p(real, null)
    return {"rows": rows, "positives": P, "events": int(pd.Series(ev[ev >= 0]).nunique()), "k": k, "pool": n, "stats": stats,
            "placebo": {"real_mean": round(float(np.mean(real)), 2), "real_min_max": [int(min(real)), int(max(real))], "shuffled_mean": round(float(np.mean(null)), 2),
                        "shuffled_min_max": [int(min(null)), int(max(null))], "diff": round(d_obs, 2), "ci90": [round(x, 2) for x in d_ci], "p": p_fmt(pv)},
            "flags_in_pool": {f: int(feats[f].sum()) for f in FLAGS}, "epss_missing": int(feats["epss_missing"].sum())}


def p_fmt(p: float) -> str:
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def main(step: str) -> None:
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "date_added"]).drop_duplicates("cve_id")
    WORK.mkdir(parents=True, exist_ok=True)
    if step == "fidelity":
        res = fidelity(kev)
        (WORK / "fidelity.json").write_text(json.dumps(res, indent=1))
        print(json.dumps(res, indent=1))
    elif step == "text":
        v = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published"])
        p = pd.to_datetime(v["published"], errors="coerce")
        text_features_2023(v[(p >= "2023-01-01") & (p < "2023-10-01")][["cve_id"]].reset_index(drop=True))
    elif step == "run":
        res = run(kev)
        (WORK / "result.json").write_text(json.dumps(res, indent=1, default=str))
        print(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
