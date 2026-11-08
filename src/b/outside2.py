"""Outside data, round 2 (Jack, 2026-11-08): GitHub PoC repo creation dates + EPSS daily archive.  Run:  python -m src.b.outside2

Data (gitignored, never committed): data/outside/poc-in-github/ (shallow clone of nomi-sec/PoC-in-GitHub, CC0-1.0) and
data/outside/epss/ (first and last day of every snapshot month from https://epss.empiricalsecurity.com, 52 files).

Rules fixed before any result:
- Date rule: a record counts only if dated on or before the end of the CVE's snapshot_month (23:59:59 UTC).
- PoC: ONLY created_at (never stars, forks, pushed_at or updated_at). poc_repo_count_by_snapshot = repos created by the
  snapshot end; days_from_first_poc_to_snapshot = days from the first such repo to the snapshot end, -1 if none (v5 has no
  NaN cells, so a sentinel is used instead of NaN). "Flagged" = at least one repo.
- EPSS: N = 30 days or the whole month if shorter = first day -> last day of the snapshot month. Feature
  epss_pct_change_month = EPSS percentile (a rank over all CVEs, as published that day) on the last day minus on the first
  day; 0 if the CVE is not in the first-day file (not scored yet). "Flagged" = a rise of at least 0.20.
- A source that flags nothing on the 2026 scoreboard is rejected. Leak check stop: a source flagging >= 80% of the 75
  replica positives is not evaluated.
- ONE combined candidate: v5 features + the passing features, v5's own selected parameters, seeds 0-19 bag, once.
  Adoption: forward >= v5, stability >= v5, pooled gain >= 2 and >= 4 (the b/rank noise-floor spread).
"""
import glob
import gzip
import json
import os

import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR

POC_DIR = DATA_DIR / "outside" / "poc-in-github"
EPSS_DIR = DATA_DIR / "outside" / "epss"
POOLS = {2024: "replica_2024.parquet", 2025: "replica_2025.parquet", 2026: "scoreboard_features.parquet"}
NOISE_FLOOR = 4
EPSS_FLAG = 0.20
RUNS = []


def run(name, status, **kw):
    RUNS.append({"run": name, "status": status, **kw})
    print("RUN", name, status, kw, flush=True)


def snap_end(months):
    return pd.to_datetime(pd.Series(months).astype(str) + "-01", utc=True) + pd.offsets.MonthEnd(0) + pd.Timedelta(hours=23, minutes=59, seconds=59)


def pools():
    P = {}
    for y, f in POOLS.items():
        d = pd.read_parquet(OUT_DIR / f)
        cols = ["cve_id", "snapshot_month"] + (["label"] if "label" in d.columns else [])
        d = d[cols].copy()
        assert d["cve_id"].is_unique, y
        d["end"] = snap_end(d["snapshot_month"]).to_numpy()
        P[y] = d.reset_index(drop=True)
    return P


def load_poc(wanted):
    rows = []
    for path in glob.glob(str(POC_DIR / "*" / "CVE-*.json")):
        cve = os.path.basename(path)[:-5]
        if cve not in wanted:
            continue
        for r in json.load(open(path)):
            rows.append((cve, r.get("created_at"), r.get("html_url")))
    df = pd.DataFrame(rows, columns=["cve_id", "created_at", "url"])
    df["created_at"] = pd.to_datetime(df["created_at"], utc=True, errors="coerce")
    return df


def poc_features(P, poc):
    for y, d in P.items():
        m = poc.merge(d[["cve_id", "end"]], on="cve_id")
        m = m[m["created_at"] <= m["end"]]                       # date rule: created by the snapshot end
        g = m.groupby("cve_id").agg(n=("created_at", "size"), first=("created_at", "min"))
        d["poc_repo_count_by_snapshot"] = g["n"].reindex(d["cve_id"]).fillna(0).astype(int).to_numpy()
        first = g["first"].reindex(d["cve_id"])
        d["days_from_first_poc_to_snapshot"] = ((d["end"].to_numpy() - first.to_numpy()) / pd.Timedelta(days=1))
        d["days_from_first_poc_to_snapshot"] = d["days_from_first_poc_to_snapshot"].fillna(-1).astype(float)
        d["poc_first"] = first.to_numpy()
        d["poc_any_dated_later"] = poc.groupby("cve_id").size().reindex(d["cve_id"]).fillna(0).to_numpy() > d["poc_repo_count_by_snapshot"]


def read_epss(day):
    p = EPSS_DIR / f"epss_scores-{day}.csv.gz"
    with gzip.open(p, "rt") as fh:
        head = fh.readline().strip()
        df = pd.read_csv(fh)
    return head, df.set_index("cve")


def epss_features(P):
    meta = []
    for y, d in P.items():
        ch = pd.Series(np.nan, index=d["cve_id"])
        endpct = pd.Series(np.nan, index=d["cve_id"])
        for mth, sub in d.groupby("snapshot_month"):
            first = f"{mth}-01"
            last = (pd.Timestamp(first) + pd.offsets.MonthEnd(0)).strftime("%Y-%m-%d")
            try:
                h0, e0 = read_epss(first)
                h1, e1 = read_epss(last)
            except Exception as e:
                run(f"EPSS read {mth}", "failed", notes=f"{type(e).__name__}: {e}")
                continue
            meta.append({"month": mth, "first_file": h0, "last_file": h1})
            ids = sub["cve_id"]
            p1 = e1["percentile"].reindex(ids)
            p0 = e0["percentile"].reindex(ids).fillna(0)          # not scored yet on day 1 -> 0
            ch.loc[ids] = (p1.fillna(0) - p0).to_numpy()
            endpct.loc[ids] = p1.to_numpy()
        d["epss_pct_change_month"] = ch.fillna(0).to_numpy()
        d["epss_end_pct_archive"] = endpct.to_numpy()
    return meta


def leak_checks(P, kev, pub, name, flag_col, date_col=None):
    rows = []
    allpos = pd.concat([P[2024], P[2025]])
    allpos = allpos[allpos["label"] == 1]
    out = {"source": name, "positives": len(allpos), "positives_flagged": int(allpos[flag_col].sum()),
           "positives_flagged_share": round(float(allpos[flag_col].mean()), 3)}
    for y in (2024, 2025):
        d = P[y]
        out[f"negatives_flagged_{y}"] = int(d.loc[d["label"] == 0, flag_col].sum())
    for y, d in P.items():
        out[f"coverage_{y}"] = int(d[flag_col].sum())
        out[f"coverage_share_{y}"] = round(float(d[flag_col].mean()), 4)
    if date_col:
        m = pd.concat(P.values())
        m = m[m[flag_col]].merge(kev, on="cve_id")
        dd = (m[date_col] - m["cisa_date"]).dt.days
        out.update(in_kev_and_flagged=len(m), source_minus_kev_days_min=dd.min(), source_minus_kev_days_median=dd.median(),
                   source_minus_kev_days_max=dd.max(), mirrored_source_ge_kev=int((dd >= 0).sum()))
        allp = pd.concat(P.values())
        allp = allp[allp[flag_col]]
        pubd = pub.reindex(allp["cve_id"]).to_numpy()
        out["first_record_before_cve_publication"] = int((allp[date_col].to_numpy() < pubd).sum())
    return out


def evaluate(P, add):
    from src.common.schema import SHARE_FEATURES
    from src.common.scoring import paired_bootstrap_hits
    from src.features import drift_fix as dfx
    from src.models import stress_v2 as st
    from src.models import train_v1 as v1
    from src.models.train_v4 import bag
    from src.models.train_v5 import FEATURES_V5
    data, sb, sb2, ctx = st.prepare(OUT_DIR, DATA_DIR)
    for y in (2024, 2025):
        f = pd.read_parquet(OUT_DIR / f"features_replica_{y}.parquet").reset_index(drop=True)
        x5 = dfx.to_v5(pd.concat([data[y]["X2"], f[SHARE_FEATURES]], axis=1)).reset_index(drop=True)
        extra = P[y].set_index("cve_id").reindex(f["cve_id"])
        assert extra[add].notna().all().all()
        for a in add:
            x5[a] = extra[a].to_numpy()
        data[y]["XO"] = x5
    FB = list(FEATURES_V5) + list(add)

    def positions(c, score):
        order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
        pos = np.empty(len(order), dtype=np.int64)
        pos[order] = np.arange(len(order))
        return pos

    rows, draws = [], 0
    for j, (tr, te) in enumerate(st.DIRS):
        c = ctx[(tr, te)]
        p5 = v1.select_lgbm(c["tr"]["XO"][FEATURES_V5], c["tr"]["y"], c["tr"]["groups"], FEATURES_V5, f"v5 train {tr}")[0]
        fit = lambda feats: bag([v1.lgbm_model(p5, feats, seed=s).fit(c["tr"]["XO"][feats], c["tr"]["y"])  # noqa: E731
                                 .predict_proba(c["te"]["XO"][feats])[:, 1] for s in range(20)])
        s5, sC = fit(list(FEATURES_V5)), fit(FB)
        B = paired_bootstrap_hits(c["label"], [positions(c, s5), positions(c, sC)], c["k"], n=1000, seed=j)
        d = B[:, 1] - B[:, 0]
        draws = draws + d
        label = "forward (train 2024 -> test 2025)" if te == 2025 else "stability (train 2025 -> test 2024)"
        h5, hC = st.hits_of(c, s5), st.hits_of(c, sC)
        rows += [{"test": label, "variant": "v5 frozen", "k": c["k"], "hits": h5, "diff_vs_v5": None, "diff_vs_v5_90": None},
                 {"test": label, "variant": "v5 + " + " + ".join(add), "k": c["k"], "hits": hC, "diff_vs_v5": hC - h5,
                  "diff_vs_v5_90": f"[{np.percentile(d, 5):+.0f}, {np.percentile(d, 95):+.0f}]"}]
        run(f"candidate {label}", "ok", v5=h5, candidate=hC, params=json.dumps(p5))
    df = pd.DataFrame(rows)
    for v in df["variant"].unique():
        h = int(df.loc[df["variant"] == v, "hits"].sum())
        rng = None if v == "v5 frozen" else f"[{np.percentile(draws, 5):+.0f}, {np.percentile(draws, 95):+.0f}]"
        df.loc[len(df)] = {"test": "pooled", "variant": v, "k": None, "hits": h, "diff_vs_v5": None if v == "v5 frozen" else h - int(df.loc[(df["variant"] == "v5 frozen") & (df["test"] != "pooled"), "hits"].sum()),
                           "diff_vs_v5_90": rng}
    return df


def main():
    P = pools()
    wanted = set(pd.concat([d["cve_id"] for d in P.values()]))
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "date_added"]).drop_duplicates("cve_id")
    kev = kev.rename(columns={"date_added": "cisa_date"}).assign(cisa_date=lambda d: pd.to_datetime(d["cisa_date"], utc=True))
    vuln = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published"])
    pub = pd.to_datetime(vuln.set_index("cve_id")["published"], errors="coerce", utc=True)

    poc = load_poc(wanted)
    run("PoC load", "ok", repos=len(poc), cves=poc["cve_id"].nunique(), missing_created_at=int(poc["created_at"].isna().sum()))
    poc_features(P, poc)
    meta = epss_features(P)
    for d in P.values():
        d["poc_flag"] = d["poc_repo_count_by_snapshot"] > 0
        d["epss_flag"] = d["epss_pct_change_month"] >= EPSS_FLAG
        d["epss_date"] = d["end"]  # the last-day file is dated the snapshot end by construction

    L = [leak_checks(P, kev, pub, "GitHub PoC (created_at)", "poc_flag", "poc_first"),
         leak_checks(P, kev, pub, "EPSS daily archive (percentile change over the month)", "epss_flag", "epss_date")]
    # extra PoC facts: overlap with v5's poc_github flag, repos dated after the snapshot (excluded by the date rule)
    ov = []
    for y in (2024, 2025, 2026):
        src = pd.read_parquet(OUT_DIR / POOLS[y])[["cve_id", "poc_github"]].set_index("cve_id").reindex(P[y]["cve_id"])
        a, b = P[y]["poc_flag"].to_numpy(), src["poc_github"].fillna(0).to_numpy() > 0
        ov.append({"pool": y, "poc_flag": int(a.sum()), "v5_poc_github": int(b.sum()), "both": int((a & b).sum()),
                   "share_of_poc_flag_also_v5": round(float((a & b).sum() / max(a.sum(), 1)), 3),
                   "corr_count_vs_v5_flag": round(float(np.corrcoef(P[y]["poc_repo_count_by_snapshot"], b)[0, 1]), 3),
                   "cves_with_repos_only_after_snapshot": int((P[y]["poc_any_dated_later"] & ~a).sum())})
    L[0]["overlap_with_v5_poc_github"] = json.dumps(ov)
    # EPSS archive vs the datathon's own epss column: which day does the datathon use?
    chk = []
    for y in (2024, 2025, 2026):
        src = pd.read_parquet(OUT_DIR / POOLS[y])[["cve_id", "epss"]].set_index("cve_id")["epss"].reindex(P[y]["cve_id"])
        for mth in sorted(P[y]["snapshot_month"].unique())[:1]:
            ids = P[y].loc[P[y]["snapshot_month"] == mth, "cve_id"]
            for day in (f"{mth}-01", (pd.Timestamp(f"{mth}-01") + pd.offsets.MonthEnd(0)).strftime("%Y-%m-%d")):
                e = read_epss(day)[1]["epss"].reindex(ids)
                chk.append({"month": mth, "file": day, "share_equal_to_datathon_epss": round(float((e.round(5) == src.loc[ids].round(5)).mean()), 3)})
    L[1]["datathon_epss_matches_archive"] = json.dumps(chk)
    L[1]["files"] = json.dumps(meta[:2] + meta[-2:])
    lk = pd.DataFrame(L)
    lk.to_csv(OUT_DIR / "outside2_leakcheck.csv", index=False)
    print(lk.T.to_string())

    add = []
    for name, cols, row in (("PoC", ["poc_repo_count_by_snapshot", "days_from_first_poc_to_snapshot"], L[0]),
                            ("EPSS", ["epss_pct_change_month"], L[1])):
        if row["coverage_2026"] == 0:
            run(f"{name} gate", "rejected", notes="flags nothing on the 2026 scoreboard")
        elif row["positives_flagged_share"] >= 0.8:
            run(f"{name} gate", "rejected", notes="flags >= 80% of positives: likely leakage")
        else:
            run(f"{name} gate", "passed", coverage_2026=row["coverage_2026"], positives_flagged=row["positives_flagged"])
            add += cols
    if not add:
        run("candidate", "not run", notes="no source passed")
        df = pd.DataFrame()
    else:
        try:
            df = evaluate(P, add)
        except Exception as e:
            run("candidate", "failed", notes=f"{type(e).__name__}: {e}")
            raise
    v5 = df[df["variant"] == "v5 frozen"].set_index("test")["hits"]
    cand = df[df["variant"] != "v5 frozen"].set_index("test")["hits"]
    f, s, p = (k for k in ("forward (train 2024 -> test 2025)", "stability (train 2025 -> test 2024)", "pooled"))
    gain = cand[p] - v5[p]
    ok = bool(cand[f] >= v5[f] and cand[s] >= v5[s] and gain >= 2 and gain >= NOISE_FLOOR)
    run("adoption check", "adopt" if ok else "v5 stays", forward=f"{cand[f]} vs {v5[f]}", stability=f"{cand[s]} vs {v5[s]}", pooled_gain=int(gain), noise_floor=NOISE_FLOOR)
    runs = pd.DataFrame(RUNS).assign(test="run log", variant=lambda r: r["run"])
    pd.concat([df, runs.drop(columns=["run"])], ignore_index=True).to_csv(OUT_DIR / "outside2_eval.csv", index=False)
    print(df.to_string())


if __name__ == "__main__":
    main()
