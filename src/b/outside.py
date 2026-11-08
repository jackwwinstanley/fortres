"""Outside data test (Jack's request, 2026-11-07): does VulnCheck KEV add anything to the frozen v5 model?

Run (token only from the environment; never printed, logged or written by this script):
    set -a; . ./.env; set +a          # loads VULNCHECK_API_TOKEN from the gitignored .env, silently
    python -m src.b.outside download  # -> data/outside/vulncheck_kev.json (gitignored)
    python -m src.b.outside all       # fields, feature, leak checks, evaluation -> outputs/outside_eval.csv, outputs/outside_report.md

Feature: vc_exploited_by_snapshot = 1 if VulnCheck's own `date_added` <= last day of the CVE's snapshot_month (same snapshot
logic as the replicas), minus "mirrored" entries whose VulnCheck date is on/after the CISA KEV date. Evaluated once each, no
tuning: v5 frozen, (A) two-tier (flagged first in v5 order, then v5 order), (B) v5 retrained with the flag as one extra feature
using v5's own selected parameters and seeds. Local outputs only; nothing here is committed.
"""
import argparse
import io
import json
import os
import sys
import zipfile

import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR

API = "https://api.vulncheck.com/v3"
INDEX = "vulncheck-kev"
RAW = DATA_DIR / "outside" / "vulncheck_kev.json"
POOLS = {2024: "replica_2024.parquet", 2025: "replica_2025.parquet", 2026: "scoreboard_features.parquet"}


# ---- 1. download ------------------------------------------------------------------------------------------------
def _session():
    import requests
    tok = os.environ.get("VULNCHECK_API_TOKEN")
    if not tok:
        sys.exit("VULNCHECK_API_TOKEN is not set in the environment")
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {tok}", "Accept": "application/json"})
    return s


def download():
    s = _session()
    RAW.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    # preferred: the backup (one zip with the whole index); fall back to cursor pagination
    r = s.get(f"{API}/backup/{INDEX}", timeout=60)
    if r.status_code == 200 and r.json().get("data"):
        link = r.json()["data"][0]["url"]                        # signed link: used, never printed
        z = zipfile.ZipFile(io.BytesIO(s.get(link, timeout=300, headers={"Authorization": None}).content))
        for name in z.namelist():
            if name.endswith(".json"):
                part = json.loads(z.read(name))
                rows += part if isinstance(part, list) else part.get("data", [])
        how = "backup"
    else:
        print(f"backup endpoint: HTTP {r.status_code}; using pagination")
        cursor, page = None, 0
        while True:
            params = {"limit": 2000, **({"next_cursor": cursor} if cursor else {"start_cursor": "true"})}
            r = s.get(f"{API}/index/{INDEX}", params=params, timeout=120)
            if r.status_code != 200:
                sys.exit(f"VulnCheck index request failed: HTTP {r.status_code}")
            j = r.json()
            rows += j.get("data", [])
            cursor = (j.get("_meta") or {}).get("next_cursor")
            page += 1
            if not cursor or not j.get("data"):
                break
        how = f"pagination ({page} pages)"
    RAW.write_text(json.dumps(rows))
    print(f"downloaded {len(rows):,} VulnCheck KEV entries via {how} -> {RAW.relative_to(DATA_DIR.parent)} "
          f"({RAW.stat().st_size / 1e6:.1f} MB)")


# ---- 2. inspect + feature ---------------------------------------------------------------------------------------
def load_vc() -> pd.DataFrame:
    rows = json.loads(RAW.read_text())
    recs = []
    for e in rows:
        cves = e.get("cve") or []
        cves = [cves] if isinstance(cves, str) else cves
        for c in cves:
            recs.append({"cve_id": c, "vc_date_added": e.get("date_added"), "vc_cisa_date_added": e.get("cisa_date_added"),
                         "vc_reported": len(e.get("vulncheck_reported_exploitation") or []),
                         "vc_timestamp": e.get("_timestamp")})
    d = pd.DataFrame(recs)
    for c in ("vc_date_added", "vc_cisa_date_added", "vc_timestamp"):
        d[c] = pd.to_datetime(d[c], errors="coerce", utc=True).dt.tz_localize(None)
    # one row per CVE: the earliest VulnCheck date_added
    return d.sort_values("vc_date_added").drop_duplicates("cve_id").reset_index(drop=True)


def fields_report() -> list[str]:
    rows = json.loads(RAW.read_text())
    keys = {}
    for e in rows[:5000]:
        for k, v in e.items():
            keys.setdefault(k, type(v).__name__)
    ex = rows[0] if rows else {}
    lines = [f"{len(rows):,} entries. Fields: " + ", ".join(f"`{k}` ({t})" for k, t in sorted(keys.items()))]
    lines.append("Date fields in one entry: " + ", ".join(f"`{k}`={v}" for k, v in ex.items() if "date" in k.lower() or k == "_timestamp"))
    return lines


def pools_with_flag(vc: pd.DataFrame, kev: pd.DataFrame) -> dict:
    out = {}
    for y, f in POOLS.items():
        p = pd.read_parquet(OUT_DIR / f)
        eom = (pd.to_datetime(p["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0))
        d = p.assign(eom=eom).merge(vc, on="cve_id", how="left").merge(kev, on="cve_id", how="left")
        raw_flag = d["vc_date_added"].notna() & (d["vc_date_added"] <= d["eom"])
        # mirrored: VulnCheck's date on/after CISA's date (it copied CISA) -> not an early signal
        mirrored = raw_flag & d["cisa_date"].notna() & (d["vc_date_added"] >= d["cisa_date"])
        d["vc_raw_flag"] = raw_flag.astype(int)
        d["vc_mirrored"] = mirrored.astype(int)
        d["vc_exploited_by_snapshot"] = (raw_flag & ~mirrored).astype("int8")
        out[y] = d
    return out


# ---- 3. leak checks ---------------------------------------------------------------------------------------------
def leak_checks(P: dict, vc: pd.DataFrame, vuln_pub: pd.Series) -> dict:
    res = {}
    rep = pd.concat([P[2024], P[2025]], ignore_index=True)
    pos = rep[rep["label"] == 1]
    res["positives"] = int(len(pos))
    res["positives_raw_flag"] = int(pos["vc_raw_flag"].sum())
    res["positives_flagged"] = int(pos["vc_exploited_by_snapshot"].sum())
    res["negatives_flagged"] = int(rep.loc[rep["label"] == 0, "vc_exploited_by_snapshot"].sum())
    fk = rep[(rep["vc_raw_flag"] == 1) & rep["cisa_date"].notna()]
    delta = (fk["vc_date_added"] - fk["cisa_date"]).dt.days
    res["flagged_in_cisa"] = int(len(fk))
    res["vc_minus_cisa_days"] = {q: (float(delta.quantile(q)) if len(delta) else None) for q in (0.0, 0.25, 0.5, 0.75, 1.0)}
    res["mirrored_excluded"] = int(rep["vc_mirrored"].sum())
    # backfilling signs over the whole VulnCheck index
    v = vc.dropna(subset=["vc_date_added"]).copy()
    v["published"] = v["cve_id"].map(vuln_pub)
    res["vc_entries"] = int(len(v))
    res["vc_min_date"] = str(v["vc_date_added"].min().date()) if len(v) else None
    top = v["vc_date_added"].dt.date.value_counts().head(5)
    res["top_dates"] = {str(k): int(n) for k, n in top.items()}
    res["share_on_top_date"] = round(float(top.iloc[0] / len(v)), 3) if len(v) else None
    res["date_before_published"] = int((v["published"].notna() & (v["vc_date_added"] < v["published"])).sum())
    res["date_before_2023"] = int((v["vc_date_added"] < "2023-01-01").sum())
    return res


# ---- 4. evaluation ----------------------------------------------------------------------------------------------
def evaluate(P: dict) -> pd.DataFrame:
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
        flag = P[y].set_index("cve_id")["vc_exploited_by_snapshot"].reindex(f["cve_id"]).fillna(0).astype(int).to_numpy()
        x5["vc_exploited_by_snapshot"] = flag
        data[y]["XO"] = x5
    FB = FEATURES_V5 + ["vc_exploited_by_snapshot"]

    def positions(c, score):
        order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
        pos = np.empty(len(order), dtype=np.int64)
        pos[order] = np.arange(len(order))
        return pos

    rows, draws = [], {"A": 0, "B": 0}
    for j, (tr, te) in enumerate(st.DIRS):
        c = ctx[(tr, te)]
        p5 = v1.select_lgbm(c["tr"]["XO"][FEATURES_V5], c["tr"]["y"], c["tr"]["groups"], FEATURES_V5, f"v5 train {tr}")[0]
        fit = lambda feats: bag([v1.lgbm_model(p5, feats, seed=s).fit(c["tr"]["XO"][feats], c["tr"]["y"])
                                 .predict_proba(c["te"]["XO"][feats])[:, 1] for s in range(20)])
        s5 = fit(FEATURES_V5)
        flag = c["te"]["XO"]["vc_exploited_by_snapshot"].to_numpy()
        sA = flag + pd.Series(s5).rank(pct=True).to_numpy() * 0.999      # flagged first (in v5 order), then v5 order
        sB = fit(FB)                                                     # same v5 parameters and seeds, one extra column
        B = paired_bootstrap_hits(c["label"], [positions(c, s5), positions(c, sA), positions(c, sB)], c["k"], n=1000, seed=j)
        draws["A"] = draws["A"] + (B[:, 1] - B[:, 0])
        draws["B"] = draws["B"] + (B[:, 2] - B[:, 0])
        label = "forward (train 2024 -> test 2025)" if te == 2025 else "stability (train 2025 -> test 2024)"
        for name, s, col in (("v5 frozen", s5, None), ("A two-tier", sA, 1), ("B v5 + flag feature", sB, 2)):
            d = None if col is None else B[:, col] - B[:, 0]
            rows.append({"test": label, "variant": name, "k": c["k"], "hits": st.hits_of(c, s),
                         "flagged_in_pool": int(flag.sum()),
                         "diff_vs_v5_90": None if d is None else f"[{np.percentile(d, 5):+.0f}, {np.percentile(d, 95):+.0f}]"})
    df = pd.DataFrame(rows)
    for name, key in (("v5 frozen", None), ("A two-tier", "A"), ("B v5 + flag feature", "B")):
        h = int(df.loc[df["variant"] == name, "hits"].sum())
        rng = None if key is None else f"[{np.percentile(draws[key], 5):+.0f}, {np.percentile(draws[key], 95):+.0f}]"
        df.loc[len(df)] = {"test": "pooled", "variant": name, "k": None, "hits": h, "flagged_in_pool": None, "diff_vs_v5_90": rng}
    return df


def main(step):
    if step in ("download",):
        download()
        return
    vc = load_vc()
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "date_added"]).drop_duplicates("cve_id")
    kev = kev.rename(columns={"date_added": "cisa_date"}).assign(cisa_date=lambda d: pd.to_datetime(d["cisa_date"]))
    vuln = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published"])
    pub = pd.to_datetime(vuln.set_index("cve_id")["published"], errors="coerce")
    P = pools_with_flag(vc, kev)
    lines = ["# Outside data: VulnCheck KEV (local report, not committed)", "", "## Fields", *fields_report(), "",
             "## Coverage of vc_exploited_by_snapshot (after removing mirrored entries)"]
    for y, d in P.items():
        lines.append(f"- {y}: {int(d['vc_exploited_by_snapshot'].sum()):,} of {len(d):,} CVEs "
                     f"({d['vc_exploited_by_snapshot'].mean():.2%}); raw before mirror removal {int(d['vc_raw_flag'].sum()):,}")
    L = leak_checks(P, vc, pub)
    lines += ["", "## Leak checks", "```", json.dumps(L, indent=1, default=str), "```"]
    print("\n".join(lines))
    if L["positives"] and L["positives_flagged"] >= 0.8 * L["positives"]:
        lines += ["", f"**STOP: the flag catches {L['positives_flagged']} of {L['positives']} positives: likely leakage. No evaluation run.**"]
        (OUT_DIR / "outside_report.md").write_text("\n".join(lines))
        print(lines[-1])
        return
    if step == "all":
        df = evaluate(P)
        df.to_csv(OUT_DIR / "outside_eval.csv", index=False)
        lines += ["", "## Evaluation (once each, no tuning)", "", df.to_markdown(index=False)]
        print(df.to_string(index=False))
    (OUT_DIR / "outside_report.md").write_text("\n".join(lines))





# ================================================================================================================
# Part 2 (Jack's expanded spec): CISA Vulnrichment + combined feature `outside_exploited`
# ================================================================================================================
VR_DIR = DATA_DIR / "outside" / "vulnrichment"


def load_vulnrichment(wanted: set) -> pd.DataFrame:
    """CISA ADP SSVC 'Exploitation' value and its timestamp for the wanted CVE ids (shallow clone = latest value only)."""
    recs = []
    for cve in wanted:
        y, n = cve.split("-")[1], cve.split("-")[2]
        p = VR_DIR / y / f"{n[:-3]}xxx" / f"{cve}.json"
        if not p.exists():
            continue
        d = json.loads(p.read_text())
        for a in d.get("containers", {}).get("adp", []):
            if a.get("providerMetadata", {}).get("shortName") != "CISA-ADP":
                continue
            for m in a.get("metrics", []):
                o = m.get("other", {})
                if o.get("type") == "ssvc":
                    c = o.get("content", {})
                    expl = next((opt["Exploitation"] for opt in c.get("options", []) if "Exploitation" in opt), None)
                    recs.append({"cve_id": cve, "ssvc_exploitation": expl, "ssvc_timestamp": c.get("timestamp")})
    d = pd.DataFrame(recs, columns=["cve_id", "ssvc_exploitation", "ssvc_timestamp"])
    d["ssvc_timestamp"] = pd.to_datetime(d["ssvc_timestamp"], errors="coerce", utc=True).dt.tz_localize(None)
    return d.drop_duplicates("cve_id")


def part2():
    from src.common.paths import OUT_DIR as O
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "date_added"]).drop_duplicates("cve_id")
    kev = kev.rename(columns={"date_added": "cisa_date"}).assign(cisa_date=lambda d: pd.to_datetime(d["cisa_date"]))
    vuln = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published"])
    pub = pd.to_datetime(vuln.set_index("cve_id")["published"], errors="coerce")
    vc = load_vc()
    P = pools_with_flag(vc, kev)                                     # VulnCheck flag (for the leak table only)
    wanted = set(pd.concat([P[y]["cve_id"] for y in P]))
    vr = load_vulnrichment(wanted)
    rows = []
    for y, d in P.items():
        d = d.merge(vr, on="cve_id", how="left")
        active = d["ssvc_exploitation"].eq("active")
        dated_ok = d["ssvc_timestamp"].notna() & (d["ssvc_timestamp"] <= d["eom"])
        vr_raw = active & dated_ok
        vr_mirror = vr_raw & d["cisa_date"].notna() & (d["ssvc_timestamp"] >= d["cisa_date"])
        d["vr_raw_flag"] = vr_raw.astype(int)
        d["vr_mirrored"] = vr_mirror.astype(int)
        d["vr_flag"] = (vr_raw & ~vr_mirror).astype(int)
        d["vr_has_ssvc"] = d["ssvc_exploitation"].notna().astype(int)
        d["vr_ssvc_dated_by_snapshot"] = (d["ssvc_exploitation"].notna() & dated_ok).astype(int)
        # VulnCheck fails the date rule (date_added = earliest evidence date, no listing date): contribution = unknown
        d["outside_exploited"] = d["vr_flag"].astype("int8")
        P[y] = d
    # ---- leak table, per source
    rep = pd.concat([P[2024], P[2025]], ignore_index=True)
    pos = rep["label"] == 1
    for src, raw, flag, mirror, date_col in (("VulnCheck KEV", "vc_raw_flag", "vc_exploited_by_snapshot", "vc_mirrored", "vc_date_added"),
                                             ("CISA Vulnrichment SSVC active", "vr_raw_flag", "vr_flag", "vr_mirrored", "ssvc_timestamp")):
        inkev = rep[(rep[raw] == 1) & rep["cisa_date"].notna()]
        delta = (inkev[date_col] - inkev["cisa_date"]).dt.days
        r = {"source": src,
             "date_rule": ("FAILS: date_added = earliest exploitation-report date (100% of entries), no listing date; contribution set to unknown"
                           if src.startswith("VulnCheck") else "passes: SSVC decision timestamp, counted only if <= snapshot end"),
             "positives_flagged_raw": int(rep.loc[pos, raw].sum()), "positives_flagged_after_mirror": int(rep.loc[pos, flag].sum()),
             "positives_total": int(pos.sum()), "negatives_flagged": int(rep.loc[~pos, flag].sum()),
             "flagged_in_cisa_kev": int(len(inkev)), "mirrored_excluded": int(rep[mirror].sum()),
             "source_minus_kev_days_p0_p50_p100": "" if not len(delta) else f"{delta.min():.0f} / {delta.median():.0f} / {delta.max():.0f}"}
        for y in (2024, 2025, 2026):
            r[f"coverage_{y}"] = f"{int(P[y][flag].sum())} of {len(P[y]):,} ({P[y][flag].mean():.2%})"
        rows.append(r)
    # backfill signs for Vulnrichment
    v = vr.dropna(subset=["ssvc_timestamp"]).copy()
    v["published"] = v["cve_id"].map(pub)
    top = v["ssvc_timestamp"].dt.date.value_counts()
    rows[1]["backfill_signs"] = (f"SSVC timestamp before CVE publication: {int((v['published'].notna() & (v['ssvc_timestamp'] < v['published'])).sum())}; "
                                 f"earliest timestamp {v['ssvc_timestamp'].min().date()}; largest single-day share {top.iloc[0] / len(v):.1%} ({top.index[0]})")
    rows[0]["backfill_signs"] = "1,134 entries dated before CVE publication; 2,103 before 2023; 108 on 2026-10-13"
    rows[1]["ssvc_present_in_pools"] = {y: f"{int(P[y]['vr_has_ssvc'].sum())} with SSVC, {int(P[y]['vr_ssvc_dated_by_snapshot'].sum())} dated by snapshot" for y in P}
    lt = pd.DataFrame(rows)
    lt.to_csv(O / "outside_leakcheck.csv", index=False)
    print(lt.T.to_string())
    stop = rows[1]["positives_flagged_after_mirror"] >= 0.8 * rows[1]["positives_total"]
    return P, stop


def eval_outside(P):
    """Same as evaluate(), on outside_exploited (Vulnrichment-only, VulnCheck unknown)."""
    for y in P:
        P[y]["vc_exploited_by_snapshot"] = P[y]["outside_exploited"]   # evaluate() reads this column name
    return evaluate(P)


def run_part2(evaluate_too: bool):
    P, stop = part2()
    if stop:
        print("STOP: outside_exploited flags close to all replica positives: likely leakage. No evaluation run.")
        return
    if evaluate_too:
        df = eval_outside(P)
        df.to_csv(OUT_DIR / "outside_eval.csv", index=False)
        print(df.to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["download", "check", "all", "part2-check", "part2-eval"])
    a = ap.parse_args()
    if a.step.startswith("part2"):
        run_part2(a.step == "part2-eval")
    else:
        main(a.step)
