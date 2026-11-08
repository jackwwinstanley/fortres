"""Person B: export the small aggregated JSON the scroll story (site/) reads.

Run:  python -m src.b.export_story     -> site/data/story.json

Aggregates and public identifiers only (counts, medians, CVE ids, our own reasons); no raw dataset rows.
Every number on the site comes from this file, which comes from the real outputs.
"""
import json
import re

import numpy as np
import pandas as pd

from src.b import runlog
from src.b.charts import blind_spot_counts, diff90, mechanism_file
from src.b.explain import cna_name, nearest_kev
from src.b.text_features import FLAGS
from src.common.paths import DATA_DIR, OUT_DIR, REPO_ROOT

SITE_DATA = REPO_ROOT / "site" / "data"
EXAMPLE = "CVE-2025-24472"  # a 2025 blind spot (no exploit code, low EPSS) that the v4 model caught
CNA_NAMES = {"security-advisories@github.com": "GitHub", "cna@vuldb.com": "VulDB", "audit@patchstack.com": "Patchstack",
             "cve@mitre.org": "MITRE", "security@wordfence.com": "Wordfence", "disclosure@vulncheck.com": "VulnCheck",
             "secure@microsoft.com": "Microsoft", "secalert_us@oracle.com": "Oracle",
             "chrome-cve-admin@google.com": "Google Chrome", "contact@wpscan.com": "WPScan",
             "psirt@us.ibm.com": "IBM", "psirt@adobe.com": "Adobe", "product-security@apple.com": "Apple"}
TAG = {"txt_rce": "Remote code execution", "txt_unauth": "No login needed", "txt_auth_bypass": "Login bypass",
       "txt_cmd_injection": "Command injection", "txt_deserialization": "Unsafe deserialization",
       "txt_path_traversal": "Path traversal", "txt_sqli": "SQL injection", "txt_priv_esc": "Privilege escalation",
       "txt_memory": "Memory corruption", "txt_edge_device": "VPN / firewall / edge", "txt_enterprise": "Enterprise software",
       "txt_browser": "Web browser", "txt_wordpress": "WordPress plugin", "txt_xss": "Cross-site scripting"}
# plain-English flaw families for the "our 500" poster: first match wins (txt_* flags from the description)
KINDS = [("Takes over the machine", ["txt_rce", "txt_cmd_injection", "txt_deserialization"]),
         ("No login needed", ["txt_unauth", "txt_auth_bypass"]),
         ("Gets admin powers", ["txt_priv_esc"]),
         ("Reads files it shouldn't", ["txt_path_traversal"]),
         ("Database attack", ["txt_sqli"]),
         ("Browser bug", ["txt_browser"]),
         ("WordPress plugin", ["txt_wordpress"]),
         ("Network edge device", ["txt_edge_device"])]
# phrases highlighted in the example description, each mapped to the text tag it triggers (or a plain label)
HIGHLIGHTS = [("Authentication Bypass", "Login bypass"), ("remote unauthenticated attacker", "No login needed"),
              ("super-admin privileges", "Takes full control"), ("FortiOS", "Widely deployed edge product")]

# ---- traits of CVEs that end up on KEV: descriptive natural frequencies (never used by the model) ----
TRAITS = [("All holes", None), ("Network edge device (firewall, VPN)", ["txt_edge_device"]),
          ("No login needed", ["txt_unauth", "txt_auth_bypass"]),
          ("Takes over the machine", ["txt_rce", "txt_cmd_injection"]),
          ("Enterprise software", ["txt_enterprise"]), ("Web browser", ["txt_browser"]),
          ("WordPress plugin", ["txt_wordpress"]), ("Cross-site scripting", ["txt_xss"])]
MIN_N = 1000  # a trait needs at least this many CVEs to be shown
FEW_CASES = 30  # fewer KEV entries than this -> "few cases, treat as a hint"
LIMITATION = ("KEV skews toward enterprise and government-relevant software, so WordPress plugins (3 of 13,777) and cross-site "
              "scripting (22 of 31,018) look safe here although they are widely attacked in practice.")


def why_traits(P):
    from src.b.phrases import strip_post_attack
    v = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published", "description"])
    v["published"] = pd.to_datetime(v["published"], errors="coerce")
    v = v[(v["published"] >= "2018-01-01") & (v["published"] <= "2025-09-30")].copy()
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "date_added"])
    v["added_to_kev"] = v["cve_id"].isin(kev["cve_id"])
    d = v["description"].fillna("").map(strip_post_attack).str.lower()
    flags = {f: d.str.contains(pat, regex=True) for f, pat in FLAGS.items()}
    rows = []
    for name, fl in TRAITS:
        m = pd.Series(True, index=v.index) if fl is None else np.logical_or.reduce([flags[f] for f in fl])
        g = v[m]
        rows.append({"trait": name, "cves": int(len(g)), "added_to_kev": int(g["added_to_kev"].sum()),
                     "per_1000": round(float(g["added_to_kev"].mean() * 1000), 2), "period": "2018-01 to 2025-09"})
    rep = pd.concat([P[2024], P[2025]], ignore_index=True)
    flagged = pd.concat([pd.read_parquet(OUT_DIR / f"replica_{y}.parquet", columns=["exploitdb", "metasploit", "nuclei", "poc_github"])
                         for y in (2024, 2025)], ignore_index=True).max(axis=1) == 1
    g = rep[flagged.to_numpy()]
    rows.insert(1, {"trait": "Public attack code exists", "cves": int(len(g)), "added_to_kev": int(g["label"].sum()),
                    "per_1000": round(float(g["label"].mean() * 1000), 2), "period": "2024-25 practice years"})
    rows = [r for r in rows if r["cves"] >= MIN_N]
    for r in rows:
        r["few_cases"] = r["added_to_kev"] < FEW_CASES  # fewer than ~30 KEV entries: treat as a hint
    return {"traits": rows, "kev_as_of": str(kev["date_added"].max()), "min_n": MIN_N,
            "note": ("Descriptive only, never a model input. Traits are keyword tags on the description (post-attack "
                     "phrases removed). 'Added to CISA KEV' = on CISA's Known Exploited Vulnerabilities list as of the date shown; "
                     "older CVEs had more time to be added. Public attack code uses the 2024-25 practice years (added by 4 Nov "
                     "of that year). A trait is associated with a higher or lower rate; it does not cause it."),
            "limitation": LIMITATION, "few_cases_below": FEW_CASES}


def blind_cves():
    """The blind-spot CVEs our headline model caught (outputs/v5_blindspots.csv from src.b.leakage), with their KEV vendor."""
    p = OUT_DIR / "v5_blindspots.csv"
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "vendor"]).drop_duplicates("cve_id").set_index("cve_id")["vendor"]
    if p.exists() and "ours_caught_cves" in pd.read_csv(p, nrows=1).columns:
        d = pd.read_csv(p).query("group == 'blind-spot'").dropna(subset=["ours_caught_cves"])
        return [{"cve_id": c, "kev_vendor": kev.get(c, ""), "test_replica": int(r.year)}
                for r in d.itertuples() for c in str(r.ours_caught_cves).split(";") if c]
    return pd.read_csv(mechanism_file()).query("group == 'blind-spot' and kind == 'gained'")[["cve_id", "kev_vendor", "test_replica"]].to_dict("records")


def pools():
    out = {}
    for y, f in ((2024, "replica_2024"), (2025, "replica_2025"), (2026, "scoreboard_features")):
        cols = ["cve_id", "snapshot_month", "epss"] + (["label"] if y < 2026 else [])
        out[y] = pd.read_parquet(OUT_DIR / f"{f}.parquet", columns=cols)
    return out


def latest_top():
    files = sorted(OUT_DIR.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    return files[-1].stem, pd.read_csv(files[-1])


def main():
    P = pools()
    res = runlog.results()
    best = runlog.latest_model(res)
    head = json.loads((OUT_DIR / "headline.json").read_text())
    story = {"model": runlog.model_name(best), "headline": head, "diff90": diff90(head)}

    # 1. the field
    prac_n = len(P[2024]) + len(P[2025])
    prac_pos = int(P[2024]["label"].sum() + P[2025]["label"].sum())
    rate = prac_pos / prac_n
    story["field"] = {"scoreboard": len(P[2026]), "practice_cves": prac_n, "practice_exploited": prac_pos,
                      "rate": rate, "one_in": int(round(1 / rate)), "expected_2026": int(round(rate * len(P[2026])))}

    # 2b. why: natural frequencies per trait (also written as its own small auditable file)
    story["why"] = why_traits(P)
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(story["why"]["traits"]).to_csv(SITE_DATA / "why_traits.csv", index=False)

    # 3. how defenders choose today (best simple rule), per practice year
    base = res[res["version"] == "baseline_exploit_epss"].set_index("test_year")
    story["fan"] = [{"year": y, "k": int(base.loc[y, "k"]), "exploited": int(P[y]["label"].sum()),
                     "caught": int(base.loc[y, "hits"]), "pool": len(P[y])} for y in (2024, 2025)]

    # 4. blind spots
    b = blind_spot_counts()
    mcol = [c for c in b.columns if c.startswith("Ours")][-1]
    story["blind"] = {
        "visible": int(b[b["group"] == "flagged"]["exploited"].sum()),
        "blind": int(b[b["group"] == "blind-spot"]["exploited"].sum()),
        "simple_caught_visible": int(b[b["group"] == "flagged"]["Public exploit, then EPSS"].sum()),
        "simple_caught_blind": int(b[b["group"] == "blind-spot"]["Public exploit, then EPSS"].sum()),
        "ours_caught_visible": int(b[b["group"] == "flagged"][mcol].sum()),
        "ours_caught_blind": int(b[b["group"] == "blind-spot"][mcol].sum()),
        "ours_blind_cves": blind_cves(),
    }

    # 5. what Granite reads: one real description
    texts = pd.read_parquet(OUT_DIR / "b_texts.parquet").set_index("cve_id")
    tf = pd.read_parquet(OUT_DIR / "text_features.parquet").set_index("cve_id")
    ex_year = int(EXAMPLE[4:8])
    nk = nearest_kev(pd.Series([EXAMPLE]), pd.Series([ex_year])).iloc[0]
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "name"]).set_index("cve_id")["name"]
    pool_scores = tf.loc[tf.index.isin(P[ex_year]["cve_id"]), "kev_text_score"]
    desc = texts.loc[EXAMPLE, "description"]
    story["example"] = {
        "cve": EXAMPLE, "description": desc,
        "highlights": [{"phrase": p, "label": l} for p, l in HIGHLIGHTS if p in desc],
        "tags": [TAG[f] for f in FLAGS if tf.loc[EXAMPLE, f] == 1],
        "kev_text_pct": float((pool_scores < tf.loc[EXAMPLE, "kev_text_score"]).mean()),
        "nearest": {"cve": nk["kev_match"], "vendor": nk["kev_match_vendor"], "product": nk["kev_match_product"],
                    "name": kev.get(nk["kev_match"], ""), "year_added": int(nk["kev_match_year"]),
                    "similarity": round(float(nk["kev_match_sim"]), 3)},
    }

    # 6. 2026 is different: median EPSS per reporter x month
    vuln = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "assigner"])
    allp = pd.concat(P.values(), ignore_index=True)[["cve_id", "snapshot_month", "epss"]].merge(vuln, on="cve_id", how="left")
    months = sorted(allp["snapshot_month"].unique())
    rows = [("All CVEs", allp)]
    for a, name in CNA_NAMES.items():
        g = allp[allp["assigner"] == a]
        if len(g) > 1500:
            rows.append((name, g))
    heat = []
    for name, g in rows[:11]:
        m = g.groupby("snapshot_month")["epss"].agg(["median", "size"]).reindex(months)
        heat.append({"name": name, "n": int(len(g)),
                     "cells": [{"month": mo, "median_pct": None if pd.isna(r["median"]) or r["size"] < 20 else round(r["median"] * 100, 4),
                                "n": int(0 if pd.isna(r["size"]) else r["size"])} for mo, r in m.iterrows()]})
    sbm = P[2026].groupby("snapshot_month")["epss"].agg(["median", "size"])
    early = sbm.loc[[m for m in sbm.index if m < "2026-07"]]
    late = sbm.loc[[m for m in sbm.index if m >= "2026-07"]]
    story["heat"] = {"months": months, "rows": heat, "jump_month": "2026-07",
                     "early_2026_median_pct": round(float(P[2026][P[2026]["snapshot_month"] < "2026-07"]["epss"].median() * 100), 3),
                     "late_2026_median_pct": round(float(P[2026][P[2026]["snapshot_month"] >= "2026-07"]["epss"].median() * 100), 3),
                     "past_median_pct": round(float(pd.concat([P[2024], P[2025]])["epss"].median() * 100), 3),
                     "late_share": round(float(late["size"].sum() / sbm["size"].sum()), 3),
                     "spot_the_year_auc": json.loads((OUT_DIR / "b_drift.json").read_text())["spot_the_year_auc"]}

    # 7. too good to be true
    lk = pd.read_csv(OUT_DIR / "leakage_results.csv")
    from src.b.leakage import banned_columns
    an = []
    for y in (2024, 2025):
        bc = banned_columns(P[y]["cve_id"]).merge(P[y][["cve_id", "label"]], on="cve_id")
        an.append(bc.groupby("label")["leak_nvd_status_analyzed"].mean())
    story["leak"] = {"honest": int(lk[lk["model"] == "honest"]["hits"].sum()),
                     "leaky": int(lk[lk["model"] == "leaky"]["hits"].sum()),
                     "by_year": lk[lk["model"].isin(["honest", "leaky"])][["replica", "model", "hits"]].to_dict("records"),
                     "analyzed_exploited": round(float(np.mean([a.loc[1] for a in an])), 3),
                     "analyzed_others": round(float(np.mean([a.loc[0] for a in an])), 3)}

    # 8. our 500
    name, top = latest_top()
    expl = pd.read_csv(OUT_DIR / "explanations.csv").set_index("cve_id")["reason"]
    sb = pd.read_parquet(OUT_DIR / "features_scoreboard.parquet", columns=["cve_id", "epss_rank_in_month", "any_exploit"]).set_index("cve_id")
    t = top.reset_index(names="rank").merge(vuln, on="cve_id", how="left")
    pretty = {"Paloaltonetworks": "Palo Alto Networks", "Vulncheck": "VulnCheck", "Hpe": "HPE", "Ivanti": "Ivanti"}
    t["cna"] = t["assigner"].map(lambda a: CNA_NAMES.get(a) or pretty.get(cna_name(a) or "", cna_name(a)) or "Other reporters")
    counts = t["cna"].value_counts()
    t["group"] = t["cna"].where(t["cna"].map(counts) >= 8, "Other reporters")
    tflags = tf.reindex(t["cve_id"])
    order = ["txt_rce", "txt_auth_bypass", "txt_unauth", "txt_cmd_injection", "txt_sqli", "txt_path_traversal",
             "txt_deserialization", "txt_priv_esc", "txt_memory", "txt_xss", "txt_edge_device", "txt_browser",
             "txt_wordpress", "txt_enterprise"]
    t["flaw"] = [next((TAG[f] for f in order if r[f] == 1), "Other flaw") for _, r in tflags.iterrows()]
    t["kind"] = [next((name for name, fl in KINDS if any(r[f] == 1 for f in fl)), "Other kinds of flaw")
                 for _, r in tflags.iterrows()]
    story["top"] = {"list": name, "items": [
        {"cve": r.cve_id, "rank": int(r["rank"]) + 1, "group": r.group, "flaw": r.flaw, "kind": r.kind,
         "reason": expl.get(r.cve_id, ""), "epss_pct": round(float(sb.loc[r.cve_id, "epss_rank_in_month"]), 3),
         "exploit": int(sb.loc[r.cve_id, "any_exploit"])} for _, r in t.iterrows()]}

    # 9. honest results
    story["results"] = [{"name": runlog.model_name(v), "is_ours": v == best,
                         "by_year": {str(int(y)): int(h) for y, h in res[res["version"] == v].set_index("test_year")["hits"].items()}}
                        for v in ["baseline_cvss", "baseline_epss", "baseline_exploit_epss", best]]

    SITE_DATA.mkdir(parents=True, exist_ok=True)
    (SITE_DATA / "story.json").write_text(json.dumps(story, separators=(",", ":"), default=str))
    kb = (SITE_DATA / "story.json").stat().st_size / 1024
    print(f"wrote site/data/story.json ({kb:.0f} KB)")
    print({k: v for k, v in story["field"].items()}, story["blind"]["visible"], story["blind"]["blind"])
    print(story["heat"]["early_2026_median_pct"], story["heat"]["late_2026_median_pct"], story["heat"]["past_median_pct"],
          story["heat"]["late_share"])
    print(story["example"]["nearest"], story["example"]["tags"], round(story["example"]["kev_text_pct"], 3))
    print(story["leak"]["analyzed_exploited"], story["leak"]["analyzed_others"], story["top"]["list"],
          pd.Series([i["group"] for i in story["top"]["items"]]).value_counts().head(8).to_dict())


if __name__ == "__main__":
    main()
