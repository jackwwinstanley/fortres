"""Write site/data/demo.json, the only data the presenter page (site/demo.html) reads.  Run:  python scripts/export_demo.py

Every number and every on-screen sentence that contains a number is built here from committed outputs, so site/demo.js holds none.
The workload row (how far down each ranking you must go to match v6) needs the practice-year scores, which are not committed: with
data/ present it is recomputed through the existing replica code; without data/ the values already in site/data/demo.json are kept.

Showcase CVEs are chosen by rule, never by hand:
  a  the highest-ranked top-500 pick whose reason passed Granite Guardian (guardian_verdict == "No");
  b  the highest-ranked top-500 pick that shows a template reason (source == "template");
  c  the highest-ranked top-500 pick with no public exploit code and a within-month EPSS rank below 1 - 500/pool (the blind-spot
     definition of stress_v2.group_of);
  d  the median-ranked CVE outside the top 500.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "outputs"
TARGET = ROOT / "site" / "data" / "demo.json"
BINS = 200
TOP = 500
# plain-English families (first match wins), the same list as src/b/export_story.KINDS
KINDS = [("Takes over the machine", ["txt_rce", "txt_cmd_injection", "txt_deserialization"]),
         ("No login needed", ["txt_unauth", "txt_auth_bypass"]),
         ("Gets admin powers", ["txt_priv_esc"]),
         ("Reads files it shouldn't", ["txt_path_traversal"]),
         ("Database attack", ["txt_sqli"]),
         ("Browser bug", ["txt_browser"]),
         ("WordPress plugin", ["txt_wordpress"]),
         ("Network edge device", ["txt_edge_device"])]
SOURCES = {"exploitdb": "Exploit-DB", "metasploit": "Metasploit", "nuclei": "Nuclei template", "poc_github": "GitHub proof of concept"}
VERDICT_NOTE = {"Yes": "Granite Guardian rejected the AI's draft, so a fixed template is shown.",
                "not_run": "The AI's draft failed our local checks, so a fixed template is shown."}


def histogram(scores: pd.DataFrame) -> dict:
    v = scores["v6_score"].to_numpy()
    edges = np.linspace(0, 1, BINS + 1)
    all_counts = np.histogram(v, bins=edges)[0]
    top = scores.sort_values("v6_rank").head(TOP)["v6_score"].to_numpy()
    top_counts = np.histogram(top, bins=edges)[0]
    return {"bins": BINS, "counts": [int(x) for x in all_counts], "top_counts": [int(x) for x in top_counts], "n": int(len(v)), "top": TOP,
            "cutoff_score": round(float(top.min()), 6), "max_count": int(all_counts.max())}


def _pct(x: float) -> str:
    return f"{max(0.1, (1 - x) * 100):.1f}%"


def card(cve: str, scores: pd.DataFrame, exp: pd.DataFrame, feat: pd.DataFrame, text: pd.DataFrame) -> dict:
    rank = int(scores.loc[cve, "v6_rank"])
    f, t = feat.loc[cve], text.loc[cve]
    kind = next((name for name, fl in KINDS if any(int(t[x]) == 1 for x in fl)), "Other kind of flaw")
    code = [label for col, label in SOURCES.items() if int(f[col]) == 1]
    kev_pct = float((text["kev_text_score"] <= t["kev_text_score"]).mean())
    signals = ["Public exploit code: " + (", ".join(code) if code else "none"),
               f"EPSS within its month: top {_pct(float(f['epss_rank_in_month']))}",
               f"IBM Granite similarity to past KEV entries: top {_pct(kev_pct)}"]
    out = {"cve": cve, "rank": rank, "rank_text": f"{rank:,}", "kind": kind, "signals": signals, "in_top": rank <= TOP}
    if cve in exp.index:
        e = exp.loc[cve]
        out.update(reason=str(e["explanation"]), guardian_verdict=str(e["guardian_verdict"]), source=str(e["source"]))
    else:
        out.update(reason=None, guardian_verdict=None, source=None)
    return out


def showcase(scores: pd.DataFrame, exp: pd.DataFrame, feat: pd.DataFrame, text: pd.DataFrame) -> dict:
    s = scores.sort_values("v6_rank")
    top = s.head(TOP).index.tolist()
    a = next(c for c in top if exp.loc[c, "guardian_verdict"] == "No")
    b = next(c for c in top if exp.loc[c, "source"] == "template")
    cut = 1 - TOP / len(feat)
    c = next((x for x in top if int(feat.loc[x, "any_exploit"]) == 0 and float(feat.loc[x, "epss_rank_in_month"]) < cut), None)
    rest = s.iloc[TOP:]
    d = rest.index[(len(rest) - 1) // 2]
    return {k: card(v, scores, exp, feat, text) for k, v in (("a", a), ("b", b), ("c", c), ("d", d)) if v is not None}


def workload() -> dict | None:
    """Depth each ranking needs, per practice test year, to match v6's hits at k, summed over the two years (needs data/)."""
    if not (ROOT / "data" / "vulnerabilities.csv").exists():
        return None
    from src.b import rank as R
    from src.common import primary
    from src.common.scoring import rank_order
    from src.models.train_v5 import FEATURES_V5
    data, ctx = R.load()
    v = pd.read_csv(ROOT / "data" / "vulnerabilities.csv", usecols=["cve_id", "cvss3_score"]).set_index("cve_id")
    F5 = list(FEATURES_V5)
    R.CACHE.mkdir(parents=True, exist_ok=True)
    tot = {"v6": 0, "rule": 0, "epss": 0, "cvss": 0}
    for d in R.DIRS:
        c = ctx[d]
        m = c["meta"].reset_index(drop=True).copy()
        p = primary.direction_params(d[0], c["tr"]["X5"], c["tr"]["y"], c["tr"]["groups"], F5)
        m["v6s"] = R.bag_scores(f"I_{d[0]}", R.V5_SPEC, p, c, R.SEEDS)
        m["c3"] = v["cvss3_score"].reindex(m["cve_id"]).fillna(-1).to_numpy()
        labels = {"v6": rank_order(m, ["v6s", "epss_rank_in_month"])["label"].to_numpy(), "rule": rank_order(m, ["exploit_epss"])["label"].to_numpy(),
                  "epss": rank_order(m, ["epss_rank_in_month"])["label"].to_numpy(), "cvss": rank_order(m, ["c3"])["label"].to_numpy()}
        h = int(labels["v6"][:c["k"]].sum())
        tot["v6"] += c["k"]
        for n in ("rule", "epss", "cvss"):
            tot[n] += int(np.flatnonzero(labels[n])[h - 1]) + 1
    return tot


def numbers() -> dict:
    h = json.loads((OUT / "headline.json").read_text())
    g = json.loads((OUT / "explanations_summary.json").read_text())
    b = pd.read_csv(OUT / "v6_blindspots.csv")
    lk = pd.read_csv(OUT / "v6_leakage_results.csv")
    pool = sum(len(pd.read_parquet(OUT / f"replica_{y}.parquet", columns=["cve_id"])) for y in (2024, 2025))
    positives = sum(h["positives"].values())
    by = lk.groupby("model")["hits"].sum()
    lo, hi = h["pooled"]["diff_cve_level_90"]
    blind = b[b["group"] == "blind-spot"]
    story = json.loads((ROOT / "site" / "data" / "story.json").read_text())
    ivanti = sum(1 for c in story["blind"]["ours_blind_cves"] if str(c.get("kev_vendor", "")).lower() == "ivanti")
    return {"ours": h["pooled_hits_bag"], "rule": h["baseline_pooled_hits"], "gain": h["pooled_hits_bag"] - h["baseline_pooled_hits"], "gain_lo": int(lo), "gain_hi": int(hi),
            "forward_ours": h["forward_train2024_test2025"]["bag_hits"], "forward_rule": h["forward_train2024_test2025"]["baseline_hits"],
            "stability_ours": h["stability_train2025_test2024"]["bag_hits"], "stability_rule": h["stability_train2025_test2024"]["baseline_hits"],
            "honest": h["leakage"]["honest"]["pooled_hits"], "leaky": h["leakage"]["leaky"]["pooled_hits"],
            "epss_only": int(by["EPSS first"]), "cvss_only": int(by["CVSS 3 first"]),
            "blind": int(blind["exploited"].sum()), "positives": positives, "blind_caught": int(blind["ours_caught"].sum()), "blind_ivanti": ivanti,
            "passed": g["passed_guardian"], "templates": g["template_fallback"], "total_reasons": g["total"],
            "pool": pool, "one_in": round(pool / positives), "seeds": h["seeds"]["bag_seeds"], "trees": h["final_params"]["n_estimators"]}


def copy_text(n: dict, hist: dict, wl: dict | None, show: dict) -> dict:
    b = show["b"]
    return {
        "hook_big": f"{hist['n']:,}",
        "hook_line": "new security holes in 2026.",
        "hook_rate": f"In our 2024 and 2025 test, about 1 in {n['one_in']} ended up on CISA's known-exploited list.",
        "what_title": f"A triage system: a model ranks every hole and picks the {hist['top']} to fix first. IBM Granite explains each pick.",
        "flow": ["Public data on every hole", f"Ranking model: {n['seeds']} models, {n['trees']} small decision trees each", f"Top {hist['top']}", "Granite writes, Guardian checks"],
        "replay_label": "replay of our real run",
        "replay_title": f"Every one of the {hist['n']:,} holes, scored and ranked",
        "replay_top": f"top {hist['top']}: fix these first",
        "lookup_a_badge": "Checked by Granite Guardian: passed",
        "lookup_b_note": VERDICT_NOTE.get(b.get("guardian_verdict"), "A fixed template is shown."),
        "lookup_d_note": f"Rank {show['d']['rank_text']}, not in the {hist['top']}. No reason is written for it.",
        "result_title": f"In our 2024 and 2025 test: holes caught, out of {n['positives']}",
        "result_bars": [{"label": "Fortres", "v": n["ours"], "ours": True}, {"label": "Public attack code, then EPSS", "v": n["rule"]},
                        {"label": "EPSS alone", "v": n["epss_only"]}, {"label": "Severity (CVSS) alone", "v": n["cvss_only"]}],
        "result_range": f"Lead over the best simple rule: +{n['gain']}. 90% range: +{n['gain_lo']} to +{n['gain_hi']}.",
        "result_split": f"Year by year: {n['forward_ours']} vs {n['forward_rule']} in 2025, {n['stability_ours']} vs {n['stability_rule']} in 2024.",
        "result_workload": None if wl is None else (f"To reach the same catches: Fortres {wl['v6']:,} reviews, the simple rule {wl['rule']:,}, "
                                                    f"EPSS {wl['epss']:,}, severity {wl['cvss']:,}."),
        "leak_big": f"We could have claimed {n['leaky']}. We didn't.",
        "leak_note": f"Some database fields are filled in after a hole is added to CISA's list. Using them lifts {n['honest']} to {n['leaky']}, so we banned them.",
        "cards": [{"big": f"{n['blind']} of {n['positives']}", "text": "gave no warning: no public attack code and a low risk score.",
                   "small": f"Fortres flags {n['blind_caught']} of them, {n['blind_ivanti']} from one Ivanti event. The usual rule flags none."},
                  {"big": f"{n['honest']} vs {n['leaky']}", "text": "Data that appears after the fact inflates the score.", "small": "We show the trap and stay out of it."},
                  {"big": f"{n['templates']} of {n['total_reasons']}", "text": "AI-written reasons were replaced by a plain template.",
                   "small": f"The other {n['passed']} passed a groundedness check."}],
        "close_big": "Fortres ranks, Granite explains, Guardian checks.",
        "close_links": ["fortres.us", "github.com/jackwwinstanley/ibm-breach"],
        "close_team": "Yahya Hashme and Jack Winstanley",
        "close_built": "Built with IBM Granite. Session audit trail with Entire.",
    }


def main() -> int:
    scores = pd.read_csv(OUT / "v6_scores.csv").set_index("cve_id")
    exp = pd.read_csv(OUT / "explanations.csv").set_index("cve_id")
    feat = pd.read_parquet(OUT / "features_scoreboard.parquet").set_index("cve_id")
    text = pd.read_parquet(OUT / "text_features.parquet").set_index("cve_id").reindex(feat.index)
    hist = histogram(scores.reset_index())
    show = showcase(scores, exp, feat, text)
    n = numbers()
    wl = workload()
    if wl is None and TARGET.exists():
        wl = json.loads(TARGET.read_text()).get("workload")
    if wl:
        wl = {**wl, "source": "scripts/export_demo.py workload(): outputs/replica_*.parquet and data/, the existing replica code, v6 settings from src/common/primary.py"}
    out = {"hist": hist, "showcase": show, "numbers": n, "workload": wl, "copy": copy_text(n, hist, wl, show),
           "sources": ["outputs/headline.json", "outputs/top500_v6.csv", "outputs/v6_scores.csv", "outputs/explanations.csv", "outputs/explanations_summary.json",
                       "outputs/v6_blindspots.csv", "outputs/v6_leakage_results.csv", "outputs/features_scoreboard.parquet", "outputs/text_features.parquet",
                       "outputs/replica_2024.parquet", "outputs/replica_2025.parquet", "site/data/story.json"]}
    TARGET.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print("wrote site/data/demo.json")
    for k, v in show.items():
        print(k, v["cve"], "rank", v["rank"], "|", v["kind"], "|", v.get("guardian_verdict"), "|", v.get("source"))
    print("workload", wl and {k: wl[k] for k in ("v6", "rule", "epss", "cvss")})
    return 0


if __name__ == "__main__":
    sys.exit(main())
