"""The presenter page (site/demo.html): site/data/demo.json equals its source files, the showcase CVEs follow the rules, and
site/demo.js holds no result numbers. A mutation check proves the comparison can fail."""
import json
import re
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import export_demo as ex  # noqa: E402

OUT = ROOT / "outputs"
DEMO = ROOT / "site" / "data" / "demo.json"
d = json.loads(DEMO.read_text())


def problems(demo: dict) -> list[str]:
    """Compare demo.json with the committed source files; returns a list of differences."""
    probs = []
    n, h = demo["numbers"], json.loads((OUT / "headline.json").read_text())
    want = {"ours": h["pooled_hits_bag"], "rule": h["baseline_pooled_hits"], "forward_ours": h["forward_train2024_test2025"]["bag_hits"],
            "forward_rule": h["forward_train2024_test2025"]["baseline_hits"], "stability_ours": h["stability_train2025_test2024"]["bag_hits"],
            "stability_rule": h["stability_train2025_test2024"]["baseline_hits"], "honest": h["leakage"]["honest"]["pooled_hits"],
            "leaky": h["leakage"]["leaky"]["pooled_hits"], "gain_lo": int(h["pooled"]["diff_cve_level_90"][0]), "gain_hi": int(h["pooled"]["diff_cve_level_90"][1])}
    g = json.loads((OUT / "explanations_summary.json").read_text())
    want.update(passed=g["passed_guardian"], templates=g["template_fallback"], total_reasons=g["total"])
    b = pd.read_csv(OUT / "v6_blindspots.csv")
    blind = b[b["group"] == "blind-spot"]
    want.update(blind=int(blind["exploited"].sum()), blind_caught=int(blind["ours_caught"].sum()), positives=int(b["exploited"].sum()))
    lk = pd.read_csv(OUT / "v6_leakage_results.csv").groupby("model")["hits"].sum()
    want.update(epss_only=int(lk["EPSS first"]), cvss_only=int(lk["CVSS 3 first"]))
    probs += [f"numbers.{k}: {n[k]} != {v}" for k, v in want.items() if n[k] != v]
    s = pd.read_csv(OUT / "v6_scores.csv")
    hist = demo["hist"]
    if hist["n"] != len(s) or sum(hist["counts"]) != len(s) or sum(hist["top_counts"]) != hist["top"]:
        probs.append("histogram totals differ from v6_scores.csv")
    e = pd.read_csv(OUT / "explanations.csv").set_index("cve_id")
    for k, c in demo["showcase"].items():
        if int(s.set_index("cve_id").loc[c["cve"], "v6_rank"]) != c["rank"]:
            probs.append(f"showcase {k}: rank differs")
        if c["reason"] is not None and (c["reason"] != e.loc[c["cve"], "explanation"] or c["guardian_verdict"] != e.loc[c["cve"], "guardian_verdict"]):
            probs.append(f"showcase {k}: reason or verdict differs from explanations.csv")
    return probs


def test_demo_json_equals_its_sources():
    assert problems(d) == []


@pytest.mark.parametrize("mutate", [lambda x: x["numbers"].__setitem__("ours", 28), lambda x: x["showcase"]["a"].__setitem__("reason", "edited"),
                                    lambda x: x["hist"]["counts"].__setitem__(0, x["hist"]["counts"][0] + 1)])
def test_mutation_check_the_comparison_can_fail(mutate):
    m = json.loads(DEMO.read_text())
    mutate(m)
    assert problems(m)


def test_showcase_follows_the_selection_rules():
    s = pd.read_csv(OUT / "v6_scores.csv").sort_values("v6_rank")
    e = pd.read_csv(OUT / "explanations.csv").set_index("cve_id")
    top = s.head(ex.TOP)["cve_id"].tolist()
    show = d["showcase"]
    assert show["a"]["cve"] == next(c for c in top if e.loc[c, "guardian_verdict"] == "No")
    assert show["b"]["cve"] == next(c for c in top if e.loc[c, "source"] == "template")
    f = pd.read_parquet(OUT / "features_scoreboard.parquet").set_index("cve_id")
    cut = 1 - ex.TOP / len(f)
    assert show["c"]["cve"] == next(c for c in top if int(f.loc[c, "any_exploit"]) == 0 and f.loc[c, "epss_rank_in_month"] < cut)
    rest = s.iloc[ex.TOP:]
    assert show["d"]["cve"] == rest["cve_id"].iloc[(len(rest) - 1) // 2] and show["d"]["reason"] is None and not show["d"]["in_top"]


def test_template_wording_matches_the_real_verdict():
    b = d["showcase"]["b"]
    assert d["copy"]["lookup_b_note"] == ex.VERDICT_NOTE[b["guardian_verdict"]]


def test_demo_js_holds_no_result_numbers():
    js = re.sub(r"/\*.*?\*/|//[^\n]*", " ", (ROOT / "site" / "demo.js").read_text(), flags=re.S)
    n = d["numbers"]
    results = {n[k] for k in ("ours", "rule", "forward_ours", "forward_rule", "stability_ours", "stability_rule", "leaky", "epss_only", "blind", "positives",
                              "passed", "templates", "total_reasons", "one_in", "seeds", "trees", "pool", "blind_caught")} | {d["hist"]["n"], d["hist"]["top"]}
    literals = {int(x.replace(",", "")) for x in re.findall(r"(?<![\w.#-])\d[\d,]*(?![\w.])", js) if x.replace(",", "").isdigit()}
    assert not (literals & results), literals & results


def test_mutation_check_a_typed_number_is_caught():
    js = 'const x = %d;' % d["numbers"]["leaky"]
    assert re.findall(r"(?<![\w.#-])\d[\d,]*(?![\w.])", js) == [str(d["numbers"]["leaky"])]


def test_page_is_offline_and_uses_the_wording_rules():
    html = (ROOT / "site" / "demo.html").read_text() + (ROOT / "site" / "demo.css").read_text() + (ROOT / "site" / "demo.js").read_text()
    assert "http://" not in html.replace("http://localhost", "") and "https://" not in html and "fonts.googleapis" not in html
    text = (html + DEMO.read_text()).lower()
    for bad in ("predicts", "detects", "proves", "verified", "guarantees", "real-time", "watsonx"):
        assert bad not in text, bad


def test_no_randomness_in_the_engine():
    assert "Math.random" not in (ROOT / "site" / "demo.js").read_text()


@pytest.mark.skipif(not (ROOT / "data" / "vulnerabilities.csv").exists(), reason="the workload row needs the untracked datathon data")
def test_workload_row_can_be_recomputed():
    w = ex.workload()
    assert {k: d["workload"][k] for k in w} == w
