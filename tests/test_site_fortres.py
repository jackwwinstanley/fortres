"""The Fortres page (site/) shows only values read from the final outputs: each reason equals outputs/explanations.csv for the
same CVE, the picks follow the primary top-500 order, and every headline number equals outputs/headline.json and the
primary model's blind-spot file."""
import json
import re
from pathlib import Path

import pandas as pd
import pytest

from src.common import primary
from src.common.paths import OUT_DIR, REPO_ROOT

SITE = REPO_ROOT / "site"
need = pytest.mark.skipif(not (SITE / "data" / "picks.json").exists() or not (OUT_DIR / "explanations.csv").exists(),
                          reason="site data or explanations not present")


@need
def test_every_reason_on_the_page_equals_explanations_csv():
    picks = json.loads((SITE / "data" / "picks.json").read_text())
    exp = pd.read_csv(OUT_DIR / "explanations.csv").set_index("cve_id")
    top = pd.read_csv(primary.file("top500"))["cve_id"].tolist()
    assert picks["list"] == primary.file("top500").stem
    for r in picks["rows"]:
        assert r["reason"] == exp.loc[r["cve"], "explanation"], r["cve"]
        assert r["guardian_passed"] == (exp.loc[r["cve"], "guardian_verdict"] == "No"), r["cve"]
        assert top[r["rank"] - 1] == r["cve"], r["cve"]
    summ = json.loads((OUT_DIR / "explanations_summary.json").read_text())
    assert picks["guardian"]["passed_guardian"] == summ["passed_guardian"] and picks["guardian"]["total"] == summ["total"]


@need
def test_page_numbers_equal_the_headline_and_blind_spot_files():
    h = json.loads((OUT_DIR / "headline.json").read_text())
    story = json.loads((SITE / "data" / "story.json").read_text())
    ours = [r for r in story["results"] if r["is_ours"]]
    assert len(ours) == 1 and sum(ours[0]["by_year"].values()) == h["pooled_hits_bag"]
    rule = [r for r in story["results"] if r["name"] == "Public exploit, then EPSS"][0]
    assert sum(rule["by_year"].values()) == h["baseline_pooled_hits"]
    b = pd.read_csv(primary.file("blindspots"))
    bl = story["blind"]
    assert bl["blind"] == int(b.loc[b["group"] == "blind-spot", "exploited"].sum())
    assert bl["ours_caught_blind"] == int(b.loc[b["group"] == "blind-spot", "ours_caught"].sum())
    assert bl["visible"] + bl["blind"] == int(b["exploited"].sum())
    html = (SITE / "index.html").read_text()
    assert [int(x) for x in re.findall(r'class="count[^"]*"[^>]*data-to="(\d+)"', html)] == [h["pooled_hits_bag"], h["baseline_pooled_hits"]]
    html = re.sub(r"<[^>]+>", "", html)  # the visible text
    f, s = h["forward_train2024_test2025"], h["stability_train2025_test2024"]
    assert f"{f['bag_hits']} to {f['baseline_hits']} in 2025" in html and f"{s['bag_hits']} to {s['baseline_hits']} in 2024" in html
    lo, hi = h["pooled"]["diff_cve_level_90"]
    assert f"+{h['pooled_hits_bag'] - h['baseline_pooled_hits']}" in html and f"from +{lo:.0f} to +{hi:.0f}" in html
    total = int(b["exploited"].sum())  # the "27 not 33" card shows percentages of the 75, not the raw counts
    pct = lambda n: int(100 * n / total + 0.5)
    assert f"from {pct(h['leakage']['honest']['pooled_hits'])}% to {pct(h['leakage']['leaky']['pooled_hits'])}%" in html


@need
def test_full_picks_and_lookup_list_equal_the_outputs():
    """The 500 table and the look-up list are data files now; every reason, the pass flag and the order must match outputs/."""
    rows = json.loads((SITE / "data" / "picks500.json").read_text())
    exp = pd.read_csv(OUT_DIR / "explanations.csv").set_index("cve_id")
    top = pd.read_csv(primary.file("top500"))["cve_id"].tolist()
    assert len(rows) == 500
    for r in rows:
        rank, cve, reason, passed = r[0], r[1], r[7], r[8]
        assert top[rank - 1] == cve, cve
        assert reason == exp.loc[cve, "explanation"], cve
        assert bool(passed) == (exp.loc[cve, "guardian_verdict"] == "No"), cve
    ranks = (SITE / "data" / "ranks.txt").read_text().strip().split(",")
    assert len(ranks) == 72670
    assert ["CVE-20" + x.split(".")[0] for x in ranks[:500]] == top


@need
def test_findings_charts_equal_the_outputs():
    """The findings page draws its charts from site/data/findings.json; it must equal a fresh export from outputs/, and the
    counts it shows must agree with the sentences beside them."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("export_site_findings", REPO_ROOT / "scripts" / "export_site_findings.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    on_page = json.loads((SITE / "data" / "findings.json").read_text())
    assert on_page == json.loads(json.dumps(mod.build(), ensure_ascii=False))
    h = json.loads((OUT_DIR / "headline.json").read_text())
    assert on_page["leakage"] == {"honest": h["leakage"]["honest"]["pooled_hits"], "leaky": h["leakage"]["leaky"]["pooled_hits"]}
    r = on_page["reasons"]
    assert r["passed_guardian"] + r["guardian_rejected"] + r["local_failed"] == r["total"]
    assert sum(n for _, _, n in on_page["events"]) == on_page["blind"]["total"]
    html = re.sub(r"\s+", " ", (SITE / "index.html").read_text())
    for sid in ["f-events", "f-vendor", "f-epss", "f-dates", "f-simple"]:
        assert f'id="{sid}"' in html, sid
    assert f"EPSS scores jumped {on_page['epss_jump']} times" in html
    assert f"{len(on_page['events'])} separate events" in html
    assert f"from {on_page['vendor_cv_2025']['ungrouped']} to {on_page['vendor_cv_2025']['vendor_grouped']}" in html
