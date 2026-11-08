"""Check the numbers and wording in Person B's documents against the real outputs.  Exit 1 on any problem.

Run:  python scripts/number_sweep.py

Expected values are READ from outputs/headline.json and the primary model's leakage and blind-spot files
(src/common/primary.py: outputs/v6_leakage_results.csv, outputs/v6_blindspots.csv) and
outputs/explanations_summary.json, never typed here. Checked files: docs/*.md, site/index.html, site/fortres.js, app/*.py,
README.md. Checks:
  1. banned words: "verified", "predicts", "uses (IBM) Granite to read each description" (allowed right after "never"/"not",
     as in the wording rules themselves);
  2. stale numbers: "23 to/→ 30", and 29 as the leaky number (29 is allowed only on a line that says it was the earlier v4 run);
  3. leaky claims "from H to L" / "H → L" on leakage lines must equal honest/leaky pooled hits; "L (a + b)" must match per direction;
  4. "N vs M" against the simple rule/baseline in the final documents must be a headline pair (pooled, forward or stability);
  5. 90% ranges in the final documents must be a headline range (any stored interval in headline.json, CVE-level or
     event-clustered, outside the `previous` block);
  6. "N of M" blind-spot claims must equal the primary model's blind-spot totals;
  7. Guardian counts in prose ("N of 500 ... passed") must equal `passed_guardian` in outputs/explanations_summary.json
     (without that file, any such count is an error);
  8. every row of the Guardian count table in docs/model_card.md (`| item | N | `field`, ... |`) must equal each field it
     names in outputs/explanations_summary.json (dotted names such as `guardian_verdicts.No` are looked up inside objects);
  9. no leftover "TODO(" markers in any checked file;
 10. explanation counts in prose: "N template(s)" must equal `template_fallback` and "N pending" must equal `pending`
     (only on lines that are about the reasons/explanations/Guardian);
 11. watsonx.governance numbers, in every checked file: a sentence or clause that names watsonx.governance is HOSTED unless it
     says the scores were computed locally (or names a local-only metric: token overlap, BERTScore, readability), then it is
     LOCAL. Every decimal and every "N of M" in a HOSTED clause must come from outputs/watsonx_gov_summary.json, and in a
     LOCAL clause from outputs/gov_metrics_summary.json, so one file can never feed the other's claim. A number claimed
     without its summary file is an error. The summaries' own `claim` must say "hosted on IBM watsonx.governance" (hosted)
     and must not say "hosted" (local);
 12. docs/entire.md: every row `| item | N | `field` |` must equal that field of outputs/entire_summary.json (a field written
     `label:field` is read from that machine's outputs/entire_summary_<label>.json, and a missing file is reported as missing),
     and every other number
     in its prose (outside code spans, code blocks, links and list markers) must be a value, date, timestamp or the version
     stored in that file; the doc without the file is an error;
 14. on a line about the 2023 back-test ("older year" and 2023), "N of M" must equal v6's hits and positives in outputs/extra_year_eval.csv;
 13. on any line that mentions Entire, "N checkpoints" and "N sessions" must equal n_checkpoints and n_sessions in that file;
 14. the findings (docs/findings.md, and any final document that repeats one): the phrases of each finding must match its source
     file, including which method each workload number belongs to (see `discovery_values`, `check_findings`);
 15. every number in the prose of docs/findings.md must be a value from those source files;
 16. the one-sentence definition of fortres must appear word for word in README.md, docs/findings.md, docs/devpost_final.md,
     docs/video_script.md, and in site/index.html once that page has a "What we found" section;
 17. every percentage that carries a raw count ("36% (27 of 75)") must be that count's percentage, and the count must come from
     its source file: fortres and the usual rule from headline.json, the "no warning" group from the blind-spot file, the leakage
     pair (36% to 44%, 27 to 33 of 75) from the leakage files, "about 2.5 times the work" from discovery_workload.csv, and for the
     2023 back-test (4 of 22, 5 of 22, 144 of 20,969, "about 26 times better than random") from extra_year_eval.csv; the
     "rebuild in about N minutes" claim must equal the whole minutes of the train_v6 timing in README.md;
 19. the "27 not 33" card of site/index.html (data-s="trust") is in percentages only: 36% and 44% are honest and leaky out of 75,
     "35% to 37% every time" is the lowest and highest pooled hits of the four seed sets in outputs/zoo_summary.md out of 75,
     18% and 23% are v6's and the usual rule's hits out of 22 in outputs/extra_year_eval.csv, and the raw counts are not shown;
 18. the "AI explanations need checking" band of site/index.html (id="f-ai"): its counts and percentage must be the
     explanations_summary.json values (total, template_fallback, guardian_verdicts.not_run and .Yes), the 0.80 and the "none
     flagged" must come from watsonx_gov_summary.json, and it must not say "passed watsonx", "verified", "validated" or "proves".
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "outputs"
# documents that state final results (research notes like considered_not_adopted.md legitimately quote other numbers)
FINAL_DOCS = {"docs/writeup_person_b.md", "docs/devpost_final.md", "docs/judge_qa.md", "docs/video_script.md",
              "docs/page_content.md", "README.md", "site/index.html", "docs/findings.md"}
MINUS = "[−-]"
MODEL_CARD = "docs/model_card.md"
ENTIRE_DOC = "docs/entire.md"
FINDINGS_DOC = "docs/findings.md"
DEFINITION = ("Fortres is a triage system for security holes: a statistical model ranks all {scoreboard:,} of 2026's new vulnerabilities "
              "and picks the {picks} to fix first, ranked by the warning signs known at the time, and IBM Granite models help read the descriptions and explain every "
              "pick in plain language.")
DEFINITION_DOCS = {"README.md", FINDINGS_DOC, "docs/devpost_final.md", "docs/video_script.md"}
GOV_SUMMARIES = {"watsonx_gov": "watsonx_gov_summary.json", "gov_local": "gov_metrics_summary.json"}
GOV_NAME = re.compile(r"watsonx[ .]?governance", re.I)
GOV_LOCAL = re.compile(r"\blocal(?:ly)?\b|no ibm service|token[- ]overlap|word[- ]overlap|bert ?score|readab|flesch|"
                       r"reading ease|grade level", re.I)
GOV_DECIMAL = re.compile(r"(?<![\d.v])(\d+\.\d+)(?![\d.])")
GOV_OF = re.compile(r"\b(\d+) of (?:the |our )?(\d+)\b")


def _intervals(d, skip=("previous",)):
    """Every stored 90% interval in headline.json (keys ending in _90), except the `previous` model's block."""
    found = []
    if isinstance(d, dict):
        for k, v in d.items():
            if k in skip:
                continue
            if k.endswith("_90") and isinstance(v, list) and len(v) == 2:
                found.append(v)
            else:
                found += _intervals(v, skip)
    return found


def expected(out=OUT) -> dict:
    import pandas as pd
    h = json.loads((out / "headline.json").read_text())
    from src.common import primary
    pf = primary.files(out_dir=out)
    lk = pd.read_csv(pf["leakage"])
    leak = {m: dict(zip(lk.loc[lk["model"] == m, "replica"].astype(int), lk.loc[lk["model"] == m, "hits"].astype(int)))
            for m in ("honest", "leaky")}
    fwd = h.get("forward_train2024_test2025", {})
    stab = h.get("stability_train2025_test2024", {})
    pooled_rng = (h.get("pooled", {}).get("diff_cve_level_90") or h.get("diff_vs_baseline_cve_level_90"))
    e = {
        "pooled": (h["pooled_hits_bag"], h["baseline_pooled_hits"]),
        "forward": (fwd.get("bag_hits"), fwd.get("baseline_hits")),
        "stability": (stab.get("bag_hits"), stab.get("baseline_hits")),
        "ranges": {tuple(int(round(x)) for x in r) for r in [pooled_rng, fwd.get("diff_cve_level_90"), *_intervals(h)] if r},
        "honest": sum(leak["honest"].values()), "leaky": sum(leak["leaky"].values()),
        "leaky_split": (leak["leaky"].get(2025), leak["leaky"].get(2024)),
    }
    ey = out / "extra_year_eval.csv"
    if ey.exists():
        row = pd.read_csv(ey).set_index("method").loc["v6"]
        eyd = pd.read_csv(ey).set_index("method")
        simple = eyd[eyd.index.str.startswith("simple rule")].iloc[0]
        e["extra_year"] = {"hits": int(row["hits"]), "positives": int(row["positives"]), "simple_hits": int(simple["hits"]),
                           "k": int(row["k"]), "pool": int(row["pool"]), "lift": float(row["lift_vs_chance"])}
    gs = out / "explanations_summary.json"
    if gs.exists():
        e["guardian"] = json.loads(gs.read_text())
    es = out / "entire_summary.json"
    if es.exists():
        e["entire"] = json.loads(es.read_text())
    e["entire_machines"] = {p.stem.removeprefix("entire_summary_"): json.loads(p.read_text())
                            for p in sorted(out.glob("entire_summary_*.json"))}
    for kind, name in GOV_SUMMARIES.items():
        if (out / name).exists():
            e[kind] = json.loads((out / name).read_text())
    bs = pf["blindspots"]
    if bs.exists():
        b = pd.read_csv(bs)
        e["blind"] = (int(b.loc[b["group"] == "blind-spot", "exploited"].sum()), int(b["exploited"].sum()))
        e["blind_ours"] = int(b.loc[b["group"] == "blind-spot", "ours_caught"].sum())
        e["blind_rule"] = int(b.loc[b["group"] == "blind-spot", "baseline_caught"].sum())
    if (out / "discovery_workload.csv").exists():
        e["findings"] = discovery_values(out, e)
    zoo = out / "zoo_summary.md"
    if zoo.exists():
        sets = [int(x) for x in re.findall(r"^\| I \| \d+-\d+ \| \d+ \| \d+ \| (\d+) \|", zoo.read_text(), re.M)]
        if sets:
            e["seed_sets"] = (min(sets), max(sets))
    readme = ROOT / "README.md"
    if readme.exists():
        m = re.search(r"train_v6`? took (\d+) min", readme.read_text())
        if m:
            e["rebuild_minutes"] = int(m.group(1))
    return e


def _search_int(path: Path, pattern: str) -> tuple[int, ...]:
    m = re.search(pattern, path.read_text())
    if not m:
        raise SystemExit(f"number sweep: {path.name} no longer has the text it is read from: {pattern}")
    return tuple(int(x.replace(",", "")) for x in m.groups())


def discovery_values(out: Path, e: dict) -> dict:
    """The values behind docs/findings.md, each read from its source file."""
    import pandas as pd
    sev = pd.read_csv(out / "discovery_kev_severity.csv").set_index("year").loc["total"]
    w = pd.read_csv(out / "discovery_workload.csv")
    pooled = w[w["test_pool"] == "pooled"].set_index("method")
    meth = {"fortres": "fortres (v6)", "usual": "usual rule (public code, then EPSS)", "epss": "EPSS only (within-month rank)",
            "severity": "severity (CVSS 3 score)"}
    work = {k: int(pooled.loc[v, "fixes_to_match"]) for k, v in meth.items()}
    work["fortres_list"], work["fortres_depth"] = int(pooled.loc[meth["fortres"], "k"]), work.pop("fortres")
    ev = pd.read_csv(out / "discovery_events.csv")
    cv = pd.read_csv(out / "rank_vendor_cv.csv")
    cvh = {(int(r.replica), r.scheme.startswith("vendor")): int(r.oof_hits_top_k) for r in cv.itertuples()}
    g = e.get("guardian", {})
    top_fail = next(iter(g.get("local_check_failures", {}).items()), (None, None))
    jump = pd.read_csv(out / "discovery_epss_jump.csv")["jump_factor_from_2026_07"].iloc[0]
    h = json.loads((out / "headline.json").read_text())
    return {
        "kev_medium": (int(sev["Medium"]), int(sev["entries"])), "one_in": round(int(sev["entries"]) / int(sev["Medium"])),
        "workload": work, "events": len(ev), "largest_event": int(ev["n_cves"].max()),
        "vendor_cv": (cvh[2025, False], cvh[2025, True]), "vendor_cv_2024": (cvh[2024, False], cvh[2024, True]),
        "guardian_rejected": g.get("guardian_verdicts", {}).get("Yes"), "local_failed": g.get("guardian_verdicts", {}).get("not_run"),
        "top_failure": top_fail, "epss_jump": float(jump),
        "msf": _search_int(out / "newdata_provenance.md", r"\*\*(\d+) of the (\d+)\*\* pool CVE"),
        "vulncheck": _search_int(out / "outside_report.md", r"\*\*([\d,]+) of ([\d,]+)\*\* entries"),
        "min_leaf": h["final_params"]["min_child_samples"], "trees": h["final_params"]["n_estimators"],
        "template_rows": _search_int(out / "newdata_report.md", r"only about (\d+) practice")[0],
        "analyzed_rest": _search_int(out.parent / "docs" / "column_review.md", r"against (\d+)% \(2024\) and (\d+)% \(2025\)"),
        "variants": 7 if "seven declared variants" in h["primary"] else None,
        "extra_methods": len(set(re.findall(r"\bm\d\d\b", _tie_break_line(out / "zoo_summary.md")))),
        "scoreboard": sum(1 for _ in (out / "v6_scores.csv").open()) - 1, "picks": 500,
        "seeds": h["seeds"]["bag_seeds"], "event_range": tuple(int(x) for x in h["pooled"]["diff_event_clustered_90"]),
        "cve_range": tuple(int(x) for x in h["pooled"]["diff_cve_level_90"]),
    }


def _tie_break_line(path: Path) -> str:
    return next(l for l in path.read_text().splitlines() if l.lstrip("- ").startswith("Tie-break"))


def files(root=ROOT):
    pats = ["docs/*.md", "site/index.html", "site/fortres.js", "site/demo.html", "site/demo.js", "site/data/demo.json", "app/*.py", "README.md"]
    for p in pats:
        yield from sorted(root.glob(p))


def check_text(rel: str, text: str, e: dict) -> list[str]:
    probs = []
    final = rel in FINAL_DOCS
    pairs = {tuple(e[k]) for k in ("pooled", "forward", "stability") if None not in e[k]}
    for n, line in enumerate(text.splitlines(), 1):
        where = f"{rel}:{n}"
        low = line.lower()
        # 1. banned words (but not when the line is stating the rule: never "verified")
        for m in re.finditer(r"\bverified\b|\bpredicts\b|\bdetects\b|\bproves\b|\bguarantees\b|uses (?:ibm )?granite to read each description", low):
            if not re.search(r"(never|not)\W{0,4}$", low[:m.start()]):
                probs.append(f"{where}: banned wording '{m.group(0)}'")
        # 2. stale numbers
        if re.search(r"\b23\s*(?:to|→)\s*30\b", line):
            probs.append(f"{where}: stale '23 to 30'")
        leak_line = re.search(r"leak|after-the-fact|banned column|cheat", low)
        if leak_line and re.search(r"\b29\b", line) and not re.search(r"v4", low):
            probs.append(f"{where}: 29 used as the leaky number (only allowed as 'the earlier v4 run')")
        # 3. leaky claims
        if leak_line:
            for m in re.finditer(r"\bfrom (\d+) to (\d+)\b|\b(\d+)\s*→\s*(\d+)\b", line):
                a, b = [int(x) for x in m.groups() if x is not None][:2]
                if a == e["honest"] and b != e["leaky"]:
                    probs.append(f"{where}: leaky claim {a}→{b}, expected {e['honest']}→{e['leaky']}")
            for m in re.finditer(r"\b(\d+) \((\d+) \+ (\d+)\)", line):
                tot, x, y = map(int, m.groups())
                if tot == e["leaky"] or (x, y) == e["leaky_split"]:
                    if (tot, (x, y)) != (e["leaky"], e["leaky_split"]):
                        probs.append(f"{where}: leaky split {m.group(0)}, expected {e['leaky']} {e['leaky_split']}")
        # 13. Entire counts wherever Entire is mentioned
        if "entire" in low and "entire" in e:
            for m in re.finditer(r"\b(\d[\d,]*) (?:entire )?checkpoints?\b", low):
                if int(m.group(1).replace(",", "")) != e["entire"].get("n_checkpoints"):
                    probs.append(f"{where}: {m.group(1)} checkpoints, outputs/entire_summary.json has n_checkpoints = {e['entire'].get('n_checkpoints')}")
            for m in re.finditer(r"\b(\d[\d,]*) (?:claude code )?sessions?\b", low):
                if int(m.group(1).replace(",", "")) != e["entire"].get("n_sessions"):
                    probs.append(f"{where}: {m.group(1)} sessions, outputs/entire_summary.json has n_sessions = {e['entire'].get('n_sessions')}")
        if not final:
            continue
        # 4. result pairs against the simple rule / baseline
        if re.search(r"rule|baseline|simple", low):
            for m in re.finditer(r"\b(\d+) (?:vs\.?|to|against) (\d+)\b", line):
                pr = (int(m.group(1)), int(m.group(2)))
                if pr not in pairs and pr[::-1] not in pairs:
                    probs.append(f"{where}: result pair {pr} is not a headline pair {sorted(pairs)}")
        # 5. 90% ranges
        if "90%" in line or "range" in low:
            for m in re.finditer(rf"({MINUS}\d+) to \+(\d+)|\[({MINUS}?\d+), \+?(\d+)\]", line):
                g = [x for x in m.groups() if x is not None]
                rng = (int(g[0].replace("−", "-")), int(g[1]))
                if rng not in e["ranges"]:
                    probs.append(f"{where}: range {rng} is not a headline range {sorted(e['ranges'])}")
        # 6. blind spots
        if "blind" in low and "blind" in e:
            for m in re.finditer(r"\b(\d+) of (?:the )?(\d+)\b", line):
                pr = (int(m.group(1)), int(m.group(2)))
                if pr[1] == e["blind"][1] and pr != e["blind"]:
                    probs.append(f"{where}: blind-spot claim {pr}, expected {e['blind']}")
        # 7. Guardian counts in prose must equal the summary
        for m in re.finditer(r"\b(\d+) of 500\b[^.]{0,60}\bpass", low):
            g = e.get("guardian")
            if g is None:
                probs.append(f"{where}: Guardian count without outputs/explanations_summary.json to check it against")
            elif int(m.group(1)) != g.get("passed_guardian"):
                probs.append(f"{where}: Guardian count {m.group(1)} of 500, expected passed_guardian = {g.get('passed_guardian')}")
        # 14. the 2023 back-test: "N of M" on a line about the older year must be v6's hits and positives from outputs/extra_year_eval.csv
        ey = e.get("extra_year")
        if ey is not None and "older year" in low and "2023" in low:
            ok_pairs = {(ey["hits"], ey["positives"])}
            if "simple_hits" in ey:
                ok_pairs |= {(ey["simple_hits"], ey["positives"]), (ey["k"], ey["pool"])}
            for m in re.finditer(r"\b(\d+) of (\d[\d,]*)\b", line):
                if (int(m.group(1)), int(m.group(2).replace(",", ""))) not in ok_pairs:
                    probs.append(f"{where}: 2023 back-test claim {m.group(0)}, outputs/extra_year_eval.csv has {ey['hits']} of {ey['positives']}")
        # 17. percentages keep their raw count, and the count comes from its source file
        for m in re.finditer(r"(?<!than )(?<!under )(\d+)% (?:of [^()]{0,60})?\((\d+) of (\d[\d,]*)\)", line):
            pct, a, b = int(m.group(1)), int(m.group(2)), int(m.group(3).replace(",", ""))
            if int(100 * a / b + 0.5) != pct:
                probs.append(f"{where}: {m.group(0)}, but {a} of {b} is {100 * a / b:.1f}%")
            s0 = max(line.rfind(". ", 0, m.start()), -1) + 1
            s1 = line.find(". ", m.end())
            sent = line[s0:s1 if s1 >= 0 else len(line)].lower()
            ey = e.get("extra_year")
            if ey is not None and "simple_hits" in ey and ("older year" in low and "2023" in low):
                want = (ey["simple_hits"] if "usual rule" in sent else ey["hits"], ey["positives"])
                src = "outputs/extra_year_eval.csv"
            elif "blind" in e and "no warning" in sent:
                want, src = e["blind"], "the blind-spot file"
            elif "blind" in e and "usual rule" in sent:
                want, src = (e["pooled"][1], e["blind"][1]), "outputs/headline.json (baseline_pooled_hits)"
            elif "blind" in e and "fortres" in sent:
                want, src = (e["pooled"][0], e["blind"][1]), "outputs/headline.json (pooled_hits_bag)"
            else:
                continue
            if (a, b) != tuple(want):
                probs.append(f"{where}: {m.group(0)}, {src} has {want[0]} of {want[1]}")
        for m in re.finditer(r"from (\d+)% to (\d+)% of [^()]{0,60}\((\d+) to (\d+) of (\d+)\)", line):
            p1, p2, a, b, n = (int(x) for x in m.groups())
            if (a, b) != (e["honest"], e["leaky"]) or ("blind" in e and n != e["blind"][1]):
                probs.append(f"{where}: {m.group(0)}, the leakage files have {e['honest']} to {e['leaky']} of {e['blind'][1] if 'blind' in e else n}")
            if (int(100 * a / n + 0.5), int(100 * b / n + 0.5)) != (p1, p2):
                probs.append(f"{where}: {m.group(0)}, but {a} and {b} of {n} are {100 * a / n:.1f}% and {100 * b / n:.1f}%")
        wk = (e.get("findings") or {}).get("workload")
        if wk:
            for m in re.finditer(r"about (\d+(?:\.\d+)?) times the work", low):
                if abs(float(m.group(1)) - wk["usual"] / wk["fortres_list"]) >= 0.1:
                    probs.append(f"{where}: {m.group(0)}, outputs/discovery_workload.csv gives {wk['usual']} / {wk['fortres_list']} = {wk['usual'] / wk['fortres_list']:.2f}")
            for m in re.finditer(r"flagging (?:less than|under) 1% of all holes \((\d+) of (\d[\d,]*)\)", low):
                k, n = int(m.group(1)), int(m.group(2).replace(",", ""))
                want_k = e["extra_year"]["k"] if ("older year" in low and "2023" in low and "k" in e.get("extra_year", {})) else wk["fortres_list"]
                if k != want_k or k / n >= 0.01:
                    probs.append(f"{where}: {m.group(0)}, the flagged list has {want_k} and must be under 1% of the pool")
        if "usual rule caught none of them" in low and e.get("blind_rule") not in (None, 0):
            probs.append(f"{where}: 'usual rule caught none', the blind-spot file has {e['blind_rule']}")
        ey = e.get("extra_year")
        if ey is not None and "lift" in ey:
            for m in re.finditer(r"about (\d+) times better than random", low):
                if int(m.group(1)) not in (int(ey["lift"]), int(ey["lift"] + 0.5)):
                    probs.append(f"{where}: {m.group(0)}, outputs/extra_year_eval.csv lift_vs_chance is {ey['lift']}")
        if e.get("rebuild_minutes") is not None:
            for m in re.finditer(r"in about (\d+) minutes", low):
                if int(m.group(1)) != e["rebuild_minutes"]:
                    probs.append(f"{where}: {m.group(0)}, README.md says train_v6 took {e['rebuild_minutes']} min")
        # 9. leftover TODO markers
        if "TODO(" in line:
            probs.append(f"{where}: leftover TODO( marker")
        # 10. other explanation counts in prose
        g = e.get("guardian")
        if g is not None and re.search(r"reason|explanation|guardian|template", low):
            for m in re.finditer(r"\b(\d+)\b[^\d.;:]{0,30}?\btemplates?\b", low):
                if int(m.group(1)) != g.get("template_fallback"):
                    probs.append(f"{where}: template count {m.group(1)}, expected template_fallback = {g.get('template_fallback')}")
            for m in re.finditer(r"\b(\d+)\b[^\d.;:]{0,20}?\bpending\b", low):
                if int(m.group(1)) != g.get("pending"):
                    probs.append(f"{where}: pending count {m.group(1)}, expected pending = {g.get('pending')}")
    if rel == MODEL_CARD:
        probs += check_guardian_table(rel, text, e)
    if rel == ENTIRE_DOC:
        probs += check_entire_doc(rel, text, e.get("entire"), e.get("entire_machines", {}))
    probs += check_gov_numbers(rel, text, e)
    if rel == "site/index.html":
        probs += check_ai_band(rel, text, e)
        probs += check_fair_card(rel, text, e)
    if "findings" in e and final:
        probs += check_findings(rel, text, e)
    return probs


def check_ai_band(rel: str, text: str, e: dict) -> list[str]:
    """Rule 18: the findings band id="f-ai" is read as plain text (tags and the chart's aria-label included)."""
    m = re.search(r'<section[^>]*id="f-ai".*?</section>', text, re.S)
    if not m:
        return []
    g, w = e.get("guardian"), e.get("watsonx_gov")
    if g is None or w is None:
        return [f"{rel}: the AI band needs outputs/explanations_summary.json and outputs/watsonx_gov_summary.json"]
    raw = m.group(0)
    s = " ".join(re.sub(r"<[^>]+>", " ", raw).split())
    probs, v = [], g["guardian_verdicts"]
    mets = {x["column"]: x for x in w["metrics"]}
    faith, harm, pii = mets["faithfulness__granite_guardian"], mets["harm__granite_guardian"], mets["output_pii"]

    def need(pattern, want, src, text_=s):
        for mm in re.finditer(pattern, text_, re.I):
            if str(mm.group(1)) != str(want):
                probs.append(f"{rel}: AI band says '{mm.group(0)}', {src} is {want}")
    for mm in re.finditer(r"(\d+)% \((\d+) of (\d+)\)", s):
        if (int(mm.group(2)), int(mm.group(3)), int(100 * g["template_fallback"] / g["total"] + 0.5)) != (g["template_fallback"], g["total"], int(mm.group(1))):
            probs.append(f"{rel}: AI band says '{mm.group(0)}', outputs/explanations_summary.json has template_fallback {g['template_fallback']} of {g['total']}")
    need(r"reason for each of our (\d+) picks", g["total"], "total")
    need(r"rejected (\d+) drafts", v["not_run"], "guardian_verdicts.not_run")
    need(r"blocked (\d+) more", v["Yes"], "guardian_verdicts.Yes")
    need(r"those (\d+) picks show a plain", g["template_fallback"], "template_fallback")
    need(r"scored all (\d+) final reasons", w["rows"]["n"], "watsonx_gov_summary.json rows.n")
    need(r"on average (\d\.\d\d) for staying true", f"{faith['mean']:.2f}", "the mean faithfulness")
    need(r"(\d+) kept, \d+ rejected by our own rules, \d+ blocked", g["passed_guardian"], "passed_guardian", raw)
    need(r"\d+ kept, (\d+) rejected by our own rules, \d+ blocked", v["not_run"], "guardian_verdicts.not_run", raw)
    need(r"\d+ kept, \d+ rejected by our own rules, (\d+) blocked", v["Yes"], "guardian_verdicts.Yes", raw)
    if "none flagged for harm or personal data" in s and (harm["n_ge_0_5"], pii["n_ge_0_5"]) != (0, 0):
        probs.append(f"{rel}: AI band says none flagged, watsonx_gov_summary.json has harm {harm['n_ge_0_5']} and pii {pii['n_ge_0_5']} at 0.5 or above")
    for bad in ("passed watsonx", "verified", "validated", "proves"):
        if bad in s.lower():
            probs.append(f"{rel}: AI band uses '{bad}'")
    return probs


def check_fair_card(rel: str, text: str, e: dict) -> list[str]:
    """Rule 19: the '27 not 33' card says percentages only, each one computed from its source."""
    m = re.search(r'<section class="step" data-s="trust">.*?</section>', text, re.S)
    if not m:
        return []
    s = " ".join(re.sub(r"<[^>]+>", " ", m.group(0)).split())
    if "blind" not in e or "seed_sets" not in e or "extra_year" not in e or "simple_hits" not in e["extra_year"]:
        return [f"{rel}: the fair card needs outputs/headline.json, the leakage files, outputs/zoo_summary.md and outputs/extra_year_eval.csv"]
    total, ey = e["blind"][1], e["extra_year"]
    pct = lambda n, d: int(100 * n / d + 0.5)
    honest, leaky = pct(e["honest"], total), pct(e["leaky"], total)
    lo, hi = pct(e["seed_sets"][0], total), pct(e["seed_sets"][1], total)
    probs = []
    for pat, want, what in ((r"(\d+)% not (\d+)%", (honest, leaky), "honest and leaky out of 75"),
                            (r"claimed (\d+)%\. We claim (\d+)%", (leaky, honest), "leaky and honest out of 75"),
                            (r"from (\d+)% to (\d+)%", (honest, leaky), "honest and leaky out of 75"),
                            (r"(\d+)% to (\d+)% every time", (lo, hi), "the lowest and highest seed set out of 75"),
                            (r"caught (\d+)% and the usual rule caught (\d+)%", (pct(ey["hits"], ey["positives"]), pct(ey["simple_hits"], ey["positives"])), "v6 and the usual rule out of 22")):
        for mm in re.finditer(pat, s):
            if (int(mm.group(1)), int(mm.group(2))) != want:
                probs.append(f"{rel}: fair card says '{mm.group(0)}', {what} gives {want[0]}% and {want[1]}%")
    for mm in re.finditer(r"(?<![\d.,])(27|33|26|28)(?![\d%.,])|\b[45] of 22\b", s):
        probs.append(f"{rel}: fair card shows the raw count '{mm.group(0)}'; it is percentages only")
    return probs


def _n(s: str) -> int:
    return int(s.replace(",", ""))


NUM = r"(\d[\d,]*\d|\d)"
WORKLOAD_LABELS = {"usual": r"usual rule", "severity": r"(?:by |for )?severity", "epss": r"epss(?: alone| only)?"}


def check_findings(rel: str, text: str, e: dict) -> list[str]:
    """Rule 14 on every final document, rule 15 on docs/findings.md and rule 16 on the documents that carry the definition."""
    f, probs = e["findings"], []
    for n, line in enumerate(text.splitlines(), 1):
        where, low = f"{rel}:{n}", line.lower()
        if "medium" in low:
            for m in re.finditer(rf"\b{NUM} of {NUM}\b", line):
                if (_n(m.group(1)), _n(m.group(2))) != f["kev_medium"] and _n(m.group(2)) > 1000:
                    probs.append(f"{where}: Medium claim {m.group(0)}, outputs/discovery_kev_severity.csv has {f['kev_medium']}")
            for m in re.finditer(r"\b1 in (\d+)\b", line):
                if int(m.group(1)) != f["one_in"]:
                    probs.append(f"{where}: {m.group(0)}, the Medium share is 1 in {f['one_in']}")
        if re.search(r"(?:catch|reach) the same", low) or re.search(r"\bfixes\b", low):             # each workload number must sit with its own method
            for key, label in WORKLOAD_LABELS.items():
                for clause in re.split(r",\s|;| and (?=epss|sorting|the usual)", low):
                    m = re.search(rf"{label}\b[^.\d]{{0,25}}?{NUM}\b", clause) or re.search(rf"\b{NUM} \(?(?:fixes )?(?:for )?{label}\b", clause)
                    if m and _n(m.group(1)) >= 100 and _n(m.group(1)) != f["workload"][key]:
                        probs.append(f"{where}: workload for {key} is {m.group(1)}, outputs/discovery_workload.csv has {f['workload'][key]:,}")
            for m in re.finditer(rf"fortres(?:'s list of| needs)? {NUM}\b|list of (?:only )?{NUM} fixes", low):
                if _n(m.group(1) or m.group(2)) not in (f["workload"]["fortres_list"], f["workload"]["fortres_depth"]):
                    probs.append(f"{where}: fortres workload {m.group(1) or m.group(2)}, expected {f['workload']['fortres_list']}")
        if "metasploit" in low and "30 days" in low:
            for m in re.finditer(rf"\b{NUM} of (?:the )?{NUM}\b", line):
                if (_n(m.group(1)), _n(m.group(2))) not in (f["msf"], f["vulncheck"]):
                    probs.append(f"{where}: Metasploit claim {m.group(0)}, outputs/newdata_provenance.md has {f['msf']}")
        if "vendor" in low and re.search(r"holding out|hold out|held out|hiding whole", low):
            for m in re.finditer(r"\b(\d+) (?:catches )?(?:to|→) (\d+)\b", line):
                if (int(m.group(1)), int(m.group(2))) not in (f["vendor_cv"], f["vendor_cv_2024"]):
                    probs.append(f"{where}: vendor hold-out {m.group(0)}, outputs/rank_vendor_cv.csv has {f['vendor_cv']}")
        if "75" in line:
            for m in re.finditer(r"\b(\d+) (?:separate |distinct |kev )?events\b", low):
                if int(m.group(1)) != f["events"]:
                    probs.append(f"{where}: {m.group(1)} events, outputs/discovery_events.csv has {f['events']}")
        for pat, key, src in ((r"guardian rejected (\d+)", "guardian_rejected", "guardian_verdicts.Yes"),
                              (r"(\d+) rejected by guardian", "guardian_rejected", "guardian_verdicts.Yes"),
                              (r"(\d+) (?:more )?failed (?:our own|local)", "local_failed", "guardian_verdicts.not_run"),
                              (r"own checks stopped (\d+)", "local_failed", "guardian_verdicts.not_run")):
            for m in re.finditer(pat, low):
                if int(m.group(1)) != f[key]:
                    probs.append(f"{where}: {m.group(0)}, outputs/explanations_summary.json {src} is {f[key]}")
        if "blind_ours" in e and re.search(r"no warning|blind|of the 44|(?<![\d,])44 of", low):
            for m in re.finditer(r"fortres (?:caught|found) (\d+)(?![\d%])", low):
                if int(m.group(1)) != e["blind_ours"]:
                    probs.append(f"{where}: {m.group(0)}, the blind-spot file has {e['blind_ours']}")
        if "epss" in low and re.search(r"jump|2024 to 2025 median", low):
            for m in re.finditer(r"(\d+(?:\.\d+)?) ?(?:×|x\b|times)", low):
                k = len(m.group(1).split(".")[1]) if "." in m.group(1) else 0
                if float(m.group(1)) != round(f["epss_jump"], k):
                    probs.append(f"{where}: EPSS jump {m.group(0)}, outputs/discovery_epss_jump.csv has {f['epss_jump']}")
    for n, line in enumerate(text.splitlines(), 1):                     # the ranking's size, wherever it is described
        for m in re.finditer(r"\b(\d+) models that vote\b[^.]*?\b(\d+) small decision trees\b", line):
            if (int(m.group(1)), int(m.group(2))) != (f["seeds"], f["trees"]):
                probs.append(f"{rel}:{n}: {m.group(0)}, outputs/headline.json has {f['seeds']} models of {f['trees']} trees")
    needs_definition = rel in DEFINITION_DOCS or (rel == "site/index.html" and "what we found" in text.lower())
    if needs_definition and DEFINITION.format(**f) not in " ".join(text.split()):
        probs.append(f"{rel}: the one-sentence definition of fortres is missing or has been reworded")
    if rel == FINDINGS_DOC:
        probs += check_findings_numbers(rel, text, e)
    return probs


FINDINGS_TOKEN = re.compile(r"(?<![\w.#/-])(\d+\.\d+|\d[\d,]*\d|\d)(?![\w-])")
FINDINGS_YEARS = {2010, 2021, 2024, 2025, 2026}   # the years the findings talk about


def findings_allowed(e: dict) -> set[float]:
    """Every value docs/findings.md may state; each comes from a source file (the years and the 30-day cut-off are stated in them)."""
    f = e["findings"]
    w = f["workload"]
    leak = (e["honest"], e["leaky"])
    return {float(x) for x in (*FINDINGS_YEARS, *e["blind"], e["blind_ours"], *f["kev_medium"], f["one_in"], *leak, *f["analyzed_rest"],
                               *f["msf"], *f["vulncheck"], 30, f["variants"], f["extra_methods"], f["min_leaf"], f["template_rows"], *f["vendor_cv"],
                               *f["vendor_cv_2024"], f["events"], f["largest_event"], *e["pooled"], e["pooled"][0] - e["pooled"][1],
                               *f["event_range"], *f["cve_range"], f["guardian_rejected"], f["local_failed"],
                               f["guardian_rejected"] + f["local_failed"], f["top_failure"][1], *w.values(), f["epss_jump"],
                               f["scoreboard"], f["picks"], f["seeds"], f["trees"], e["guardian"]["total"], 1, 0)}


def check_findings_numbers(rel: str, text: str, e: dict) -> list[str]:
    allowed, probs = findings_allowed(e), []
    prose = re.sub(r"(?m)^(#+\s*)\d+\.\s", r"\1", _strip_entire_prose(text))
    prose = re.sub(r"Granite \d\.\d|CVSS \d|CVE-\d+-\d+", " ", prose)          # names, not results
    for n, line in enumerate(prose.splitlines(), 1):
        for tok in FINDINGS_TOKEN.findall(line):
            if float(tok.replace(",", "")) not in allowed:
                probs.append(f"{rel}: the number {tok!r} is not in any of the findings' source files (fix it, or add its source to the sweep)")
    return probs


def _gov_values(summary: dict) -> tuple[set, set, set]:
    """(decimals, counts, totals) a summary supports: per-metric mean/median/min/max/mean_by_source; n, n_ge_0_5 and the
    rest; the row totals."""
    dec, cnt = set(), set()
    rows = summary.get("rows", {})
    tot = {v for v in (rows.get("n"), rows.get("requested")) if isinstance(v, int)}
    cnt |= tot | {v for v in rows.get("by_source", {}).values() if isinstance(v, int)}
    for m in summary.get("metrics", []):
        dec |= {float(m[k]) for k in ("mean", "median", "min", "max") if isinstance(m.get(k), (int, float))}
        dec |= {float(v) for v in m.get("mean_by_source", {}).values() if isinstance(v, (int, float))}
        n = m.get("n")
        if isinstance(n, int):
            cnt.add(n)
            if isinstance(m.get("n_ge_0_5"), int):
                cnt |= {m["n_ge_0_5"], n - m["n_ge_0_5"]}
    return dec, cnt, tot


def _gov_clauses(line: str):
    """Sentences / clauses: split on ';' and on a '.' followed by a space or the end (not inside 0.81 or watsonx.governance)."""
    return [c for c in re.split(r";|\.(?=\s|$)", line) if c.strip()]


def check_gov_numbers(rel: str, text: str, e: dict) -> list[str]:
    probs = []
    for n, line in enumerate(text.splitlines(), 1):
        if not GOV_NAME.search(line):
            continue
        for clause in _gov_clauses(line):
            if not GOV_NAME.search(clause):
                continue
            kind = "gov_local" if GOV_LOCAL.search(clause) else "watsonx_gov"
            nums = [m.group(1) for m in GOV_DECIMAL.finditer(clause)]
            pairs = [(int(a), int(b)) for a, b in GOV_OF.findall(clause)]
            if not nums and not pairs:
                continue
            fname = "outputs/" + GOV_SUMMARIES[kind]
            label = "hosted watsonx.governance" if kind == "watsonx_gov" else "local SDK"
            if kind not in e:
                probs.append(f"{rel}:{n}: {label} number(s) {nums + [f'{a} of {b}' for a, b in pairs]} without {fname}")
                continue
            dec, cnt, tot = _gov_values(e[kind])
            for x in nums:
                k = len(x.split(".")[1])
                if not any(round(v, k) == float(x) for v in dec):
                    probs.append(f"{rel}:{n}: {label} number {x} is not in {fname}")
            for a, b in pairs:
                if b not in tot or a not in cnt:
                    probs.append(f"{rel}:{n}: {label} claim '{a} of {b}' is not in {fname} (rows {sorted(tot)})")
    return probs


def gov_summary_problems(e: dict) -> list[str]:
    probs = []
    w = e.get("watsonx_gov")
    if w is not None and "hosted on IBM watsonx.governance" not in w.get("claim", ""):
        probs.append("outputs/watsonx_gov_summary.json: claim must say 'hosted on IBM watsonx.governance'")
    loc = e.get("gov_local")
    if loc is not None and "hosted" in loc.get("claim", "").lower():
        probs.append("outputs/gov_metrics_summary.json: the local claim must not say 'hosted'")
    return probs


def _field(summary: dict, name: str):
    v = summary
    for part in name.split("."):
        if not isinstance(v, dict) or part not in v:
            return None
        v = v[part]
    return v


def check_guardian_table(rel: str, text: str, e: dict) -> list[str]:
    """Rows like  | label | 347 | `passed_guardian`, `guardian_verdicts.No` |  must match every named summary field."""
    probs = []
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\|[^|]*\|\s*(\d[\d,]*)\s*\|([^|]*`[^|]*)\|\s*$", line)
        if not m:
            continue
        fields = re.findall(r"`([A-Za-z_][\w.]*)`", m.group(2))
        if not fields:
            continue
        g = e.get("guardian")
        if g is None:
            probs.append(f"{rel}:{n}: Guardian table row without outputs/explanations_summary.json to check it against")
            continue
        val = int(m.group(1).replace(",", ""))
        for f in fields:
            want = _field(g, f)
            if want is None:
                probs.append(f"{rel}:{n}: Guardian table names `{f}`, which is not in outputs/explanations_summary.json")
            elif val != want:
                probs.append(f"{rel}:{n}: Guardian table says {val} for `{f}`, summary has {want}")
    return probs


def _numbers_in(summary: dict) -> set[int]:
    """Every integer stored anywhere in the summary (booleans are not numbers)."""
    found = set()
    if isinstance(summary, dict):
        for v in summary.values():
            found |= _numbers_in(v)
    elif isinstance(summary, list):
        for v in summary:
            found |= _numbers_in(v)
    elif isinstance(summary, int) and not isinstance(summary, bool):
        found.add(summary)
    return found


def _dates_in(summary: dict) -> set[str]:
    """Every YYYY-MM-DD that appears as a key or as the start of a stored timestamp."""
    found = set()
    if isinstance(summary, dict):
        for k, v in summary.items():
            found |= set(re.findall(r"\d{4}-\d\d-\d\d", str(k))) | _dates_in(v)
    elif isinstance(summary, str):
        found |= set(re.findall(r"\d{4}-\d\d-\d\d", summary))
    return found


def _strip_entire_prose(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.S)                  # fenced code blocks
    text = re.sub(r"`[^`\n]*`", " ", text)                              # inline code spans
    text = re.sub(r"\]\([^)]*\)", "]", text)                             # link targets
    text = re.sub(r"https?://\S+", " ", text)                           # bare URLs
    return re.sub(r"(?m)^\s*(?:#+\s*)?\d+[.)]\s", " ", text)            # list numbers and numbered headings


ENTIRE_TOKEN = re.compile(r"(?<![\w.#/-])(\d{4}-\d\d-\d\dT[\d:]+Z|\d{4}-\d\d-\d\d|\d+\.\d+\.\d+|\d[\d,]*)(?![\w-])")


def check_entire_doc(rel: str, text: str, summary: dict | None, machines: dict | None = None) -> list[str]:
    """docs/entire.md: table rows tie a number to a named field (`label:field` = that machine's own summary file); every other
    number in the prose must be a value in one of the summaries."""
    if summary is None:
        return [f"{rel}: this document needs outputs/entire_summary.json to check its numbers against"]
    machines = machines or {}
    probs = []
    for n, line in enumerate(text.splitlines(), 1):                    # rows like  | label | 30 | `n_checkpoints` |
        m = re.match(r"^\|[^|]*\|\s*(\d[\d,]*)\s*\|([^|]*`[^|]*)\|\s*$", line)
        if not m:
            continue
        for f in re.findall(r"`((?:[a-z0-9][a-z0-9_-]*:)?[A-Za-z_][\w.\-]*)`", m.group(2)):
            label, _, name = f.rpartition(":")
            src, fname = (machines.get(label), f"outputs/entire_summary_{label}.json") if label else (summary, "outputs/entire_summary.json")
            if src is None:
                probs.append(f"{rel}:{n}: table names `{f}`, but {fname} is missing")
                continue
            want = _field(src, name)
            if want is None:
                probs.append(f"{rel}:{n}: table names `{name}`, which is not in {fname}")
            elif int(m.group(1).replace(",", "")) != want:
                probs.append(f"{rel}:{n}: table says {m.group(1)} for `{f}`, {fname} has {want}")
    every = [summary, *machines.values()]
    allowed_ints = set().union(*(_numbers_in(s) for s in every))
    allowed_dates = set().union(*(_dates_in(s) for s in every))
    stamps = {s.get(k) for s in every for k in ("generated_at", "first_checkpoint_at", "last_checkpoint_at")}
    for n, line in enumerate(_strip_entire_prose(text).splitlines(), 1):
        for tok in ENTIRE_TOKEN.findall(line):
            if re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:]+Z", tok):
                ok = tok in stamps
            elif re.fullmatch(r"\d{4}-\d\d-\d\d", tok):
                ok = tok in allowed_dates
            elif tok.count(".") == 2:
                ok = tok in {s.get("entire_version") for s in every}
            else:
                ok = int(tok.replace(",", "")) in allowed_ints
            if not ok:
                probs.append(f"{rel}: the number {tok!r} in the prose is not in outputs/entire_summary.json (write it in words, in a code span, or fix it)")
    return probs


def main(root=ROOT) -> int:
    e = expected(root / "outputs")
    probs = gov_summary_problems(e)
    for f in files(root):
        probs += check_text(str(f.relative_to(root)), f.read_text(errors="ignore"), e)
    shown = {k: (sorted(v) if isinstance(v, set) else v) for k, v in e.items() if k not in ("extra_year", "guardian", "entire", "entire_machines", "findings", *GOV_SUMMARIES)}
    shown["gov_summaries"] = sorted(k for k in GOV_SUMMARIES if k in e)
    if "guardian" in e:
        shown["passed_guardian"] = e["guardian"].get("passed_guardian")
    if "entire" in e:
        shown["entire"] = [e["entire"].get("n_checkpoints"), e["entire"].get("n_sessions")]
    print(f"number sweep: expected {json.dumps(shown)}")
    if probs:
        print(f"{len(probs)} problem(s):")
        print("\n".join("  " + p for p in probs))
        return 1
    print("number sweep: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
