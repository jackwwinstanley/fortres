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
  6. "N of M" blind-spot claims must equal the v5 blind-spot totals;
  7. Guardian counts in prose ("N of 500 ... passed") must equal `passed_guardian` in outputs/explanations_summary.json
     (without that file, any such count is an error);
  8. every row of the Guardian count table in docs/model_card.md (`| item | N | `field`, ... |`) must equal each field it
     names in outputs/explanations_summary.json (dotted names such as `guardian_verdicts.No` are looked up inside objects).
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
              "docs/page_content.md", "README.md", "site/index.html"}
MINUS = "[−-]"
MODEL_CARD = "docs/model_card.md"


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
    gs = out / "explanations_summary.json"
    if gs.exists():
        e["guardian"] = json.loads(gs.read_text())
    bs = pf["blindspots"]
    if bs.exists():
        b = pd.read_csv(bs)
        e["blind"] = (int(b.loc[b["group"] == "blind-spot", "exploited"].sum()), int(b["exploited"].sum()))
    return e


def files(root=ROOT):
    pats = ["docs/*.md", "site/index.html", "site/fortres.js", "app/*.py", "README.md"]
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
        for m in re.finditer(r"\bverified\b|\bpredicts\b|uses (?:ibm )?granite to read each description", low):
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
    if rel == MODEL_CARD:
        probs += check_guardian_table(rel, text, e)
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


def main(root=ROOT) -> int:
    e = expected(root / "outputs")
    probs = []
    for f in files(root):
        probs += check_text(str(f.relative_to(root)), f.read_text(errors="ignore"), e)
    shown = {k: (sorted(v) if isinstance(v, set) else v) for k, v in e.items() if k != "guardian"}
    if "guardian" in e:
        shown["passed_guardian"] = e["guardian"].get("passed_guardian")
    print(f"number sweep: expected {json.dumps(shown)}")
    if probs:
        print(f"{len(probs)} problem(s):")
        print("\n".join("  " + p for p in probs))
        return 1
    print("number sweep: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
