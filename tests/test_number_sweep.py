import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import number_sweep as ns  # noqa: E402

E = {"pooled": (21, 19), "forward": (12, 13), "stability": (9, 6), "ranges": {(-4, 8), (-6, 3)},
     "honest": 21, "leaky": 28, "leaky_split": (17, 11), "blind": (44, 75),
     "guardian": {"total": 500, "passed_guardian": 347, "template_fallback": 153, "pending": 0,
                  "guardian_verdicts": {"No": 347, "Yes": 78, "not_run": 75}}}
FINAL = "docs/writeup_person_b.md"


@pytest.mark.parametrize("line,needle", [
    ("Guardian verified every reason.", "banned wording"),
    ("The model predicts which CVEs get exploited.", "banned wording"),
    ("Our model uses IBM Granite to read each description.", "banned wording"),
    ("The leakage test jumps from 23 to 30.", "stale '23 to 30'"),
    ("With banned columns the leaky arm gets 29.", "29 used as the leaky number"),
    ("Leakage: pooled hits jump from 21 to 30.", "leaky claim"),
    ("Leakage arm 28 (17 + 12).", "leaky split"),
    ("We caught 22 vs 19 for the simple rule.", "result pair"),
    ("Our edge is +2, 90% range −5 to +8.", "range"),
    ("43 of the 75 were blind spots.", "blind-spot claim"),
    ("419 of 500 reasons passed a groundedness check.", "Guardian count 419"),
])
def test_each_problem_is_caught(line, needle):
    probs = ns.check_text(FINAL, line, E)
    assert any(needle in p for p in probs), probs


@pytest.mark.parametrize("line", [
    'Guardian reasons "passed a groundedness check", never "verified".',
    "Leaky arm 28 (17 + 11); 29 was the earlier v4 run.",
    "Leakage: pooled hits jump from 21 to 28.",
    "We caught 21 vs 19 for the best simple rule; forward 12 vs 13; stability 9 vs 6.",
    "Pooled +2, 90% range −4 to +8; forward −6 to +3.",
    "44 of the 75 were blind spots.",
    "The 2026 list has 72,670 CVEs; KEV as of 2025-12-29.",
    "347 of 500 reasons passed a groundedness check.",
])
def test_correct_lines_pass(line):
    assert ns.check_text(FINAL, line, E) == []


def test_research_notes_may_quote_other_results():
    # considered_not_adopted.md is not a final document: a 15 vs 13 blend result there is fine
    assert ns.check_text("docs/considered_not_adopted.md", "The blend caught 15 vs 13 for the simple rule.", E) == []


@pytest.mark.skipif(not (ns.OUT / "headline.json").exists() or not (ns.OUT / "v6_leakage_results.csv").exists(),
                    reason="needs the tracked outputs")
def test_the_repository_passes_the_sweep():
    assert ns.main() == 0


def test_guardian_prose_needs_the_summary():
    e = {k: v for k, v in E.items() if k != "guardian"}
    probs = ns.check_text(FINAL, "347 of 500 reasons passed a groundedness check.", e)
    assert any("without outputs/explanations_summary.json" in p for p in probs), probs


CARD = "docs/model_card.md"
GOOD_TABLE = """| item | count | field |
|---|---|---|
| CVEs with a reason | 500 | `total` |
| Granite sentences kept (Guardian answered "No") | 347 | `passed_guardian`, `guardian_verdicts.No` |
| of those: Guardian answered "Yes" | 78 | `guardian_verdicts.Yes` |
| rows still pending | 0 | `pending` |"""


def test_model_card_table_matches_the_summary():
    assert ns.check_text(CARD, GOOD_TABLE, E) == []


@pytest.mark.parametrize("row,needle", [
    ('| Granite sentences kept | 350 | `passed_guardian`, `guardian_verdicts.No` |', "says 350 for `passed_guardian`"),
    ('| of those: Guardian answered "Yes" | 79 | `guardian_verdicts.Yes` |', "says 79 for `guardian_verdicts.Yes`"),
    ('| something new | 5 | `no_such_field` |', "not in outputs/explanations_summary.json"),
])
def test_model_card_table_errors(row, needle):
    probs = ns.check_text(CARD, row, E)
    assert any(needle in p for p in probs), probs


def test_table_check_only_applies_to_the_model_card():
    row = '| Granite sentences kept | 350 | `passed_guardian` |'
    assert ns.check_text("docs/considered_not_adopted.md", row, E) == []


# ---- docs/entire.md: every number must come from outputs/entire_summary.json -------------------------------------------------
ENT = {"generated_at": "2026-11-08T06:42:18Z", "entire_version": "0.13.1", "n_checkpoints": 30, "n_sessions": 2,
       "first_checkpoint_at": "2026-11-07T18:44:05Z", "last_checkpoint_at": "2026-11-08T06:01:26Z",
       "checkpoints_by_day": {"2026-11-07": 21, "2026-11-08": 9}, "agents": ["Claude Code"], "push_sessions": False,
       "contains_transcripts": False, "checkpoints_by_origin": {"imported": 27, "live": 3}}
EE = {**E, "entire": ENT}
DOC = "docs/entire.md"
GOOD_ENTIRE = """# Entire

Entire CLI 0.13.1 kept 30 checkpoints from 2 sessions, first at 2026-11-07T18:44:05Z, last at 2026-11-08T06:01:26Z.
Of them 27 were imported and 3 were live; 21 fell on 2026-11-07 and 9 on 2026-11-08.

1. A numbered list marker is not a number.
2. Code is skipped: `git log -n 5`, and links such as [the docs](https://example.org/a/1234/page).

```
entire --version   # 999 inside a code block is skipped
```

| item | count | field |
|---|---|---|
| checkpoints | 30 | `n_checkpoints` |
| sessions | 2 | `n_sessions` |
| on the first day | 21 | `checkpoints_by_day.2026-11-07` |
| imported | 27 | `checkpoints_by_origin.imported` |
"""


def test_a_correct_entire_doc_passes():
    assert ns.check_text(DOC, GOOD_ENTIRE, EE) == []


@pytest.mark.parametrize("text,needle", [
    ("| checkpoints | 31 | `n_checkpoints` |", "says 31 for `n_checkpoints`"),
    ("| first day | 20 | `checkpoints_by_day.2026-11-07` |", "says 20 for `checkpoints_by_day.2026-11-07`"),
    ("| live | 3 | `checkpoints_by_origin.nope` |", "not in outputs/entire_summary.json"),
    ("Entire kept 31 checkpoints.", "the number '31' in the prose"),
    ("Entire ran for 4 sessions.", "the number '4' in the prose"),
    ("The last one was on 2026-11-09.", "the number '2026-11-09' in the prose"),
    ("The last one was at 2026-11-08T06:01:27Z.", "in the prose"),
    ("Entire CLI 0.14.0 was used.", "the number '0.14.0' in the prose"),
    ("Counts come to 1,234 in total.", "the number '1,234' in the prose"),
])
def test_entire_doc_errors(text, needle):
    probs = ns.check_text(DOC, text, EE)
    assert any(needle in p for p in probs), probs


def test_entire_doc_needs_the_summary():
    probs = ns.check_text(DOC, "No numbers here.", E)
    assert any("needs outputs/entire_summary.json" in p for p in probs), probs


def test_entire_doc_check_applies_only_to_that_document():
    assert ns.check_text("docs/considered_not_adopted.md", "Entire kept 99 things on 2020-01-01.", EE) == []


@pytest.mark.parametrize("line,ok", [
    ("Built with Entire: 30 checkpoints from 2 sessions.", True),
    ("Built with Entire: 31 checkpoints.", False),
    ("Entire captured 3 sessions of Claude Code.", False),
    ("We ran 12 sessions of the stress test.", True),            # not about Entire: not checked
])
def test_entire_counts_on_any_line_that_mentions_entire(line, ok):
    probs = ns.check_text("README.md", line, EE)
    assert (probs == []) is ok, probs


def test_entire_count_rule_needs_no_summary_when_there_is_none():
    assert ns.check_text("README.md", "Entire has 99 checkpoints.", E) == []


def test_leftover_todo_markers_fail():
    probs = ns.check_text("docs/judge_qa.md", "Count: TODO(#35): fill from the summary.", E)
    assert any("leftover TODO( marker" in p for p in probs), probs


@pytest.mark.parametrize("line,needle", [
    ("The other 150 reasons use the plain template.", "template count 150"),
    ("Explanations: 3 rows pending.", "pending count 3"),
])
def test_explanation_counts_in_prose(line, needle):
    probs = ns.check_text(FINAL, line, E)
    assert any(needle in p for p in probs), probs


def test_correct_explanation_counts_pass():
    line = "347 of 500 reasons passed a groundedness check; the other 153 use the plain template; 0 pending."
    assert ns.check_text(FINAL, line, E) == []


ENTIRE_MAIN = {"n_checkpoints": 30, "n_sessions": 2, "entire_version": "0.13.1", "checkpoints_by_origin": {"imported": 27, "live": 3}}
ENTIRE_ABA = {"n_checkpoints": 12, "n_sessions": 1, "entire_version": "0.13.1", "checkpoints_by_origin": {"imported": 0, "live": 12}}


def test_entire_per_machine_rows_read_their_own_file():
    text = "| checkpoints, Jack's laptop | 30 | `n_checkpoints` |\n| checkpoints, Aba's laptop | 12 | `aba:n_checkpoints` |\n"
    assert ns.check_entire_doc("docs/entire.md", text, ENTIRE_MAIN, {"aba": ENTIRE_ABA}) == []


def test_entire_per_machine_row_with_the_wrong_value_fails():
    text = "| checkpoints, Aba's laptop | 30 | `aba:n_checkpoints` |\n"
    probs = ns.check_entire_doc("docs/entire.md", text, ENTIRE_MAIN, {"aba": ENTIRE_ABA})
    assert any("entire_summary_aba.json has 12" in p for p in probs), probs


def test_entire_per_machine_row_without_its_file_says_missing():
    text = "| checkpoints, Aba's laptop | 12 | `aba:n_checkpoints` |\n"
    probs = ns.check_entire_doc("docs/entire.md", text, ENTIRE_MAIN, {})
    assert any("entire_summary_aba.json is missing" in p for p in probs), probs


# ---- the findings: docs/findings.md and every final document that repeats one ----------------------------------------------
F = {"kev_medium": (162, 1484), "one_in": 9, "workload": {"usual": 1116, "epss": 10026, "severity": 6858, "fortres_list": 441, "fortres_depth": 353},
     "events": 67, "largest_event": 3, "vendor_cv": (19, 10), "vendor_cv_2024": (7, 6), "guardian_rejected": 90, "local_failed": 92,
     "top_failure": ("word not in the facts", 91), "epss_jump": 6.37, "msf": (249, 490), "vulncheck": (5803, 5809), "min_leaf": 200,
     "template_rows": 140, "analyzed_rest": (42, 50), "variants": 7, "extra_methods": 11, "scoreboard": 72670, "picks": 500, "seeds": 20,
     "event_range": (1, 15), "cve_range": (2, 14), "trees": 150}
EF = {**E, "pooled": (27, 19), "forward": (18, 13), "stability": (9, 6), "ranges": {(2, 14)}, "honest": 27, "leaky": 33, "leaky_split": (21, 12),
      "blind_ours": 5, "findings": F}
GOOD_WORK = "To catch the same 27, the usual rule needs 1,116 fixes, sorting by severity needs 6,858, and EPSS alone needs 10,026."


def test_correct_findings_lines_pass():
    for line in (GOOD_WORK, "1 in 9 entries (162 of 1,484) is rated only Medium.", "Granite Guardian rejected 90 reasons and 92 more failed our own checks.",
                 "In Metasploit, for 249 of the 490 pairs, the link was added more than 30 days after the module.",
                 "Holding out whole vendors cuts it from 19 catches to 10.", "The 75 holes come from 67 separate events."):
        assert ns.check_findings("docs/judge_qa.md", line, EF) == [], line


@pytest.mark.parametrize("line,needle", [
    ("To catch the same 27, sorting by severity needs 10,026, and EPSS alone needs 6,858.", "workload for severity"),
    ("To catch the same 27, the usual rule needs 1,200 fixes.", "workload for usual"),
    ("To reach the same 27, sorting by severity 10,026, and EPSS alone 6,858.", "workload for severity"),
    ("Fortres caught those 27 with a list of only 500 fixes.", "fortres workload 500"),
    ("EPSS scores were 7 times the 2024 to 2025 median.", "EPSS jump"),
    ("1 in 8 entries (162 of 1,484) is rated only Medium.", "the Medium share"),
    ("161 of 1,484 entries are rated only Medium.", "Medium claim"),
    ("In Metasploit, 250 of the 490 pairs were added more than 30 days later.", "Metasploit claim"),
    ("Holding out whole vendors cuts it from 19 catches to 11.", "vendor hold-out"),
    ("The 75 holes come from 60 separate events.", "60 events"),
    ("Granite Guardian rejected 91 reasons.", "guardian rejected 91"),
    ("Of the 44 with no warning, fortres caught 6.", "fortres caught 6"),
    ("EPSS jumped about 7× from July.", "EPSS jump"),
])
def test_each_findings_error_is_caught(line, needle):
    probs = ns.check_findings("docs/judge_qa.md", line, EF)
    assert any(needle in p for p in probs), probs


def test_definition_must_be_word_for_word():
    good = ns.DEFINITION.format(**F)
    assert not [p for p in ns.check_findings("README.md", good, EF) if "definition" in p]
    assert any("definition" in p for p in ns.check_findings("README.md", good.replace("triage system", "ranking system"), EF))
    assert not [p for p in ns.check_findings("site/index.html", "No section yet.", EF) if "definition" in p]
    assert any("definition" in p for p in ns.check_findings("site/index.html", "<h2>What we found</h2>", EF))


def test_findings_page_may_only_state_sourced_numbers():
    d = ns.DEFINITION.format(**F)
    assert not ns.check_findings_numbers("docs/findings.md", d + " Granite 3.3 and CVSS 4; 162 of 1,484.", EF)
    assert any("'163'" in p for p in ns.check_findings_numbers("docs/findings.md", "It was 163.", EF))


@pytest.mark.parametrize("line", ["It detects attacks.", "This proves the point.", "It guarantees a catch."])
def test_new_banned_words(line):
    assert any("banned wording" in p for p in ns.check_text(FINAL, line, E))


def test_model_size_wording_is_checked():
    assert ns.check_findings("docs/judge_qa.md", "The ranking is 20 models that vote, each built from 150 small decision trees.", EF) == []
    probs = ns.check_findings("docs/judge_qa.md", "The ranking is 20 models that vote, each built from 100 small decision trees.", EF)
    assert any("150 trees" in p for p in probs), probs


def test_the_2023_back_test_claim_is_checked():
    e = {**E, "extra_year": {"hits": 4, "positives": 22}}
    assert ns.check_text(FINAL, "On an older year the model never saw, 2023, it caught 4 of 22.", e) == []
    probs = ns.check_text(FINAL, "On an older year the model never saw, 2023, it caught 9 of 22.", e)
    assert any("2023 back-test claim" in p for p in probs), probs


# ---- rule 17: percentages carry their raw count, and the count comes from its source file ------------------------------------------
X = {**E, "pooled": (27, 19), "honest": 27, "leaky": 33, "blind": (44, 75), "blind_ours": 5, "blind_rule": 0, "rebuild_minutes": 6,
     "findings": {"workload": {"usual": 1116, "fortres_list": 441}},
     "extra_year": {"hits": 4, "positives": 22, "simple_hits": 5, "k": 144, "pool": 20969, "lift": 26.5}}
RESULT = ("In our 2024 and 2025 test, fortres caught 36% of the holes attackers later used (27 of 75), while flagging less than 1% of "
          "all holes (441 of 64,119). The usual rule (public attack code first, then EPSS) caught 25% (19 of 75).")
OLDER = ("On an older year rebuilt from public data (2023), fortres caught 18% of the exploited holes (4 of 22) while flagging under 1% of "
         "all holes (144 of 20,969), about 26 times better than random. The usual rule caught 23% (5 of 22). We report it anyway.")


@pytest.mark.parametrize("line", [
    RESULT,
    "Fortres reached those catches with 441 fixes; the usual rule needed 1,116, about 2.5 times the work.",
    "59% of exploited holes (44 of 75) gave no warning sign. The usual rule caught none of them; fortres caught 5.",
    "Using them would have raised our catch rate from 36% to 44% of exploited holes (27 to 33 of 75), a gain that would have been fake.",
    OLDER,
    "Anyone with the data can rebuild the exact same 500, byte for byte, in about 6 minutes on a laptop.",
])
def test_rule_17_correct_claims_pass(line):
    assert ns.check_text(FINAL, line, X) == []


@pytest.mark.parametrize("line,needle,env", [
    (RESULT.replace("36% of the holes attackers later used (27 of 75)", "37% of the holes attackers later used (27 of 75)"), "but 27 of 75 is 36.0%", X),
    (RESULT.replace("caught 25% (19 of 75)", "caught 27% (20 of 75)"), "outputs/headline.json (baseline_pooled_hits) has 19 of 75", X),
    (RESULT.replace("(441 of 64,119)", "(500 of 64,119)"), "the flagged list has 441", X),
    (RESULT.replace("(441 of 64,119)", "(441 of 20,000)"), "must be under 1% of the pool", X),
    ("Fortres needed 441 fixes and the usual rule 1,116, about 3 times the work.", "outputs/discovery_workload.csv gives 1116 / 441", X),
    ("59% of exploited holes (43 of 75) gave no warning sign.", "the blind-spot file has 44 of 75", X),
    ("The usual rule caught none of them; fortres caught 5.", "'usual rule caught none'", {**X, "blind_rule": 3}),
    ("It would have raised our catch rate from 36% to 45% of exploited holes (27 to 34 of 75).", "the leakage files have 27 to 33 of 75", X),
    (OLDER.replace("(4 of 22)", "(5 of 22)"), "outputs/extra_year_eval.csv has 4 of 22", X),
    (OLDER.replace("(144 of 20,969)", "(150 of 20,969)"), "the flagged list has 144", X),
    (OLDER.replace("about 26 times", "about 30 times"), "lift_vs_chance is 26.5", X),
    ("Anyone can rebuild the exact same 500 in about 10 minutes on a laptop.", "README.md says train_v6 took 6 min", X),
])
def test_rule_17_wrong_claims_are_caught(line, needle, env):
    probs = ns.check_text(FINAL, line, env)
    assert any(needle in p for p in probs), probs


def test_rule_17_percentages_without_a_known_subject_are_only_checked_for_arithmetic():
    assert ns.check_text(FINAL, "Some other group was 50% (3 of 6).", X) == []
    assert any("but 3 of 6 is 50.0%" in p for p in ns.check_text(FINAL, "Some other group was 40% (3 of 6).", X))


def test_the_definition_is_the_fix_first_wording():
    assert "to fix first, ranked by the warning signs known at the time" in ns.DEFINITION
    assert "most likely to be attacked" not in ns.DEFINITION


# ---- rule 18: the "AI explanations need checking" band of site/index.html ---------------------------------------------------------
AI = {**E, "guardian": {"total": 500, "passed_guardian": 318, "template_fallback": 182, "pending": 0,
                        "guardian_verdicts": {"No": 318, "Yes": 90, "not_run": 92}},
      "watsonx_gov": {"rows": {"n": 500}, "metrics": [
          {"column": "faithfulness__granite_guardian", "mean": 0.8011, "n_ge_0_5": 495},
          {"column": "harm__granite_guardian", "mean": 0.0, "n_ge_0_5": 0}, {"column": "output_pii", "mean": 0.0, "n_ge_0_5": 0}]}}
BAND = """<section class="fd tone-blue" id="f-ai" data-viz="reasons">
  <div class="ft"><span class="fk">06</span><span class="fbig"><b>36%</b><small>(182 of 500)</small></span>
    <h3>AI explanations need checking.</h3>
    <p>IBM Granite drafted a reason for each of our 500 picks, using only that hole's facts. Our own rules rejected 92 drafts, most often
    for using a word that isn't in the facts. IBM Granite Guardian then checked the rest against the facts and blocked 90 more. Those 182
    picks show a plain fixed sentence instead. Afterwards, IBM watsonx.governance scored all 500 final reasons: on average 0.80 for staying
    true to the facts, and none flagged for harm or personal data.</p></div>
  <figure class="fv"><div class="viz" role="img" aria-label="500 bricks, one per pick: 318 kept, 92 rejected by our own rules, 90 blocked by Granite Guardian"></div></figure>
</section>"""
SITE = "site/index.html"


def test_rule_18_the_correct_ai_band_passes():
    assert ns.check_text(SITE, BAND, AI) == []


@pytest.mark.parametrize("old,new,needle", [
    ("<b>36%</b><small>(182 of 500)</small>", "<b>37%</b><small>(182 of 500)</small>", "has template_fallback 182 of 500"),
    ("<b>36%</b><small>(182 of 500)</small>", "<b>36%</b><small>(180 of 500)</small>", "has template_fallback 182 of 500"),
    ("rejected 92 drafts", "rejected 91 drafts", "guardian_verdicts.not_run is 92"),
    ("blocked 90 more", "blocked 80 more", "guardian_verdicts.Yes is 90"),
    ("Those 182", "Those 183", "template_fallback is 182"),
    ("each of our 500 picks", "each of our 499 picks", "total is 500"),
    ("scored all 500 final", "scored all 400 final", "rows.n is 500"),
    ("on average 0.80", "on average 0.85", "the mean faithfulness is 0.80"),
    ("318 kept, 92 rejected", "320 kept, 92 rejected", "passed_guardian is 318"),
    ("92 rejected by our own rules, 90 blocked", "92 rejected by our own rules, 91 blocked", "guardian_verdicts.Yes is 90"),
    ("scored all 500 final reasons", "verified all 500 final reasons and scored all 500 final reasons", "uses 'verified'"),
    ("scored all 500 final reasons", "scored all 500 final reasons (passed watsonx)", "uses 'passed watsonx'"),
])
def test_rule_18_wrong_ai_band_is_caught(old, new, needle):
    assert old in BAND
    probs = ns.check_text(SITE, BAND.replace(old, new), AI)
    assert any(needle in p for p in probs), probs


def test_rule_18_none_flagged_needs_zero_flags_and_the_summaries():
    flagged = {**AI, "watsonx_gov": {**AI["watsonx_gov"], "metrics": [*AI["watsonx_gov"]["metrics"][:2], {"column": "output_pii", "n_ge_0_5": 2}]}}
    assert any("none flagged" in p for p in ns.check_text(SITE, BAND, flagged))
    assert any("needs outputs/explanations_summary.json" in p for p in ns.check_text(SITE, BAND, E))
    assert ns.check_text(SITE, "<section id=\"f-other\">36% (182 of 500)</section>", E) == []


# ---- rule 19: the "27 not 33" card is percentages only, each computed from its source ---------------------------------------------
CARD_X = {**X, "seed_sets": (26, 28)}
FAIR = """<section class="step" data-s="trust"><div class="card">
    <span class="num mint">36%<small>not 44%</small></span>
    <h2>We could have claimed 44%. <mark>We claim 36%.</mark></h2>
    <p>Some data only appears after a hole is attacked, like NVD marking it as reviewed. Using it would have lifted our catch rate from 36% to 44%, so we left it out. Rerun with new random seeds: 35% to 37% every time. Trained on shuffled answers, it catches almost nothing.</p>
    <p>On an older year (2023), we caught 18% and the usual rule caught 23%. We report it anyway.</p>
    <p>Anyone can rebuild the exact same 500 from our code in about 6 minutes.</p>
  </div></section>"""


def test_rule_19_the_correct_card_passes():
    assert ns.check_text(SITE, FAIR, CARD_X) == []


@pytest.mark.parametrize("old,new,needle", [
    ("36%<small>not 44%</small>", "37%<small>not 44%</small>", "gives 36% and 44%"),
    ("36%<small>not 44%</small>", "36%<small>not 45%</small>", "gives 36% and 44%"),
    ("We claim 36%", "We claim 40%", "gives 44% and 36%"),
    ("from 36% to 44%", "from 36% to 43%", "gives 36% and 44%"),
    ("35% to 37% every time", "35% to 38% every time", "the lowest and highest seed set out of 75 gives 35% and 37%"),
    ("we caught 18%", "we caught 19%", "v6 and the usual rule out of 22 gives 18% and 23%"),
    ("usual rule caught 23%", "usual rule caught 25%", "v6 and the usual rule out of 22 gives 18% and 23%"),
    ("every time.", "every time (27 of 75).", "raw count '27'"),
    ("caught 23%.", "caught 23% (5 of 22).", "raw count '5 of 22'"),
    ("in about 6 minutes", "in about 10 minutes", "README.md says train_v6 took 6 min"),
])
def test_rule_19_wrong_card_is_caught(old, new, needle):
    assert old in FAIR
    probs = ns.check_text(SITE, FAIR.replace(old, new), CARD_X)
    assert any(needle in p for p in probs), probs


def test_rule_19_needs_its_sources_and_only_applies_to_that_card():
    assert any("fair card needs" in p for p in ns.check_text(SITE, FAIR, E))
    assert ns.check_text(SITE, '<section class="step" data-s="other">36% not 44%, 27 and 33</section>', E) == []
