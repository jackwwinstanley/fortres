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
