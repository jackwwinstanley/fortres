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
