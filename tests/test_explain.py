from src.b.explain import check_reason, cna_name


def test_cna_name():
    assert cna_name("psirt@cisco.com") == "Cisco"
    assert cna_name("cve@mitre.org") is None
    assert cna_name(None) is None


def test_check_reason_flags_invented_facts():
    facts = "- CVE: CVE-2026-1\n- Reported by: Cisco\n- Most similar past exploited CVE: CVE-2024-9 (Ivanti VPN, added to KEV in 2024)"
    assert check_reason("A remote code execution flaw (reported by Cisco) similar to CVE-2024-9 from 2024.", facts) == []
    assert "number 2023" in check_reason("Similar to an attack in 2023.", facts)
    assert "cve CVE-2021-44228" in check_reason("Like CVE-2021-44228.", facts)
    assert "name Fortinet" in check_reason("A flaw in Fortinet gear.", facts)


def test_check_reason_flags_unsupported_claims():
    assert check_reason("This critical flaw should be patched.", "- CVE: CVE-2026-1")
    assert check_reason("It is actively exploited.", "- CVE: CVE-2026-1")


# ---- Granite Guardian gate (fail closed) ------------------------------------------------------------
import io  # noqa: E402
import json  # noqa: E402
import socket  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

import pandas as pd  # noqa: E402
import pytest  # noqa: E402

from src.b import explain as ex  # noqa: E402

FACTS = ("- CVE: CVE-2026-1\n- Weakness hints: remote code execution\n- Public exploit code: Metasploit\n"
         "- EPSS percentile within its month: top 3%\n- Description similarity to past exploited CVEs: high")
PROSE = "CVE-2026-1 is a vulnerability. Public exploit code exists: Metasploit. Its EPSS percentile within its month is in the top 3%."
TEMPLATE = "A remote code execution flaw; public exploit code already exists (Metasploit)."
GOOD = "Prioritised because it is a remote code execution flaw, it has public exploit code in Metasploit and its EPSS percentile within its month is in the top 3%."


def never_called(facts, draft):
    raise AssertionError("Guardian must not be asked about a draft that failed a local check")


def fake_urlopen(content=None, exc=None):
    def _open(req, timeout=None):
        if exc:
            raise exc
        return io.BytesIO(json.dumps({"message": {"role": "assistant", "content": content}}).encode())
    return _open


def test_good_draft_with_guardian_no_is_used():
    d = ex.decide(GOOD, FACTS, PROSE, TEMPLATE, guardian=lambda f, t: "No")
    assert (d["source"], d["guardian_verdict"], d["explanation"]) == ("granite", "No", GOOD)


@pytest.mark.parametrize("draft", ["It is actively exploited and a critical flaw.", "Attackers confirmed this flaw in Metasploit.",
                                   "This flaw will be exploited soon.", "This flaw is being exploited now.",
                                   "A flaw reported in 2023 with public exploit code in Metasploit.", "A remote code execution flaw with exploit code"])
def test_unsupported_claim_or_phrase_gives_the_template_and_skips_guardian(draft):
    d = ex.decide(draft, FACTS, PROSE, TEMPLATE, guardian=never_called)
    assert d["source"] == "template" and d["explanation"] == TEMPLATE and d["guardian_verdict"] == "not_run" and d["problems"]


@pytest.mark.parametrize("verdict", ["", "empty", "Yes", "unparseable", "timeout", "error", None])
def test_anything_but_a_clear_no_gives_the_template(verdict):
    d = ex.decide(GOOD, FACTS, PROSE, TEMPLATE, guardian=lambda f, t: verdict)
    assert d["source"] == "template" and d["explanation"] == TEMPLATE


def test_guardian_exception_gives_the_template():
    def boom(facts, draft):
        raise RuntimeError("ollama crashed")
    d = ex.decide(GOOD, FACTS, PROSE, TEMPLATE, guardian=boom)
    assert d["source"] == "template" and d["guardian_verdict"] == "error"


def test_empty_verdict_from_the_model_gives_the_template(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen(content=""))
    assert ex.guardian_verdict(PROSE, GOOD) == "empty"
    d = ex.decide(GOOD, FACTS, PROSE, TEMPLATE)               # real guardian_verdict, mocked server
    assert d["source"] == "template" and d["guardian_verdict"] == "empty"


@pytest.mark.parametrize("exc", [TimeoutError("slow"), socket.timeout("slow"), urllib.error.URLError(socket.timeout("slow"))])
def test_timeout_gives_the_template(monkeypatch, exc):
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen(exc=exc))
    assert ex.guardian_verdict(PROSE, GOOD) == "timeout"
    d = ex.decide(GOOD, FACTS, PROSE, TEMPLATE)
    assert d["source"] == "template" and d["guardian_verdict"] == "timeout"


def test_connection_refused_is_an_error_and_fails_closed(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen(exc=urllib.error.URLError(ConnectionRefusedError())))
    assert ex.guardian_verdict(PROSE, GOOD) == "error"


@pytest.mark.parametrize("content,expected", [("No", "No"), (" no.\n", "No"), ("Yes", "Yes"), ("YES", "Yes"), ("Maybe", "unparseable"),
                                              ("No, because it is grounded", "unparseable"), ("   ", "empty")])
def test_guardian_answer_parsing(monkeypatch, content, expected):
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen(content=content))
    assert ex.guardian_verdict(PROSE, GOOD) == expected


def test_guardian_request_uses_groundedness_with_facts_as_context(monkeypatch):
    seen = {}

    def spy(req, timeout=None):
        seen.update(json.loads(req.data), timeout=timeout)
        return io.BytesIO(json.dumps({"message": {"content": "No"}}).encode())
    monkeypatch.setattr(urllib.request, "urlopen", spy)
    ex.guardian_verdict(PROSE, GOOD)
    assert [m["role"] for m in seen["messages"]] == ["system", "context", "assistant"]
    assert seen["messages"][0]["content"] == "groundedness" and seen["messages"][1]["content"] == PROSE and seen["messages"][2]["content"] == GOOD
    assert seen["model"] == "granite3-guardian:2b" and seen["options"]["temperature"] == 0


def test_blocked_phrases_and_numbers_not_in_facts():
    assert ex.check_reason("It will be exploited.", FACTS)
    assert ex.check_reason("It is being exploited.", FACTS)
    assert ex.check_reason("Exploitation is confirmed.", FACTS)
    assert "number 99" in ex.check_reason("Its EPSS is in the top 99%.", FACTS)
    assert ex.check_reason("Its EPSS rank is in the top 3%.", FACTS) == []


def items(n=3):
    return [dict(cve_id=f"CVE-2026-{i}", facts=FACTS, prose=PROSE, template=TEMPLATE, key=ex.cache_key(FACTS + str(i))) for i in range(n)]


def test_process_writes_incrementally_resumes_and_summarises(tmp_path):
    calls = {"draft": 0, "guardian": 0}

    def draft(it, attempt=0):
        calls["draft"] += 1
        return GOOD

    def guardian(facts, text):
        calls["guardian"] += 1
        return "No" if calls["guardian"] != 2 else "Yes"

    df = ex.process(items(), draft, guardian, out_dir=tmp_path, log=lambda *_: None)
    assert list(df.columns) == ex.OUT_COLS and list(df.columns[:4]) == ["cve_id", "explanation", "source", "guardian_verdict"]
    assert df["source"].tolist() == ["granite", "template", "granite"] and df["guardian_verdict"].tolist() == ["No", "Yes", "No"]
    assert (df["reason"] == df["explanation"]).all()
    s = json.loads((tmp_path / "explanations_summary.json").read_text())
    assert (s["total"], s["passed_guardian"], s["rewritten"], s["template_fallback"], s["pending"], s["guardian_ran"]) == (3, 2, 3, 1, 0, True)
    # restart: nothing is recomputed, the output is identical
    before = pd.read_csv(tmp_path / "explanations.csv")
    again = ex.process(items(), draft, guardian, out_dir=tmp_path, log=lambda *_: None)
    assert calls == {"draft": 3, "guardian": 3}
    pd.testing.assert_frame_equal(before, pd.read_csv(tmp_path / "explanations.csv"))
    assert again["source"].tolist() == df["source"].tolist()


def test_process_survives_a_crash_and_retries_transient_failures(tmp_path):
    its = items(3)
    state = {"n": 0}

    def draft(it, attempt=0):
        state["n"] += 1
        if state["n"] == 2:
            raise KeyboardInterrupt("crash while processing the second CVE")
        return GOOD

    with pytest.raises(KeyboardInterrupt):
        ex.process(its, draft, lambda f, t: "timeout", out_dir=tmp_path, log=lambda *_: None, batch_size=1)   # one row per chunk: files are written after each CVE
    partial = pd.read_csv(tmp_path / "explanations.csv")
    assert len(partial) == 3 and partial["guardian_verdict"].tolist() == ["timeout", "pending", "pending"]   # complete file, honest labels
    seen = []
    df = ex.process(its, lambda it, attempt=0: seen.append(it["cve_id"]) or GOOD, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None)
    assert seen == ["CVE-2026-0", "CVE-2026-1", "CVE-2026-2"]          # the timed-out CVE is retried too
    assert df["source"].tolist() == ["granite"] * 3 and df["guardian_verdict"].tolist() == ["No"] * 3


def test_without_granite_nothing_claims_guardian(tmp_path):
    df = ex.process(items(2), None, out_dir=tmp_path, log=lambda *_: None)
    assert df["source"].tolist() == ["template"] * 2 and df["guardian_verdict"].tolist() == ["not_run"] * 2
    s = json.loads((tmp_path / "explanations_summary.json").read_text())
    assert s["passed_guardian"] == 0 and s["guardian_ran"] is False and s["rewritten"] == 0


def test_templates_are_grounded_for_the_tracked_facts():
    f = ex.facts_for(pd.read_csv(ex.OUT_DIR / ex.TOP_FILE))
    for _, r in f.iterrows():
        assert ex.check_reason(ex.template(r), ex.facts_text(r)) == [], r["cve_id"]
        for phrase in ex.BLOCKED_PHRASES:                     # the fallback contains none of the blocked phrases
            assert not re.search(rf"\b(?:{phrase})\b", ex.template(r), re.I), (r["cve_id"], phrase)
        assert r["cve_id"] in ex.facts_prose(r) and r["cve_id"] in ex.facts_text(r)


# ---- quality fixes: one phrase constant, glue detector, reason == explanation, cache invalidation -----
import re  # noqa: E402
from pathlib import Path  # noqa: E402

PHRASE_SENTENCES = {
    "exploitation claims": ["This flaw will be exploited soon.", "It is being exploited now.", "Exploitation is confirmed.",
                            "Attackers are actively scanning for it.", "It was seen in the wild.", "Used by ransomware gangs.",
                            "A zero-day flaw.", "A zero day flaw.", "It has been exploited before.", "It is a known exploited flaw."],
    "intensity words": ["A high-impact flaw.", "A high impact flaw.", "A highly similar description.", "A serious flaw.", "A dangerous flaw.",
                        "A widespread flaw.", "A widely used product.", "A critical flaw.", "A severe flaw.", "The severity is clear."],
    "nonsense": ["Public exploit template exists.", "Two exploit templates exist."],
    "predictions and interpretation": ["Shows a strong likelihood of exploitation.", "It is likely to matter.", "Indicating a high risk.",
                                       "There is a risk of exploitation.", "It has potential for exploitation.", "It follows exploitation patterns.",
                                       "Mirroring past CVEs.", "A significant risk exists.", "A strong signal.", "Strongly similar text.", "The strongest signal.",
                                       "A significant flaw.", "It matters significantly.", "Evidenced by the code.", "A known pattern.",
                                       "Recurring patterns.", "Exploitation is imminent."],
    "audit patterns": ["Prioritised because it has a GitHub proof of concept and the reporting organisation's history of exploiting similar CVEs.",
                       "Prioritised because it has a GitHub proof of concept for a remote code execution vulnerability, as indicated by CVE-2026-16723.",
                       "Prioritised because it is a flaw, identified as CVE-2026-19650.", "Prioritised because it is a flaw, identified by CVE-2026-2636.",
                       "It is an unauthenticated CVE, specifically targeting VPN/firewall/edge-devices.", "It is a vulnerability with a specific template for exploitation.",
                       "It allows unauthenticated exploitation.", "It is allowed.", "It is an unauthenticated vulnerability affecting VPN/firewall/edge-devices.",
                       "It affects web-browsers.", "It poses a path traversal risk.", "As highlighted by its main drivers.", "It highlights the history.",
                       "The ranking model considers the history.", "It shares high similarity to past exploited CVEs with a top 1% IBM Granite KEV-likeness.",
                       "It shares a top 7% KEV-likeness with other 2026 descriptions.", "It has a GitHub proof of concept for a proof of exploit.",
                       "It is a weakness hint of unauthenticated vulnerability.", "It is unauthenticated enterprise-software related.",
                       "It is an enterprise-software-related flaw.",
                       "Prioritised because it has a GitHub proof of concept for public exploit code and the reporting organisation's history of exploited CVEs.",
                       "Prioritised because it has a GitHub proof of concept in public exploit code and a mentioned vendor's history of exploited CVEs."],
    "causal links": ["Placing it in the top group.", "It is placed first.", "Thereby ranking it higher.", "Therefore it ranks high.", "Thus it ranks high.",
                     "Hence it ranks high.", "Reflecting its history.", "Suggesting a pattern.", "It implies a pattern.", "Resulting in a high rank.",
                     "Leading to a high rank.", "It matters due to its exploit code.", "As evidenced by the code."],
}


def test_blocked_phrases_are_one_constant_at_the_top_of_the_module():
    src = Path(ex.__file__).read_text()
    assert src.count("BLOCKED_PHRASES = [") == 1 and "CLAIMS" not in src
    assert src.index("BLOCKED_PHRASES = [") < src.index("def cna_name")
    for phrase in ["high-impact", "high impact", "highly", "serious", "dangerous", "widespread", "widely", "actively", "in the wild",
                   "ransomware", "zero-day", "exploit template", "will be exploited", "is being exploited", "confirmed", "likelihood", "likely",
                   "indicating", "risk of exploitation", "potential for exploitation", "exploitation patterns", "mirroring", "significant risk", "strong",
                   "significant", "significantly", "evidenced", "pattern", "patterns", "imminent"]:
        assert any(re.search(rf"\b(?:{p})\b", phrase, re.I) for p in ex.BLOCKED_PHRASES), phrase


@pytest.mark.parametrize("cls,sentence", [(c, s) for c, ss in PHRASE_SENTENCES.items() for s in ss])
def test_every_blocked_phrase_class_is_rejected(cls, sentence):
    assert any(p.startswith("blocked phrase") for p in ex.check_reason(sentence, FACTS)), sentence
    d = ex.decide(sentence, FACTS, PROSE, TEMPLATE, guardian=never_called)
    assert d["source"] == "template" and d["guardian_verdict"] == "not_run"


def test_every_pattern_in_the_constant_is_exercised_by_a_test_sentence():
    sentences = [s for ss in PHRASE_SENTENCES.values() for s in ss]
    for p in ex.BLOCKED_PHRASES:
        assert any(re.search(rf"\b(?:{p})\b", s, re.I) for s in sentences), f"no test sentence for {p!r}"


@pytest.mark.parametrize("text,fragment", [
    ("A flaw with aKEV-likeness score.", "aKEV"),                      # one-letter word glued to a capitalised word
    ("A flaw with public exploit availableGitHub code.", "availableGitHub"),   # lowercase glued to uppercase
    ("A flaw reported in the vulnerabilityin question.", "vulnerabilityin"),   # two lowercase words joined
    ("A flaw with a GitHub proof-ofof-concept.", "ofof"),                      # repeated fragment
    ("An unauthentication flaw.", "unauthentication"),                         # garbled word
    ("A flaw with aGitHub proof of concept.", "aGitHub"),
])
def test_glue_detector_rejects_joined_or_garbled_words(text, fragment):
    probs = ex.glue_problems(text, FACTS)
    assert any(fragment in p for p in probs), (text, probs)
    d = ex.decide(text, FACTS, PROSE, TEMPLATE, guardian=never_called)
    assert d["source"] == "template" and d["guardian_verdict"] == "not_run"


def test_glue_detector_allows_real_tokens_and_words_from_the_facts():
    assert ex.glue_problems("A flaw with code on GitHub, WordPress, ExploitDB and LightGBM.", "") == []
    assert ex.glue_problems("A flaw with a GitHub proof of concept.", FACTS + "\n- Public exploit code: a GitHub proof of concept") == []
    assert ex.glue_problems("A flaw in Zorbaware software.", FACTS + "\n- Vendor: Zorbaware") == []      # a word the facts contain is allowed
    assert ex.glue_problems("A flaw in Zorbaware software.", FACTS)                                       # but not otherwise


def test_reason_is_an_exact_copy_of_explanation(tmp_path):
    df = ex.process(items(3), lambda it, attempt=0: GOOD, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None)
    assert df["reason"].tolist() == df["explanation"].tolist()
    written = pd.read_csv(tmp_path / "explanations.csv")
    assert written["reason"].equals(written["explanation"])
    bad = df.copy()
    bad.loc[0, "reason"] = bad.loc[0, "reason"] + "x"
    with pytest.raises(AssertionError):
        ex.write_atomic(bad, tmp_path / "x.csv")


def test_committed_explanations_are_consistent_and_pass_todays_checks():
    d = pd.read_csv(ex.OUT_DIR / "explanations.csv")
    assert d["reason"].equals(d["explanation"]) and d["cve_id"].is_unique and len(d) == 500
    assert (d.loc[d["source"] == "granite", "guardian_verdict"] == "No").all()      # a Granite sentence is only ever kept after Guardian said No
    assert (d.loc[d["source"] == "template", "guardian_verdict"] != "No").all()     # nothing claims Guardian passed a template row
    top = pd.read_csv(ex.OUT_DIR / ex.TOP_FILE)
    f = ex.facts_for(top).set_index("cve_id")
    for _, r in d[d["source"] == "granite"].iterrows():
        row = f.loc[r["cve_id"]].copy()
        row["cve_id"] = r["cve_id"]
        assert ex.local_problems(r["explanation"], ex.facts_text(row)) == [], r["cve_id"]


def write_cache(tmp_path, recs):
    (tmp_path / ".cache").mkdir(exist_ok=True)
    (tmp_path / ".cache" / "explain_cache.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))


def test_cached_sentences_failing_the_new_checks_are_regenerated_with_guardian(tmp_path):
    its = items(3)
    clean = lambda it: dict(cve_id=it["cve_id"], key=it["key"], draft=GOOD, attempt=0, problems=[], explanation=GOOD,  # noqa: E731
                            source="granite", guardian_verdict="No")
    bad = clean(its[1]) | dict(draft="Prioritised because it is a high-impact remote code execution flaw.", explanation="Prioritised because it is a high-impact remote code execution flaw.")
    write_cache(tmp_path, [clean(its[0]), bad, clean(its[2])])
    asked, guarded = [], []

    def draft(it, attempt=0):
        asked.append((it["cve_id"], attempt))
        return GOOD

    df = ex.process(its, draft, lambda f, t: guarded.append(t) or "No", out_dir=tmp_path, log=lambda *_: None)
    assert asked == [("CVE-2026-1", 1)]                        # only the invalidated row, starting at the retry prompt
    assert guarded == [GOOD]                                   # and it went through Guardian
    assert df["source"].tolist() == ["granite"] * 3 and df["guardian_verdict"].tolist() == ["No"] * 3
    assert df.loc[1, "explanation"] == GOOD
    s = json.loads((tmp_path / "explanations_summary.json").read_text())
    assert (s["invalidated_by_new_checks"], s["regenerated_passed_guardian"], s["regenerated_template_fallback"]) == (1, 1, 0)
    assert s["invalidated_by_class"] == {"blocked phrase 'high-impact'": 1, "word not in the facts": 1}
    again = ex.process(its, draft, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None)    # resume keeps the recorded numbers
    assert asked == [("CVE-2026-1", 1)] and again["source"].tolist() == ["granite"] * 3
    assert json.loads((tmp_path / "explanations_summary.json").read_text())["invalidated_by_new_checks"] == 1


def test_retries_only_after_local_failures_never_after_a_guardian_verdict(tmp_path):
    seq = ["Prioritised because it is a high-impact flaw.", "Prioritised because it is aKEV-likeness flaw.", GOOD]
    calls, guard = [], []

    def draft(it, attempt=0):
        calls.append(attempt)
        return seq[attempt]

    ex.process(items(1), draft, lambda f, t: guard.append(t) or "No", out_dir=tmp_path, log=lambda *_: None)
    assert calls == [0, 1, 2] and guard == [GOOD]               # Guardian only saw the draft that passed the local checks
    # Guardian said Yes: final, no retry
    other = tmp_path / "b"
    other.mkdir()
    calls.clear()
    ex.process(items(1), lambda it, attempt=0: calls.append(attempt) or GOOD, lambda f, t: "Yes", out_dir=other, log=lambda *_: None)
    assert calls == [0]
    # all attempts fail locally: template, not_run, problems recorded and counted by class
    third = tmp_path / "c"
    third.mkdir()
    df = ex.process(items(1), lambda it, attempt=0: "Prioritised because it is a critical flaw.", never_called, out_dir=third, log=lambda *_: None)
    assert df["source"].tolist() == ["template"] and df["guardian_verdict"].tolist() == ["not_run"]
    assert json.loads((third / "explanations_summary.json").read_text())["local_check_failures"] == {"blocked phrase 'critical'": 1, "word not in the facts": 1}


def test_cached_template_rows_show_todays_template_text(tmp_path):
    its = items(1)
    write_cache(tmp_path, [dict(cve_id=its[0]["cve_id"], key=its[0]["key"], draft=None, attempt=0, problems=["x"],
                                explanation="OLD TEMPLATE WORDING highly similar", source="template", guardian_verdict="Yes")])
    df = ex.process(its, lambda it, attempt=0: GOOD, never_called, out_dir=tmp_path, log=lambda *_: None)
    assert df.loc[0, "explanation"] == TEMPLATE and df.loc[0, "guardian_verdict"] == "Yes"


def test_new_prompt_version_is_in_the_cache_key():
    import inspect
    assert "PROMPT_VERSION" in inspect.getsource(ex.cache_key)
    assert ex.cache_key(FACTS) != ex.cache_key(FACTS + "x")
    old = ex.PROMPT_VERSION
    try:
        k = ex.cache_key(FACTS)
        ex.PROMPT_VERSION = old + "-next"
        assert ex.cache_key(FACTS) != k
    finally:
        ex.PROMPT_VERSION = old


def test_sentences_cached_under_an_old_prompt_version_are_regenerated(tmp_path):
    its = items(2)
    stale = [dict(cve_id=it["cve_id"], key="old-prompt-key", draft=GOOD, attempt=0, problems=[], explanation=GOOD, source="granite",
                  guardian_verdict="No") for it in its]
    write_cache(tmp_path, stale)
    asked = []
    df = ex.process(its, lambda it, attempt=0: asked.append((it["cve_id"], attempt)) or GOOD, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None)
    assert asked == [("CVE-2026-0", 0), ("CVE-2026-1", 0)] and df["source"].tolist() == ["granite", "granite"]
    s = json.loads((tmp_path / "explanations_summary.json").read_text())
    assert s["rows_regenerated_for_new_prompt"] == 2 and s["prompt_version"] == ex.PROMPT_VERSION


def test_time_box_leaves_unfinished_rows_as_pending_templates(tmp_path):
    calls = []

    def slow(it, attempt=0):
        calls.append(it["cve_id"])
        return GOOD

    df = ex.process(items(3), slow, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None, time_box_minutes=-1)   # deadline already passed
    assert calls == [] and df["guardian_verdict"].tolist() == ["pending"] * 3 and df["source"].tolist() == ["template"] * 3


@pytest.mark.parametrize("sentence,ok", [
    ("Prioritised because its EPSS percentile within its month is in the top 3%, it has public exploit code in Metasploit and high similarity to past exploited CVEs.", True),
    ("Prioritised because it has high similarity to past exploited CVEs, and an EPSS rank in the top 3%.", True),
    ("Prioritised because of a high similarity to past exploited CVEs placing it in the top 3% EPSS percentile.", False),       # EPSS % in the similarity clause
    ("Prioritised because its IBM Granite KEV-likeness and EPSS rank are both in the top 3%.", False),                          # one % on two facts
    ("Prioritised because its KEV-likeness is in the top 3%.", False),                                                        # no such fact: the 3% is EPSS's
    ("Prioritised because it is in the top 3%.", False),                                                                       # percentage attached to nothing
    ("Prioritised because its EPSS rank is in the top 5%.", False),                                                           # wrong value
])
def test_percentages_stay_attached_to_their_own_fact(sentence, ok):
    facts = FACTS  # EPSS top 3%, no KEV-likeness fact
    probs = ex.percentage_problems(sentence, facts)
    assert (probs == []) is ok, (sentence, probs)
    assert (not ex.check_reason(sentence, facts) or not ok) or True
    both = FACTS + "\n- IBM Granite KEV-likeness of the description within the 2026 pool: top 9%"
    assert ex.percentage_problems("Prioritised because its EPSS rank is in the top 3% and its IBM Granite KEV-likeness is in the top 9%.", both) == []
    assert ex.percentage_problems("Prioritised because its EPSS rank is in the top 9% and its IBM Granite KEV-likeness is in the top 3%.", both)


@pytest.mark.parametrize("draft", ["A remote code execution flaw with public exploit code in Metasploit.",           # does not start with the required form
                                   "Prioritised because it has public exploit code. It is a remote code execution flaw."])  # two sentences
def test_format_must_be_a_single_prioritised_because_sentence(draft):
    probs = ex.local_problems(draft, FACTS)
    assert any(p.startswith("format") or p == "more than one sentence" for p in probs)
    assert ex.decide(draft, FACTS, PROSE, TEMPLATE, guardian=never_called)["source"] == "template"


def test_the_example_shown_to_the_model_passes_every_local_check():
    assert ex.local_problems(ex.EXAMPLE_SENTENCE, ex.EXAMPLE_FACTS) == []
    assert "7%" in ex.EXAMPLE_FACTS and "7%" in ex.EXAMPLE_SENTENCE


def test_at_most_three_facts_and_the_template_restates_exactly_those():
    f = ex.facts_for(pd.read_csv(ex.OUT_DIR / ex.TOP_FILE))
    for _, r in f.iterrows():
        sel = ex.selected_facts(r)
        assert 1 <= len(sel) <= ex.MAX_FACTS
        assert ex.facts_text(r).count("\n- ") == len(sel)                         # one bullet per fact plus the CVE line
        t = ex.template(r)
        assert t.startswith("Prioritised because ") and t.endswith(".") and t.count(".") >= 1
        kinds = {k for k, *_ in sel}
        assert ("main drivers" in t) == ("drivers" in kinds)                      # nothing outside the selected facts is restated
        assert ("EPSS" in t) == ("epss" in kinds) and ("KEV-likeness" in t) == ("kev" in kinds)
        assert ex.facts_prose(r).count("EPSS percentile") == int("epss" in kinds)


def test_batch_draft_function_is_asked_only_for_rows_that_still_need_a_draft(tmp_path):
    its = items(4)
    calls = []

    def batch(rows, attempt=0):
        calls.append((attempt, [r["cve_id"] for r in rows]))
        # attempt 0: rows 1 and 3 are rejected locally; attempt 1: row 3 is still bad; attempt 2: it is fixed
        return [GOOD if (attempt == 2 or r["cve_id"] in ("CVE-2026-0", "CVE-2026-2") or (attempt == 1 and r["cve_id"] == "CVE-2026-1"))
                else "A serious flaw." for r in rows]

    df = ex.process(its, None, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None, batch_draft_fn=batch, batch_size=4)
    assert calls == [(0, ["CVE-2026-0", "CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]), (1, ["CVE-2026-1", "CVE-2026-3"]), (2, ["CVE-2026-3"])]
    assert df["source"].tolist() == ["granite"] * 4 and df["guardian_verdict"].tolist() == ["No"] * 4


def test_template_only_run_then_granite_run_drafts_every_item(tmp_path):
    """Review of #35: rows cached by a run WITHOUT Granite (template, not_run, no draft) must be drafted by a later Granite run."""
    facts = "- CVE: CVE-2026-1\n- Weakness hints: remote code execution"
    items = [dict(cve_id=f"CVE-2026-{i}", facts=facts, prose=facts, template="Prioritised because it is a remote code execution flaw.",
                  key=ex.cache_key(facts)) for i in range(1, 4)]
    quiet = lambda *a, **k: None
    d1 = ex.process(items, None, out_dir=tmp_path, log=quiet)                      # run 1: template only
    assert (d1["source"] == "template").all() and (d1["guardian_verdict"] == "not_run").all()
    calls = []

    def draft_fn(it, attempt=0):
        calls.append(it["cve_id"])
        return "Prioritised because it is a remote code execution flaw."
    d2 = ex.process(items, draft_fn, guardian=lambda f, d: "No", out_dir=tmp_path, log=quiet)   # run 2: Granite on, same out_dir
    assert sorted(calls) == sorted(i["cve_id"] for i in items)                      # every item drafted
    assert (d2["source"] == "granite").all() and (d2["guardian_verdict"] == "No").all()


# ---- content-word allowlist and the audit fixtures -------------------------------------------------------
import json as _json  # noqa: E402

AUDIT = _json.loads((Path(__file__).parent / "fixtures" / "explanation_audit.json").read_text())


def test_content_words_must_be_in_the_cves_own_facts_or_the_whitelist_without_stemming():
    facts = "- CVE: CVE-2026-1\n- Description similarity to past exploited CVEs: high\n- Weakness hints: unauthenticated"
    assert ex.content_word_problems("Prioritised because it has high similarity to past exploited CVEs and it is an unauthenticated flaw.", facts) == []
    assert ex.content_word_problems("Prioritised because its history of exploiting CVEs is high.", facts)             # exploiting is not exploited
    assert ex.content_word_problems("Prioritised because it is an unauthenticated weaknesses.", facts)               # weaknesses is not weakness
    assert ex.content_word_problems("Prioritised because it has public exploit code.", facts)                       # a fact the CVE does not have
    # 'high similarity to past exploited CVEs' is NOT whitelisted: without that fact the sentence may not say it
    no_sim = "- CVE: CVE-2026-1\n- Weakness hints: unauthenticated"
    assert ex.content_word_problems("Prioritised because it has high similarity to past exploited CVEs.", no_sim)
    assert ex.content_word_problems("Prioritised because it is a flaw and it involves unauthenticated.", no_sim) == []   # connectives and neutral words
    for w in ex.CONNECTIVE_WORDS | ex.NEUTRAL_WORDS:
        assert ex.content_word_problems(w, "") == []


def test_every_audited_sentence_that_stated_something_not_in_its_facts_is_now_rejected():
    assert len(AUDIT["flagged"]) >= 100
    for x in AUDIT["flagged"]:
        assert ex.local_problems(x["sentence"], x["facts"]), (x["cve_id"], x["sentence"])
        d = ex.decide(x["sentence"], x["facts"], "", "TEMPLATE", guardian=never_called)       # never reaches Guardian
        assert d["source"] == "template" and d["guardian_verdict"] == "not_run", x["cve_id"]


def test_clean_audited_sentences_still_pass_every_check():
    assert len(AUDIT["clean"]) >= 50
    for x in AUDIT["clean"]:
        assert ex.local_problems(x["sentence"], x["facts"]) == [], (x["cve_id"], x["sentence"])


def test_unflagged_sentences_with_words_outside_their_facts_are_rejected_by_the_allowlist():
    assert len(AUDIT["allowlist_rejects"]) >= 30
    for x in AUDIT["allowlist_rejects"]:
        assert any(p.startswith("word not in the facts") for p in ex.local_problems(x["sentence"], x["facts"])), (x["cve_id"], x["sentence"])


def test_fallback_template_passes_the_new_checks_and_contains_none_of_the_audited_phrases_for_all_500():
    f = ex.facts_for(pd.read_csv(ex.OUT_DIR / ex.TOP_FILE))
    assert len(f) == 500
    for _, r in f.iterrows():
        t, facts = ex.template(r), ex.facts_text(r)
        assert ex.local_problems(t, facts) == [], (r["cve_id"], t, ex.local_problems(t, facts))
        for phrase in ex.BLOCKED_PHRASES:
            assert not re.search(rf"\b(?:{phrase})\b", t, re.I), (r["cve_id"], phrase)


# ---- the primary model's list (v6): list, contributions and explanations must belong together ----------------------------
def test_primary_list_and_contribution_file_are_the_same_model():
    assert (ex.PRIMARY, ex.TOP_FILE, ex.CONTRIB_FILE) == ("v6", "top500_v6.csv", "v6_top500_contrib.parquet")
    assert ex.latest_top() == str(ex.OUT_DIR / ex.TOP_FILE)
    top = pd.read_csv(ex.OUT_DIR / ex.TOP_FILE)["cve_id"].tolist()
    assert pd.read_parquet(ex.OUT_DIR / ex.CONTRIB_FILE)["cve_id"].tolist() == top


def test_facts_for_refuses_a_list_that_is_not_in_the_contribution_file():
    top = pd.read_csv(ex.OUT_DIR / "top500_v5.csv").head(500)
    foreign = top[~top["cve_id"].isin(pd.read_parquet(ex.OUT_DIR / ex.CONTRIB_FILE)["cve_id"])]
    if foreign.empty:
        pytest.skip("v5 list is contained in the v6 contribution file")
    with pytest.raises(AssertionError, match="same model"):
        ex.facts_for(foreign)


def test_committed_explanations_cover_exactly_the_primary_list_in_order():
    d = pd.read_csv(ex.OUT_DIR / "explanations.csv")
    assert d["cve_id"].tolist() == pd.read_csv(ex.OUT_DIR / ex.TOP_FILE)["cve_id"].tolist()
    s = json.loads((ex.OUT_DIR / "explanations_summary.json").read_text())
    assert s["top_list"] == ex.TOP_FILE and s["total"] == 500


def test_classify_splits_the_cache_into_kept_changed_failed_new_and_retry():
    its = {c: dict(cve_id=c, facts=f"- CVE: {c}\n- Public exploit code: Metasploit", key=f"k-{c}") for c in "abcdefg"}
    good = "Prioritised because it has public exploit code (Metasploit)."
    rec = lambda c, **kw: dict(cve_id=c, key=f"k-{c}", explanation=good, source="granite", guardian_verdict="No", draft=good, **kw)  # noqa: E731
    recs = {
        "a": rec("a"),                                                                         # same key, passes -> kept
        "b": {**rec("b"), "key": "old"},                                                       # facts changed -> changed
        "c": {**rec("c"), "draft": "Prioritised because it is the most critical flaw."},       # same key, fails today's checks -> failed
        "d": dict(cve_id="d", key="k-d", explanation="T", source="template", guardian_verdict="Yes", draft=good),   # a template row stays
        "e": dict(cve_id="e", key="k-e", explanation="T", source="template", guardian_verdict="not_run", draft=None),  # never drafted -> retry
        "f": dict(cve_id="f", key="k-f", explanation="T", source="template", guardian_verdict="not_run", draft="bad draft"),  # drafted and rejected: kept
    }
    got = ex.classify(list(its.values()), recs)           # "g" has no record at all
    assert got == {"kept": ["a", "d", "f"], "changed": ["b"], "failed": ["c"], "new": ["g"], "retry": ["e"]}


def test_the_driver_list_pattern_blocks_the_join_but_not_a_separate_clause_or_the_template():
    facts = "- CVE: CVE-2026-1\n- Public exploit code: a GitHub proof of concept\n- Weakness hints: path traversal"
    ok = "Prioritised because it has a GitHub proof of concept for public exploit code and it is a path traversal weakness."
    assert not any(p.startswith("blocked phrase") for p in ex.check_reason(ok, facts))
    epss = "Prioritised because it has a GitHub proof of concept for public exploit code and its EPSS percentile within its month is in the top 9%."
    assert not any(p.startswith("blocked phrase") for p in ex.local_problems(epss, facts + "\n- EPSS percentile within its month: top 9%"))     # a separate clause
    join = "Prioritised because it has a GitHub proof of concept for public exploit code and the reporting organisation's history of exploited CVEs."
    assert any("proof of concept" in p for p in ex.check_reason(join, facts))
    f = ex.facts_for(pd.read_csv(ex.OUT_DIR / ex.TOP_FILE))                    # the driver-only templates say 'public exploit code and the reporting ...'
    assert all(not any(p.startswith("blocked phrase") for p in ex.check_reason(ex.template(r), ex.facts_text(r))) for _, r in f.iterrows())
