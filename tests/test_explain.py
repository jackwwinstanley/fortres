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
GOOD = "A remote code execution flaw with public exploit code in Metasploit and an EPSS rank in the top 3%."


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
        ex.process(its, draft, lambda f, t: "timeout", out_dir=tmp_path, log=lambda *_: None)
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
    f = ex.facts_for(pd.read_csv(ex.OUT_DIR / "top500_v5.csv").head(40))
    for _, r in f.iterrows():
        assert ex.check_reason(ex.template(r), ex.facts_text(r)) == [], r["cve_id"]
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
}


def test_blocked_phrases_are_one_constant_at_the_top_of_the_module():
    src = Path(ex.__file__).read_text()
    assert src.count("BLOCKED_PHRASES = [") == 1 and "CLAIMS" not in src
    assert src.index("BLOCKED_PHRASES = [") < src.index("def cna_name")
    for phrase in ["high-impact", "high impact", "highly", "serious", "dangerous", "widespread", "widely", "actively", "in the wild",
                   "ransomware", "zero-day", "exploit template", "will be exploited", "is being exploited", "confirmed"]:
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
    top = pd.read_csv(ex.OUT_DIR / "top500_v5.csv")
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
    bad = clean(its[1]) | dict(draft="A high-impact remote code execution flaw.", explanation="A high-impact remote code execution flaw.")
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
    assert s["invalidated_by_class"] == {"blocked phrase 'high-impact'": 1}
    again = ex.process(its, draft, lambda f, t: "No", out_dir=tmp_path, log=lambda *_: None)    # resume keeps the recorded numbers
    assert asked == [("CVE-2026-1", 1)] and again["source"].tolist() == ["granite"] * 3
    assert json.loads((tmp_path / "explanations_summary.json").read_text())["invalidated_by_new_checks"] == 1


def test_retries_only_after_local_failures_never_after_a_guardian_verdict(tmp_path):
    seq = ["A high-impact flaw.", "It is aKEV-likeness flaw.", GOOD]
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
    df = ex.process(items(1), lambda it, attempt=0: "A critical flaw.", never_called, out_dir=third, log=lambda *_: None)
    assert df["source"].tolist() == ["template"] and df["guardian_verdict"].tolist() == ["not_run"]
    assert json.loads((third / "explanations_summary.json").read_text())["local_check_failures"] == {"blocked phrase 'critical'": 1}


def test_cached_template_rows_show_todays_template_text(tmp_path):
    its = items(1)
    write_cache(tmp_path, [dict(cve_id=its[0]["cve_id"], key=its[0]["key"], draft=None, attempt=0, problems=["x"],
                                explanation="OLD TEMPLATE WORDING highly similar", source="template", guardian_verdict="Yes")])
    df = ex.process(its, lambda it, attempt=0: GOOD, never_called, out_dir=tmp_path, log=lambda *_: None)
    assert df.loc[0, "explanation"] == TEMPLATE and df.loc[0, "guardian_verdict"] == "Yes"
