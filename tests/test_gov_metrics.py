"""scripts/gov_metrics.py guards, with no network at all (sockets are patched to fail) and a fake IBM client.
Never reads any .env and never needs the SDK: it runs in the project's own environment."""
import json
import socket
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gov_metrics as gm  # noqa: E402
import number_sweep as ns  # noqa: E402

WHERE = "IBM watsonx.governance (test-instance, ca-tor, Lite plan) on IBM Cloud"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for k in ("WATSONX_APIKEY", "WATSONX_REGION", "WXG_SERVICE_INSTANCE_ID", "WXG_INSTANCE_NAME", "WATSONX_SERVER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(gm.time, "sleep", lambda s: None)


def fake_rows(n=3):
    ids = [f"CVE-2026-{i:04d}" for i in range(n)]
    return pd.DataFrame({"record_id": ids, "source": ["granite", "template", "granite"][:n] + ["granite"] * max(0, n - 3),
                         "input_text": [f"Why is {c} prioritised?" for c in ids],
                         "context": [f"{c} is a vulnerability. Fact {i}." for i, c in enumerate(ids)],
                         "generated_text": [f"Prioritised because of fact {i}." for i in range(n)],
                         "ground_truth": [f"Prioritised because fact {i}." for i in range(n)]})


@pytest.fixture
def fake_ibm(monkeypatch, tmp_path):
    """Fake rows, client and scorer. Returns the list of (metric, n_rows) calls made."""
    calls = []
    rows = {"df": fake_rows()}
    monkeypatch.setattr(gm, "build_rows", lambda out=None: rows["df"])
    monkeypatch.setattr(gm, "make_client", lambda: (object(), WHERE))

    def score(client, cls, method, df):
        calls.append((cls, len(df)))
        return {r: 0.25 + 0.1 * i for i, r in enumerate(df["record_id"])}
    monkeypatch.setattr(gm, "score_batch", score)
    return dict(calls=calls, rows=rows, out=tmp_path, cache=tmp_path / ".cache" / "gov")


def write_inputs(out: Path, ids, top_ids=None, pending=0, top_list="top500_v5.csv"):
    out.mkdir(parents=True, exist_ok=True)
    (out / "headline.json").write_text(json.dumps({"primary": "v5: test bag"}))
    pd.DataFrame({"cve_id": top_ids if top_ids is not None else ids}).to_csv(out / "top500_v5.csv", index=False)
    pd.DataFrame({"cve_id": ids, "explanation": ["x."] * len(ids), "source": ["granite"] * len(ids)}).to_csv(
        out / "explanations.csv", index=False)
    (out / "explanations_summary.json").write_text(json.dumps({"pending": pending, "top_list": top_list}))


# ---- dry run and refusals ----------------------------------------------------------------------------------------------
def test_dry_run_no_network_writes_nothing(fake_ibm, capsys):
    before = sorted(p for p in fake_ibm["out"].rglob("*"))
    write_inputs(fake_ibm["out"], list(fake_ibm["rows"]["df"]["record_id"]))
    before = sorted(fake_ibm["out"].rglob("*"))
    text = gm.dry_run("all", out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert sorted(fake_ibm["out"].rglob("*")) == before
    assert fake_ibm["calls"] == []
    assert "3 rows x 5 metrics = 15" in text and "would call IBM: 15" in text and "Lite plan" in text
    assert "inputs: OK" in text


def test_default_main_is_dry_run_on_real_files(monkeypatch, tmp_path):
    monkeypatch.setattr(gm, "CACHE", tmp_path / "cache")
    before = {p: p.stat().st_mtime for p in (ROOT / "outputs").glob("*") if p.is_file()}
    assert gm.main([]) == 0
    assert {p: p.stat().st_mtime for p in (ROOT / "outputs").glob("*") if p.is_file()} == before
    assert not (tmp_path / "cache").exists()


def test_refuses_without_both_flags(fake_ibm, monkeypatch):
    monkeypatch.setenv("WATSONX_APIKEY", "test-not-a-key")
    for argv in (["--run"], ["--check-one"], ["--confirm-spend"]):
        if argv == ["--confirm-spend"]:
            assert gm.main(argv) == 0  # no run flag: just the dry run
            continue
        with pytest.raises(SystemExit) as ex:
            gm.main(argv)
        assert ex.value.code == 2
    assert fake_ibm["calls"] == []


def test_refuses_without_credentials(fake_ibm):
    with pytest.raises(SystemExit) as ex:
        gm.main(["--run", "--confirm-spend"])
    assert ex.value.code == 2 and fake_ibm["calls"] == []


@pytest.mark.parametrize("kw,needle", [
    (dict(pending=3), "pending = 3"),
    (dict(top_ids=["CVE-2026-0000", "CVE-2026-0001", "CVE-2026-9999"]), "ids differ"),
    (dict(top_list="top500_v4.csv"), "top_list"),
])
def test_refuses_unfinished_inputs(tmp_path, kw, needle):
    write_inputs(tmp_path, ["CVE-2026-0000", "CVE-2026-0001", "CVE-2026-0002"], **kw)
    probs = gm.input_problems(tmp_path)
    assert any(needle in p for p in probs), probs


def test_main_refuses_when_inputs_not_final(fake_ibm, monkeypatch):
    monkeypatch.setenv("WATSONX_APIKEY", "test-not-a-key")
    monkeypatch.setattr(gm, "input_problems", lambda out=None: ["explanations_summary.json pending = 5, must be 0"])
    with pytest.raises(SystemExit) as ex:
        gm.main(["--run", "--confirm-spend"])
    assert ex.value.code == 2 and fake_ibm["calls"] == []


def test_real_inputs_are_final():
    assert gm.input_problems(ROOT / "outputs") == []


# ---- hosted run with a fake client -------------------------------------------------------------------------------------
def test_cache_and_resume(fake_ibm):
    r = gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert r["stopped"] is None and r["calls"] == 15
    s = json.loads((fake_ibm["out"] / "watsonx_gov_summary.json").read_text())
    assert s["rows"]["n"] == 3 and s["stopped"] is None
    fake_ibm["calls"].clear()
    r = gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])  # everything cached: no calls
    assert r["calls"] == 0 and fake_ibm["calls"] == []
    fake_ibm["rows"]["df"] = fake_rows(4)  # one new row: only it is scored
    r = gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert r["calls"] == 5 and all(n == 1 for _, n in fake_ibm["calls"])
    df = fake_rows(4)
    df.loc[0, "generated_text"] = "A changed sentence."  # a changed sentence is a new cache key
    fake_ibm["rows"]["df"] = df
    fake_ibm["calls"].clear()
    r = gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert r["calls"] == 5


def test_check_one_scores_one_row_and_writes_no_results(fake_ibm):
    r = gm.hosted("sample100", one=True, out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert r["calls"] == 5 and all(n == 1 for _, n in fake_ibm["calls"])
    assert not (fake_ibm["out"] / "watsonx_gov_summary.json").exists()


def test_quota_error_stops_cleanly(fake_ibm, monkeypatch):
    def score(client, cls, method, df):
        fake_ibm["calls"].append((cls, len(df)))
        if cls == "AnswerRelevanceMetric":
            raise RuntimeError("Status code 429: Too Many Requests. Quota exceeded for this plan.")
        return {r: 0.9 for r in df["record_id"]}
    monkeypatch.setattr(gm, "score_batch", score)
    r = gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert r["stopped"] and "quota or rate limit" in r["stopped"]
    assert [c for c, _ in fake_ibm["calls"]].count("AnswerRelevanceMetric") == 1  # no retry on quota
    assert "OutputHAPMetric" not in [c for c, _ in fake_ibm["calls"]]  # nothing after the stop
    s = json.loads((fake_ibm["out"] / "watsonx_gov_summary.json").read_text())
    assert s["stopped"] == r["stopped"] and "incomplete" in s["claim"] and s["rows"]["n"] == 0


def test_transient_errors_retried_at_most_twice(fake_ibm, monkeypatch):
    n = {"k": 0}

    def flaky(client, cls, method, df):
        n["k"] += 1
        raise ConnectionError("Connection reset by peer")
    monkeypatch.setattr(gm, "score_batch", flaky)
    r = gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    assert n["k"] == 3 and r["stopped"] and r["stopped"].startswith("error")


def test_claim_built_from_data(fake_ibm, monkeypatch):
    gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    s = json.loads((fake_ibm["out"] / "watsonx_gov_summary.json").read_text())
    assert s["claim"] == f"3 explanation sentences (2 granite, 1 template) scored with metrics hosted on {WHERE}."
    assert "hosted on IBM watsonx.governance" in s["claim"]
    other = "IBM watsonx.governance (other, us-south, Lite plan) on IBM Cloud"
    monkeypatch.setattr(gm, "make_client", lambda: (object(), other))
    fake_ibm["rows"]["df"] = fake_rows(2)
    gm.hosted("all", one=False, out=fake_ibm["out"], cache=fake_ibm["cache"])
    s = json.loads((fake_ibm["out"] / "watsonx_gov_summary.json").read_text())
    assert s["claim"].startswith("2 explanation sentences") and other in s["claim"]


def test_secrets_redacted(monkeypatch):
    monkeypatch.setenv("WATSONX_APIKEY", "abcDEF123secretKEYvalue")
    out = gm.redact("bad key abcDEF123secretKEYvalue for 12345678-1234-1234-1234-123456789abc crn:v1:bluemix:x")
    assert "secret" not in out and "12345678-" not in out and "crn:v1" not in out


def test_not_imported_anywhere_else():
    import re
    pat = re.compile(r"import\s+gov_metrics|from\s+scripts(?:\.gov_metrics|\s+import\s+[^\n]*\bgov_metrics\b)|"
                     r"scripts\.gov_metrics|['\"]gov_metrics['\"]")
    hits = [p for p in ROOT.glob("**/*.py") if ".venv" not in str(p) and p.name not in ("gov_metrics.py", "test_gov_metrics.py")
            and pat.search(p.read_text(errors="ignore"))]
    assert hits == []


# ---- number sweep: hosted and local numbers come from their own summary files ----------------------------------------
HOSTED_S = {"claim": f"100 explanation sentences (70 granite, 30 template) scored with metrics hosted on {WHERE}.",
            "rows": {"n": 100, "requested": 100, "by_source": {"granite": 70, "template": 30}},
            "metrics": [{"n": 100, "mean": 0.8079, "median": 0.8312, "min": 0.5622, "max": 0.9242, "n_ge_0_5": 100},
                        {"n": 100, "mean": 0.6524, "n_ge_0_5": 93}, {"n": 100, "mean": 0.0, "n_ge_0_5": 0}]}
BASE = {"pooled": (21, 19), "forward": (12, 13), "stability": (9, 6), "ranges": {(-4, 8), (-6, 3)}, "honest": 21, "leaky": 28,
        "leaky_split": (17, 11), "blind": (44, 75)}
LOCAL_S = {"claim": "Computed locally with the IBM watsonx.governance SDK on 500 explanation sentences.",
           "rows": {"n": 500, "by_source": {"granite": 347, "template": 153}},
           "metrics": [{"n": 500, "mean": 0.7419}, {"n": 500, "mean": 14.3627}]}


@pytest.mark.parametrize("line,e,needle", [
    ("IBM watsonx.governance rated faithfulness 0.86 on average.", {"watsonx_gov": HOSTED_S}, "number 0.86"),
    ("IBM watsonx.governance rated faithfulness 0.74 on average.", {"watsonx_gov": HOSTED_S, "gov_local": LOCAL_S},
     "number 0.74"),  # a local number in a hosted claim
    ("Computed locally with the watsonx.governance SDK: token faithfulness 0.81.", {"watsonx_gov": HOSTED_S, "gov_local": LOCAL_S},
     "local SDK number 0.81"),  # a hosted number in a local claim
    ("IBM watsonx.governance: 95 of 100 above 0.5.", {"watsonx_gov": HOSTED_S}, "'95 of 100'"),
    ("IBM watsonx.governance rated faithfulness 0.81.", {}, "without outputs/watsonx_gov_summary.json"),
])
def test_sweep_catches_gov_numbers(line, e, needle):
    probs = ns.check_text("docs/devpost_final.md", line, dict(BASE, **e))
    assert any(needle in p for p in probs), probs


@pytest.mark.parametrize("line", [
    "Hosted on IBM watsonx.governance: Granite Guardian faithfulness 0.81 on average (93 of 100 relevant).",
    "IBM watsonx.governance flagged 0 of 100 for HAP; locally the watsonx.governance SDK gave token faithfulness 0.74.",
    "Readability with the watsonx.governance SDK, run locally: grade 14.4.",
    "We use IBM watsonx.governance to audit the sentences.",
    "ibm-watsonx-gov 1.5.2 is the watsonx.governance SDK version.",
])
def test_sweep_accepts_matching_gov_numbers(line):
    assert ns.check_text("docs/devpost_final.md", line, dict(BASE, watsonx_gov=HOSTED_S, gov_local=LOCAL_S)) == []


def test_sweep_passes_without_hosted_summary_when_nothing_claimed():
    assert ns.check_text("docs/devpost_final.md", "We plan to use IBM watsonx.governance.", dict(BASE, gov_local=LOCAL_S)) == []


def test_sweep_checks_summary_claims():
    bad = dict(HOSTED_S, claim="Scored by watsonx.")
    assert ns.gov_summary_problems({"watsonx_gov": bad})
    assert ns.gov_summary_problems({"gov_local": dict(LOCAL_S, claim="hosted locally")})
    assert ns.gov_summary_problems({"watsonx_gov": HOSTED_S, "gov_local": LOCAL_S}) == []
