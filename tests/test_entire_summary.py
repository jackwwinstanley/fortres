"""scripts/entire_summary.py: counts and timestamps only, from a FAKE temporary git repo (never the real checkpoints)."""
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import entire_summary as es  # noqa: E402

NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
# strings a transcript, a prompt, a commit message or a path could carry; none may ever reach the JSON
POISON = ["/Users/someone/project/file.py", "someone@gmail.com", "someone@uwaterloo.ca", "C:\\Users\\someone", "secret prompt text"]
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}


def git(repo, *args, stdin=None, date=None):
    env = dict(ENV)
    if date:
        env["GIT_COMMITTER_DATE"] = date
    r = subprocess.run(["git", "-C", str(repo), *args], input=stdin, capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def blob(repo, text):
    return git(repo, "hash-object", "-w", "--stdin", stdin=text)


def tree(repo, entries):
    return git(repo, "mktree", stdin="".join(f"{mode} {kind} {sha}\t{name}\n" for mode, kind, sha, name in entries))


def add_checkpoint(repo, cid, sessions, imported=False, commit_date="2026-11-08T01:00:00-05:00", garble=False):
    """sessions: list of (session_id, created_at, agent). The tree has Entire's layout plus poisoned prompt/transcript files."""
    session_trees = []
    for i, (sid, created, agent) in enumerate(sessions):
        meta = {"session_id": sid, "created_at": created, "agent": agent, "files_touched": [POISON[0]], "model": "m"}
        entries = [("100644", "blob", blob(repo, "{ not json" if garble else json.dumps(meta)), "metadata.json"),
                   ("100644", "blob", blob(repo, json.dumps({"role": "user", "text": POISON[4], "who": POISON[1]})), "full.jsonl"),
                   ("100644", "blob", blob(repo, " ".join(POISON)), "prompt.txt"),
                   ("100644", "blob", blob(repo, POISON[2]), "transcript.jsonl")]
        session_trees.append(("040000", "tree", tree(repo, entries), str(i)))
    root = {"checkpoint_id": cid, "sessions": [{"metadata": f"{i}/metadata.json"} for i in range(len(sessions))],
            "strategy": "import" if imported else "manual-commit", "files_touched": POISON}
    if imported:
        root["imported"] = True
    t = tree(repo, [("100644", "blob", blob(repo, json.dumps(root)), "metadata.json"), *session_trees])
    commit = git(repo, "commit-tree", t, "-m", f"{POISON[3]} {POISON[1]}", date=commit_date)
    git(repo, "update-ref", f"refs/entire/checkpoints/{cid[:2]}/{cid}", commit)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".entire").mkdir()
    (tmp_path / ".entire" / "settings.local.json").write_text(json.dumps({"enabled": True, "strategy_options": {"push_sessions": False}}))
    add_checkpoint(tmp_path, "AA00000000000000000000000A", [("s1", "2026-11-07T23:30:00.123Z", "Claude Code")], imported=True)
    add_checkpoint(tmp_path, "BB00000000000000000000000B", [("s1", "2026-11-08T00:10:00Z", "Claude Code"), ("s2", "2026-11-08T03:00:00+02:00", "Claude Code")])
    add_checkpoint(tmp_path, "CC00000000000000000000000C", [("s2", "2026-11-08T06:00:00.999999Z", "Claude Code")])
    return tmp_path


def run(repo, out=None):
    out = out or repo / "outputs" / "entire_summary.json"
    code = es.main(["--repo", str(repo), "--out", str(out)], version_fn=lambda: "9.9.9", now=NOW)
    return code, out


def test_counts_and_timestamps_from_a_fake_repo(repo):
    code, out = run(repo)
    s = json.loads(out.read_text())
    assert code == 0 and list(s) == es.KEYS
    assert s["generated_at"] == "2026-11-08T12:00:00Z" and s["entire_version"] == "9.9.9"
    assert s["n_checkpoints"] == 3 and s["n_sessions"] == 2                       # s1 and s2, however many checkpoints they span
    assert s["first_checkpoint_at"] == "2026-11-07T23:30:00Z"                      # earliest session time of each checkpoint
    assert s["last_checkpoint_at"] == "2026-11-08T06:00:00Z"
    assert s["checkpoints_by_day"] == {"2026-11-07": 1, "2026-11-08": 2}           # UTC days; +02:00 input is converted (03:00+02:00 = 01:00Z)
    assert sum(s["checkpoints_by_day"].values()) == s["n_checkpoints"]
    assert s["agents"] == ["Claude Code"]
    assert s["push_sessions"] is False and s["contains_transcripts"] is False
    assert s["checkpoints_by_origin"] == {"imported": 1, "live": 2} and s["time_basis"] == "UTC" and s["n_checkpoints_unparsed"] == 0


def test_the_json_never_contains_personal_strings_or_any_path(repo):
    """Fails if the file contains /Users/, an at-sign, gmail, uwaterloo, or any path, even though the fake repo is full of them."""
    code, out = run(repo)
    text = out.read_text()
    assert code == 0
    assert_clean(text)


def assert_clean(text):
    for bad in ("/Users/", "@", "gmail", "uwaterloo", "secret prompt", "Users"):
        assert bad not in text, bad
    assert not re.search(r"[\\/]", text), "a path separator is in the file"
    assert not re.search(r"[A-Za-z]:\\", text)


def test_the_committed_snapshot_is_clean_and_has_the_fields():
    p = ROOT / "outputs" / "entire_summary.json"
    if not p.exists():
        pytest.skip("snapshot not generated yet")
    s = json.loads(p.read_text())
    assert_clean(p.read_text())
    assert list(s) == es.KEYS and s["contains_transcripts"] is False and s["push_sessions"] is False
    assert s["n_checkpoints"] == sum(s["checkpoints_by_day"].values()) == sum(s["checkpoints_by_origin"].values())


def test_a_fresh_clone_prints_one_line_and_writes_nothing(tmp_path, capsys):
    git(tmp_path, "init", "-q")
    out = tmp_path / "outputs" / "entire_summary.json"
    assert es.main(["--repo", str(tmp_path), "--out", str(out)], version_fn=lambda: "9.9.9", now=NOW) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1 and "nothing written" in lines[0]
    assert not out.exists() and not out.parent.exists()


def test_a_snapshot_already_committed_is_left_alone_in_a_fresh_clone(tmp_path):
    git(tmp_path, "init", "-q")
    out = tmp_path / "outputs" / "entire_summary.json"
    out.parent.mkdir()
    out.write_text('{"kept": true}')
    assert es.main(["--repo", str(tmp_path), "--out", str(out)], version_fn=lambda: "1.0.0") == 0
    assert out.read_text() == '{"kept": true}'


def test_the_script_refuses_to_write_if_a_value_would_leak(repo, monkeypatch):
    monkeypatch.setattr(es, "build", lambda *a, **k: {**{k_: 0 for k_ in es.KEYS}, "entire_version": "/Users/someone/bin"})
    code, out = run(repo)
    assert code == 1 and not out.exists()


@pytest.mark.parametrize("obj,n", [({"agents": ["Claude Code"]}, 0), ({"agents": ["a/b"]}, 1), ({"x": "a@b.c"}, 1), ({"d": "C:\\Users\\x"}, 1),
                                   ({"x": "Someone-Gmail"}, 1), ({"x/y": 1}, 1), ({"ok": "2026-11-08T12:00:00Z"}, 0)])
def test_clean_problems(obj, n):
    assert len(es.clean_problems(obj)) == n


def test_an_agent_name_that_looks_like_a_path_or_address_becomes_unknown(tmp_path):
    git(tmp_path, "init", "-q")
    add_checkpoint(tmp_path, "DD00000000000000000000000D", [("s1", "2026-11-08T01:00:00Z", "someone@gmail.com/x")])
    add_checkpoint(tmp_path, "EE00000000000000000000000E", [("s2", "2026-11-08T02:00:00Z", "Claude Code")])
    s = es.build(tmp_path, "9.9.9", NOW)
    assert s["agents"] == ["Claude Code", "unknown"]
    assert es.clean_problems(s) == []


def test_a_checkpoint_that_does_not_parse_is_counted_and_reported(tmp_path):
    git(tmp_path, "init", "-q")
    add_checkpoint(tmp_path, "FF00000000000000000000000F", [("s1", "2026-11-08T01:00:00Z", "Claude Code")], garble=True,
                   commit_date="2026-11-08T04:00:00+00:00")
    s = es.build(tmp_path, "9.9.9", NOW)
    assert s["n_checkpoints"] == 1 and s["n_checkpoints_unparsed"] == 1 and s["n_sessions"] == 0
    assert s["first_checkpoint_at"] == "2026-11-08T04:00:00Z"                      # falls back to the ref commit's time
    assert es.clean_problems(s) == []


def test_push_sessions_is_read_from_the_settings_and_local_wins(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".entire").mkdir()
    assert es.push_sessions(tmp_path) is None                                      # no file: unknown, not guessed
    (tmp_path / ".entire" / "settings.json").write_text(json.dumps({"strategy_options": {"push_sessions": True}}))
    assert es.push_sessions(tmp_path) is True
    (tmp_path / ".entire" / "settings.local.json").write_text(json.dumps({"strategy_options": {"push_sessions": False}}))
    assert es.push_sessions(tmp_path) is False


def test_the_script_is_not_part_of_the_pipeline_or_the_dashboard():
    for f in [ROOT / "src" / "b" / "refresh_all.py", *sorted((ROOT / "app").glob("*.py")), *sorted((ROOT / "src").rglob("*.py"))]:
        assert "entire_summary" not in f.read_text(), f"{f.name} must not import or run entire_summary"


@pytest.mark.parametrize("dirty", ['{"x": "/Users/someone"}', '{"x": "someone@host"}', '{"x": "gmail"}', '{"x": "uwaterloo"}', '{"x": "a/b"}',
                                   '{"x": "C:\\\\dir"}', '{"x": "secret prompt text"}'])
def test_the_cleanliness_check_fails_on_dirty_text(dirty):
    with pytest.raises(AssertionError):
        assert_clean(dirty)


def test_label_writes_the_per_machine_file_in_outputs(repo):
    add_checkpoint(repo, "aa11bb22cc33", [("s1", "2026-11-08T03:00:00Z", "Claude Code")])
    assert es.main(["--repo", str(repo), "--label", "aba"], version_fn=lambda: "9.9.9", now=NOW) == 0
    out = repo / "outputs" / "entire_summary_aba.json"
    d = json.loads(out.read_text())
    assert list(d) == es.KEYS and d["n_checkpoints"] >= 1
    assert not (repo / "outputs" / "entire_summary.json").exists()      # the default file is left alone
    text = out.read_text()
    assert not any(p.lower() in text.lower() for p in POISON) and not re.search(r"[\\/@]", text)


def test_out_wins_over_label(repo, tmp_path):
    add_checkpoint(repo, "aa11bb22cc33", [("s1", "2026-11-08T03:00:00Z", "Claude Code")])
    out = tmp_path / "elsewhere.json"
    assert es.main(["--repo", str(repo), "--label", "aba", "--out", str(out)], version_fn=lambda: "9.9.9", now=NOW) == 0
    assert out.exists() and not (repo / "outputs" / "entire_summary_aba.json").exists()


@pytest.mark.parametrize("label", ["a/b", "x@y", "users", "Gmail", "../up", "", "a" * 40])
def test_a_label_that_could_leak_or_escape_is_refused(repo, label, capsys):
    add_checkpoint(repo, "aa11bb22cc33", [("s1", "2026-11-08T03:00:00Z", "Claude Code")])
    assert es.main(["--repo", str(repo), "--label", label], version_fn=lambda: "9.9.9", now=NOW) == 1
    assert "refusing the label" in capsys.readouterr().err
    assert not list((repo / "outputs").glob("entire_summary_*.json")) if (repo / "outputs").exists() else True
