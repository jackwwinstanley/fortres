"""Redacted evidence that Entire captured this project's AI-assisted work: counts and timestamps only.

Run:  python scripts/entire_summary.py            # writes outputs/entire_summary.json
      python scripts/entire_summary.py --out /tmp/x.json --repo /path/to/clone
      python scripts/entire_summary.py --label aba   # this machine's snapshot -> outputs/entire_summary_aba.json

Reads, with read-only git commands, Entire's local checkpoint refs (refs/entire/checkpoints/<xx>/<id>, the CLI's default
"one git ref per checkpoint" backend; see `entire configure --help`) and, from each one, only the small JSON files that list its
sessions: the session id (used to count distinct sessions, never written), the creation time and the agent name. It also reads
`strategy_options.push_sessions` from .entire/settings.json and .entire/settings.local.json (the local file wins) and runs
`entire --version`.

It never reads prompts or transcripts, and it never writes them, paths, e-mail addresses, commit messages, session ids or
checkpoint ids. Before writing, every key and string of the result is checked and the script refuses to write if one contains a
slash, a backslash, an "@" or a personal marker.

Checkpoints are local by design (push_sessions is off), so a fresh clone has none: the script then prints one line and exits 0
without writing, and the committed outputs/entire_summary.json stays as the snapshot. The layout inside a checkpoint ref is
Entire's own, written by CLI 0.13.1; a checkpoint that does not parse is still counted (its time is the ref commit's time) and is
reported in n_checkpoints_unparsed.

Not imported by src.b.refresh_all or the dashboard: this is a one-off evidence file.
"""
import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF_PREFIX = "refs/entire/checkpoints"
SETTINGS = (".entire/settings.json", ".entire/settings.local.json")   # later files override earlier ones
AGENT_OK = re.compile(r"^[A-Za-z][A-Za-z0-9 ._-]{0,39}$")
FORBIDDEN = ("users", "gmail", "uwaterloo")
LABEL_OK = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")             # personal markers (lower case) that must never reach the file
KEYS = ["generated_at", "entire_version", "n_checkpoints", "n_sessions", "first_checkpoint_at", "last_checkpoint_at",
        "checkpoints_by_day", "agents", "push_sessions", "contains_transcripts", "checkpoints_by_origin", "time_basis",
        "n_checkpoints_unparsed"]


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def _json_at(repo: Path, ref: str, path: str):
    r = _git(repo, "show", f"{ref}:{path}")
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def _utc(text: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)


def _stamp(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def checkpoint_refs(repo: Path) -> list[str]:
    r = _git(repo, "for-each-ref", "--format=%(refname)", REF_PREFIX)
    return sorted(x for x in r.stdout.split() if x) if r.returncode == 0 else []


def read_checkpoint(repo: Path, ref: str) -> dict:
    """Only counts and times: {'sessions': [ids], 'agents': [names], 'at': datetime, 'imported': bool, 'parsed': bool}."""
    commit_time = _utc(_git(repo, "log", "-1", "--format=%cI", ref).stdout.strip())
    root = _json_at(repo, ref, "metadata.json")
    out = {"sessions": [], "agents": [], "at": commit_time, "imported": False, "parsed": False}
    if not isinstance(root, dict) or not isinstance(root.get("sessions"), list):
        return out
    out["imported"] = bool(root.get("imported")) or root.get("strategy") == "import"
    times = []
    for i in range(len(root["sessions"])):
        m = _json_at(repo, ref, f"{i}/metadata.json")
        if not isinstance(m, dict):
            return out                                         # unparsed: keep the ref commit's time, no sessions
        if m.get("session_id"):
            out["sessions"].append(str(m["session_id"]))
        if isinstance(m.get("agent"), str):
            out["agents"].append(m["agent"])
        t = _utc(m.get("created_at", ""))
        if t:
            times.append(t)
    if times:
        out["at"] = min(times)
    out["parsed"] = True
    return out


def push_sessions(repo: Path):
    """strategy_options.push_sessions from Entire's settings (local file wins); None when no file sets it."""
    value = None
    for rel in SETTINGS:
        p = repo / rel
        if p.exists():
            try:
                v = json.loads(p.read_text()).get("strategy_options", {}).get("push_sessions")
            except (json.JSONDecodeError, AttributeError, OSError):
                continue
            if isinstance(v, bool):
                value = v
    return value


def entire_version() -> str:
    try:
        r = subprocess.run(["entire", "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    m = re.search(r"\d+\.\d+\.\d+", r.stdout)
    return m.group(0) if m else "unknown"


def build(repo: Path, version: str, now: datetime | None = None) -> dict | None:
    refs = checkpoint_refs(repo)
    if not refs:
        return None
    cps = [read_checkpoint(repo, r) for r in refs]
    stamps = sorted(c["at"] for c in cps if c["at"])
    sessions = {s for c in cps for s in c["sessions"]}
    agents = sorted({a for c in cps for a in c["agents"] if AGENT_OK.match(a)} | ({"unknown"} if any(
        not AGENT_OK.match(a) for c in cps for a in c["agents"]) else set()))
    by_day = Counter(_stamp(c["at"])[:10] for c in cps if c["at"])
    imported = sum(c["imported"] for c in cps)
    return {
        "generated_at": _stamp(now or datetime.now(timezone.utc)),
        "entire_version": version,
        "n_checkpoints": len(cps),
        "n_sessions": len(sessions),
        "first_checkpoint_at": _stamp(stamps[0]) if stamps else None,
        "last_checkpoint_at": _stamp(stamps[-1]) if stamps else None,
        "checkpoints_by_day": dict(sorted(by_day.items())),
        "agents": agents,
        "push_sessions": push_sessions(repo),
        "contains_transcripts": False,
        "checkpoints_by_origin": {"imported": imported, "live": len(cps) - imported},
        "time_basis": "UTC",
        "n_checkpoints_unparsed": sum(not c["parsed"] for c in cps),
    }


def clean_problems(obj, path="") -> list[str]:
    """Every key and string must be free of slashes, backslashes, '@' and personal markers (the file is public)."""
    probs = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            probs += clean_problems(str(k), f"{path}/key") + clean_problems(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for v in obj:
            probs += clean_problems(v, path)
    elif isinstance(obj, str):
        if re.search(r"[\\/@]", obj) or any(w in obj.lower() for w in FORBIDDEN):
            probs.append(f"{path or 'value'} contains a path, address or personal marker")
    return probs


def main(argv=None, version_fn=entire_version, now: datetime | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", type=Path, default=ROOT)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--label", default=None, help="machine label for a per-machine snapshot: outputs/entire_summary_<label>.json")
    a = ap.parse_args(argv)
    if a.label is not None and (not LABEL_OK.match(a.label) or clean_problems(a.label)):
        print(f"entire_summary: refusing the label {a.label!r}: use 1-31 lower-case letters, digits, '-' or '_', "
              "and no path, address or personal marker", file=sys.stderr)
        return 1
    default = f"entire_summary_{a.label}.json" if a.label else "entire_summary.json"
    out = a.out or a.repo / "outputs" / default
    summary = build(a.repo, version_fn(), now)
    if summary is None:
        print(f"entire_summary: no local Entire checkpoints ({REF_PREFIX}) in this clone, nothing written; "
              "the committed outputs/entire_summary.json stays as the snapshot.")
        return 0
    assert list(summary) == KEYS, "summary keys changed"
    problems = clean_problems(summary)
    if problems:
        print("entire_summary: refusing to write, " + "; ".join(problems), file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=1) + "\n")
    print(f"entire_summary: wrote {out.name}: {summary['n_checkpoints']} checkpoints, {summary['n_sessions']} sessions, "
          f"{summary['first_checkpoint_at']} to {summary['last_checkpoint_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
