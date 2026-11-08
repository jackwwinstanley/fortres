# Built with Entire: an audit trail for AI-assisted work

This page says what Entire is, how we used it, what we publish and what we keep local. Every number in it comes from
`outputs/entire_summary.json` (counts and timestamps only; `scripts/number_sweep.py` fails if a number here drifts from that
file). The commands in "Check it yourself" are the ones we ran, word for word.

## What Entire is
Entire is a command-line tool (the CLI says "The command-line interface for Entire"; `entire enable` turns on session tracking in
a repository, and `entire agent add <name>` installs hooks for one coding agent). Its overview page describes the product as "The
Git forge for agent-human collaboration" and says the CLI captures sessions and checkpoints as the agent works: a checkpoint pairs
a code change with the prompts, responses and tool calls behind it, and commits made during an agent session are linked to
checkpoints. The CLI is open source.

How it works, as the documentation and the CLI describe it:
- **Agent hooks** collect what the coding agent did. **Git hooks** link that to a commit: a checkpoint is created on commit, and the
  commit gets an `Entire-Checkpoint` trailer (an ID; the documentation says it holds no prompt or file content).
- **Storage is your own repository.** The default backend is one git ref per checkpoint under `refs/entire/checkpoints/`
  (`entire configure --help` lists the two backends). Refs are not branches: your working branch stays clean, and `git branch -a`
  does not show them.
- **Pushing is a setting.** The documentation says checkpoint data is pushed with your git pushes only when
  `strategy_options.push_sessions` is true, which is the default. We set it to false.

Links: [overview](https://docs.entire.com/overview) (the older docs.entire.io address redirects there),
[security and privacy](https://docs.entire.com/security.md),
[capturing checkpoints](https://docs.entire.com/guides/checkpoints/capture-checkpoints.md).

## How we used it
Two people built this project in one repository, and AI coding assistants (Claude Code) were part of the workflow. A model that ranks
vulnerabilities is easy to tune by accident, so we pre-declared the evaluation protocol (`CONTRACT.md`) and
logged the results that did not work (`outputs/runlog.csv`, `docs/considered_not_adopted.md`). Entire adds a different record: for
the AI-assisted changes, which session produced a change, when, and with which agent. It is an audit trail of how the work was
done. It does not replace the protocol or the run log, and it says nothing about whether a result is right.

What the snapshot in `outputs/entire_summary.json` shows (the command that makes it is `python scripts/entire_summary.py`):

| item | count | field |
|---|---|---|
| checkpoints | 30 | `n_checkpoints` |
| distinct sessions | 2 | `n_sessions` |
| imported from earlier Claude Code history | 27 | `checkpoints_by_origin.imported` |
| captured live, on commit | 3 | `checkpoints_by_origin.live` |
| checkpoints dated 2026-11-07 (UTC) | 21 | `checkpoints_by_day.2026-11-07` |
| checkpoints dated 2026-11-08 (UTC) | 9 | `checkpoints_by_day.2026-11-08` |
| checkpoints the script could not parse | 0 | `n_checkpoints_unparsed` |

The first checkpoint is dated 2026-11-07T18:44:05Z and the last 2026-11-08T06:01:26Z; the agent is Claude Code; the CLI is version
0.13.1. We read these as follows:
- Entire was switched on part-way through the project, so most checkpoints are not live captures. Their metadata marks them as
  imports (strategy `import`); the CLI lists `entire import claude-code` ("Import existing Claude Code transcripts as local,
  read-only history") among its experimental commands, which matches. Their dates in the summary are the session times in the metadata, not the day the import ran.
- Only the live checkpoints come from the hooks firing on a commit.
- The snapshot covers one laptop's clone. Checkpoints are local, so a teammate's sessions on another machine are not in it.
- A second machine, Aba's laptop, has Entire set up the same way (push off, telemetry off, nothing pushed). Its own snapshot
  goes in `outputs/entire_summary_aba.json` (`python scripts/entire_summary.py --label aba`) once it has checkpoints, and its
  table rows name their fields as `aba:n_checkpoints` and so on, so each row is checked against that machine's own file.
- Two sessions is what Entire recorded here. It is not a count of every Claude Code window the project used.

## What is published, what is not, and why
Published in the repository: this page, `docs/entire_demo.md`, `scripts/entire_summary.py` with its tests, and
`outputs/entire_summary.json`. The JSON has counts and timestamps only. The script refuses to write a file whose keys or values
contain a slash, a backslash, an at-sign or a personal marker, and a test fails if the file ever does. It never reads prompts or
transcripts; it reads only the small metadata files that list each checkpoint's sessions.

Not published: the checkpoints themselves. They stay in `refs/entire/checkpoints/` on one laptop, `push_sessions` is false, and
the remote has no `refs/entire/*` ref (see "Check it yourself"). Entire's settings (`.entire/`) and the Claude Code hook file are
kept out of git with `.git/info/exclude`, a file that is local to the clone.

Why: the repository is public, and the documentation says that if the repository is public, so are its checkpoints. Transcripts
contain personal data. We counted with a script, without reading them, how many lines of the local checkpoint data contain a home-folder path or
an at-sign, and both occur in every checkpoint, including e-mail-shaped strings. Entire's documentation describes redaction as "a safety net rather than a guarantee", and
says its layer that redacts e-mail addresses and phone numbers is off by default. So we do not publish transcripts, checkpoint exports or prompts anywhere.

Two further facts. Commits made while Entire is on can carry an `Entire-Checkpoint` trailer; some commits on `main` do. It is an
ID only, and the documentation notes it encodes a creation time. And the CLI's usage analytics are on by default per its
documentation; we turned them off for this clone with `entire configure --telemetry=false --local`.

## Check it yourself
Read-only commands, run from the repository root, as we ran them. In a fresh clone the first group has nothing to show, because
checkpoints are not pushed; the second group is the evidence anyone can check.

On the machine that holds the checkpoints:
```
entire --version
entire agent list
git for-each-ref --format='%(refname)' refs/entire/checkpoints | wc -l
grep push_sessions .entire/settings.local.json
```
`entire --version` prints the CLI version first (then Go and OS lines). `entire agent list` marks installed agents with a check;
`claude-code` is the one that is marked. The `wc -l` line prints the checkpoint count and should equal `n_checkpoints` while the
snapshot is current. The `grep` prints `"push_sessions": false`.

From any clone:
```
git ls-remote origin 'refs/entire/*'
git branch -r | grep -i 'origin/entire/'
cat outputs/entire_summary.json
```
The first two print nothing (the `grep` also exits with status one when it finds nothing); that is the proof that no Entire data is on
the remote. The `grep` looks for Entire's own branch names (`entire/...`), so it ignores this project's branch `a/entire`. The last prints the counts above.

Avoid, when recording or sharing a screen: `entire status` (it lists active sessions with the opening words of each session's latest
prompt), and `entire checkpoint list --outgoing` (the CLI says it shows each checkpoint's first prompt).

## Limits
- This CLI version has no `rewind` command; we did not rewind or restore anything.
- Features of the CLI we did not use: trails, search, dispatch, recap and activity (activity reads from entire.io), the
  experimental review, blame, why and experts commands, summary generation (`entire checkpoint explain --generate` hands a
  redacted transcript to a summary provider), a checkpoint remote, and pushing checkpoints.
- The layout inside a checkpoint ref belongs to Entire, and `scripts/entire_summary.py` was written against the layout of the
  CLI version above. A different version may change it; the script then reports unparsed checkpoints instead of guessing.
- The snapshot is a point in time (`generated_at` in the JSON). Checkpoints made after it are not counted until the script is run
  again, and the script writes nothing in a clone that has no checkpoints.
- Entire records that AI-assisted changes happened, not that they are correct. The evaluation protocol, the tests and the
  number sweep do that job.
