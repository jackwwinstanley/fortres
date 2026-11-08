# Entire demo: a 20 to 30 second screen recording

Goal: show, with read-only commands only, that Entire captured the AI-assisted work, that the captures stay on this machine, and
that nothing from Entire is on the public remote. Background and limits: `docs/entire.md`. Run it on the laptop that holds the
checkpoints (a fresh clone has none, so the first four commands would show nothing there).

## Before you record
- Use a plain prompt that hides the username and machine name: `PS1='$ '` (zsh: `PROMPT='$ '`).
- Open a new terminal window, `cd` to the repository root, run `clear`. Never record from a folder whose name shows in the prompt.
- Turn off the terminal's title bar text or crop it out, and crop out the menu bar and any Finder or home-folder window. Full paths
  and the home folder must not appear anywhere in the frame.
- Close Claude Code, chat and mail windows. Do a dry run first and read every line that appears.
- Do not enlarge the font so far that long lines wrap; the output below is short.

## The take (about twenty-five seconds; type each command, then pause for the time shown)
| step | command | what it should show | pause |
|---|---|---|---|
| 1 | `entire --version` | `Entire CLI` and a version, then a Go line and an OS line | 2 s |
| 2 | `entire agent list` | a list of agents; a check mark beside `claude-code` only | 3 s |
| 3 | `git for-each-ref --format='%(refname)' refs/entire/checkpoints \| wc -l` | one number: the count of checkpoints on this machine (it should equal `n_checkpoints` in the JSON of step 7) | 3 s |
| 4 | `grep push_sessions .entire/settings.local.json` | one line: `"push_sessions": false` | 3 s |
| 5 | `git ls-remote origin 'refs/entire/*'` | nothing at all: the remote has no Entire ref | 4 s |
| 6 | `git branch -r \| grep -i entire` | nothing at all, and the shell prompt returns | 3 s |
| 7 | `cat outputs/entire_summary.json` | the counts-and-timestamps file: no prompts, no paths, no addresses | 7 s |

Narration, one short line per step: "Entire is installed with the Claude Code hooks." "This many checkpoints are on this laptop."
"Pushing sessions is off." "The remote has none of it." "What we publish is only counts and timestamps."

## Never show
- `entire status` (it prints the opening words of each active session's latest prompt).
- `entire checkpoint list` with `--outgoing` or `--pending`, and `entire session list` or `entire session info`: the CLI says the
  first can show prompts, and the others show session details such as the worktree path and the last prompt.
- Any `git show`, `git log -p` or `cat` of something under `refs/entire/`, `.entire/` or the Claude Code settings file, and any
  `git log` of full commit messages (a commit can carry an `Entire-Checkpoint` trailer).
- The `~` or `/Users` part of any path. If a path appears by accident, delete the clip and record again.

## After
Watch the clip once with the sound off and look only for: a username, a path, an address, a prompt. If there is one, re-record.
