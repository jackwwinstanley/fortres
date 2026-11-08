# Outside data, round 2: GitHub PoC dates and the EPSS daily archive (b/outside2): report for Jack

Branch `b/outside2` (off b/outside, no PR). Code `src/b/outside2.py`. Tables: `outputs/outside2_eval.csv` (results plus a run
log), `outputs/outside2_leakcheck.csv`. Data stays on Aba's laptop under `data/outside/` (gitignored, never committed):

| download | where | size |
|---|---|---|
| PoC-in-GitHub shallow clone | `data/outside/poc-in-github/` | 77 MB |
| EPSS files | `data/outside/epss/` | 93 MB (52 files: first and last day of each of the 26 snapshot months) |

Nothing in top500*, headline.json, runlog.csv, docs/, site/, app/ or README.md was touched. No list or doc was regenerated.

## Verdict: v5 stays
v5 plus both sources' features was run once:
- forward **9** vs v5's 12;
- stability **9** vs 9;
- pooled **18 vs 21** (−3, 90% range −7 to +1).

It fails the forward condition and the pooled-gain condition (≥ 2 and ≥ the noise floor of 4).

| test | v5 frozen | v5 + PoC + EPSS-change features | vs v5, 90% |
|---|---|---|---|
| forward (train 2024 → test 2025) | 12 | 9 | −3 [−7, +1] |
| stability (train 2025 → test 2024) | 9 | 9 | +0 [+0, +0] |
| pooled | 21 | 18 | −3 [−7, +1] |

## Rules fixed before any result
- **Date rule:** a record counts only if dated on or before the end of the CVE's snapshot month.
- **PoC:** only the repo `created_at` date is used, never stars, forks, pushed_at or updated_at.
  - `poc_repo_count_by_snapshot` = number of repos created by then.
  - `days_from_first_poc_to_snapshot` = days since the first repo, −1 if none. v5 has no blank cells, so a sentinel is
    used instead of a blank.
- **EPSS:**
  - N = 30 days or the whole month if shorter, which means the first day to the last day of the snapshot month.
  - `epss_pct_change_month` = the EPSS percentile on the last day minus on the first day. The percentile is a rank over
    all CVEs, so a change of EPSS model version doesn't shift the scale.
  - Scores are as published that day. A CVE not scored on day 1 gets 0.
- **Evaluation:**
  - one combined candidate, with v5's own settings and seeds 0-19;
  - adoption only if forward ≥ v5, stability ≥ v5, and pooled gain ≥ 2 and ≥ 4.

## Leak checks per source (`outputs/outside2_leakcheck.csv`)
| check | GitHub PoC (created_at) | EPSS change ≥ +0.20 percentile |
|---|---|---|
| practice positives flagged | 30 of 75 (40%) | 36 of 75 (48%) |
| practice negatives flagged | 1,138 | 11,026 |
| coverage 2024 / 2025 / 2026 | 517 / 651 / 1,523 | 5,022 / 6,040 / 23,408 |
| source date minus CISA KEV date (flagged CVEs in KEV) | min −662, median −50, max −10 days | min −511, median −48.5, max −1 days |
| mirrored entries (source date ≥ KEV date) | 0 | 0 |
| backfill signs | 1,194 CVEs whose first repo predates CVE publication (allowed, because dated before the snapshot) | none: files are stamped with their score date |
| passes the gate (flags something in 2026, < 80% of positives) | yes | yes |

## Notes
- **Overlap with v5:** about 91-94% of the CVEs flagged by PoC repo dates are already flagged by v5's own `poc_github`
  column. The correlation between the repo count and that flag is 0.34-0.45. So the PoC source mostly repeats what v5
  already knows.
- **Repos created after the snapshot:** 442 / 441 / 934 CVEs have repos only from after the snapshot. The date rule
  excludes them.
- **Deleted repos:** the clone can't show repos that were deleted later. That makes the counts low, but it doesn't leak.
- **Datathon's EPSS date:** the datathon's own EPSS column matches the archive's **last day of the month** (95% of CVEs in
  January 2024, 99% in January 2026), not the first day. So the snapshot EPSS is month-end and the change feature lines up
  with it.
- **One bug of mine:** the pooled difference in the first output read −24. The correct figure is −3 (18 vs 21). The code
  and the CSV are fixed; no re-run was needed.

## For Devpost: outside data we checked
| source | link | licence / terms | date rule | used? |
|---|---|---|---|---|
| PoC-in-GitHub | https://github.com/nomi-sec/PoC-in-GitHub | CC0-1.0 | repo created_at on or before the snapshot-month end | tested; did not help |
| EPSS daily archive | https://epss.empiricalsecurity.com (FIRST EPSS, https://www.first.org/epss) | free public data under FIRST's EPSS usage terms | score date of the daily file on or before the snapshot-month end | tested; did not help |
