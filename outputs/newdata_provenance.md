# New data, provenance audit: Nuclei templates

Written **before** any feature was built or evaluated.

- **Source:** https://github.com/projectdiscovery/nuclei-templates
- **Licence:** MIT ("Copyright (c) 2025 ProjectDiscovery, Inc."; the LICENSE file in the clone).
- **How we got it:** a FULL `git clone` (not shallow), 75870 commits, taken 2026-11-08T06:04:48Z (HEAD `7ab1c409395f`).
- **Where it is kept:** under the gitignored `data/outside/`, deleted when the experiment ends. The repository holds no template.

## What a record is
One YAML template file, which is a detection check for a vulnerability. We use only:
- **the path** (file name);
- **the CVE id**, from the file name `CVE-YYYY-N`, else the `cve-id:` field of the file at HEAD;
- **the git history of the path.**

Nothing inside the file (no `created`, disclosure or metadata field) is used for dates.

| item | count |
|---|---|
| YAML template paths ever added (history, renames followed) | 15,604 |
| still present at HEAD | 14,195 |
| with a CVE id | 4,950 |
| without a CVE id (not used) | 10,654 |
| distinct CVEs | 4,731 |
| CVEs with several templates (earliest date used) | 171 |

## Dates: point-in-time or hindsight?
There is one date column: the **author date of the commit that first added the file**. It comes from one pass of
`git log --reverse -M --name-status`, with renames followed, so a moved file keeps its first date.

**Spot check.** For 20 random CVE templates, the date equals `git log --follow --diff-filter=A` on the single file:
**20 of 20 agree**.

**Verdict: point-in-time, with two exceptions treated as missing.**
- **It is a record of when the file entered the public repository**, written by git at commit time, not a field typed later.
  The author date is the same day as the commit date for the median template; 4 CVE templates differ by
  more than 30 days, and none by more than a year.
- **Exception 1, impossible dates:** 41 template files (10 with a CVE id)
  carry an author date before the repository's first commit (for example 1970-01-01) or more than a day after their own commit.
  They are **missing**, not early.
- **Exception 2, bulk imports and restructures:** the threshold, declared before looking, is a commit that adds or renames in
  at least 100 CVE templates.
  - 2 CVE templates come from such commits; with the invalid ones, 10 CVEs have only invalid or bulk dates and count as missing.
  - The largest commits add 95, 80 and 63 CVE templates. They fall below the threshold, so they count; the per-commit list is below.
- **Caveat: deleted repos and branches.** A template that existed only on an unmerged branch is not in the history. That makes the
  counts low, but it doesn't make dates early.

Largest commits by CVE templates added:

| commit | CVE templates | date |
|---|---|---|
| `1b2fddb9cb50` | 95 | 2023-10-17 |
| `74f0e42fcbcc` | 80 | 2020-08-25 |
| `60ebe6449744` | 63 | 2021-09-27 |
| `332e19282ed4` | 35 | 2023-07-07 |
| `2666ec340109` | 29 | 2025-10-02 |

## Hindsight checks against the CISA KEV dates (practice and 2026 pools)
- **Flagged by the snapshot and in CISA KEV:** template date minus KEV date runs from −313 to −5 days, median −86.5. **0
  mirrored** (none on or after the KEV date). This follows from the as-of rule: practice positives are added to KEV after
  their snapshot month.
- **Templates dated before the CVE's publication:** 103 of the flagged CVEs (reserved CVEs); allowed, because they are dated
  before the snapshot.

## Join audit (cve_id), counted by the snapshot-month end
| pool | CVEs | any template ever | template by the snapshot end | share | datathon `nuclei` flag | both | template only after the snapshot |
|---|---|---|---|---|---|---|---|
| 2024 | 28,839 | 430 | 135 | 0.47% | 105 | 104 | 295 |
| 2025 | 35,280 | 418 | 142 | 0.40% | 109 | 109 | 276 |
| 2026 | 72,670 | 513 | 211 | 0.29% | 167 | 167 | 302 |

- **Positives flagged by the snapshot end:** 2024 7 of 27, 2025
  13 of 48, so 20 of 75 (27%), far from "nearly all".
- **Negatives flagged:** 2024 128, 2025 129.
- **Missing values:** `published` is present for every pool CVE. A CVE without a dated template gets 0 / −1 / 0. Nothing is
  dropped. NIST review status is not used.
- **Overlap:** the datathon's own `nuclei` flag (already in v5/v6) is almost a subset of the new flag. The new source adds about
  30 CVEs per pool whose template is dated by the snapshot end but which the datathon flag does not mark, and it adds the
  count and timing.

**Usable for the experiment:** yes. Its dates are point-in-time git records, and the invalid and bulk dates are excluded as
missing.
