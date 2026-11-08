# New data experiment: Nuclei templates as a feature source (b/new-data)

**Verdict: fails the pre-declared rule. v6 stays.** This is an experiment under the fixed protocol, not an adoption.

- **Source:** https://github.com/projectdiscovery/nuclei-templates (MIT), from a full clone.
- **Code:** `src/b/new_data.py`.
- **Provenance audit**, written before anything was built: `outputs/newdata_provenance.md`.
- **Tables:** `outputs/newdata_eval.csv`.
- **Derived per-CVE table:** `outputs/newdata_nuclei_first_added.csv` (cve_id, first_added_date; 4,721 rows, 169 KB). It is
  derived from the MIT-licensed nuclei-templates history (Copyright (c) 2025 ProjectDiscovery, Inc.; MIT licence: use,
  copy and redistribute with the notice). It contains no template content.
- **Not committed:** the clone, which is deleted after the run.

## Records matched and the temporal boundary
- **Matched:** templates with a CVE id cover 4,721 CVEs.
- **Dated by the end of the snapshot month:**
  - 135 of the 2024 pool (0.47%);
  - 142 of the 2025 pool (0.40%);
  - 211 of the 2026 scoreboard (0.29%).
- **Not counted:** another 276-302 CVEs per pool get a template only after their snapshot month.
- **Practice positives flagged:** 20 of 75.
- **Overlap with our own flag:** the datathon's own `nuclei` flag (already a v6 feature) marks 105 / 109 / 167. Nearly all of
  those are inside the new flag.
- **How the boundary is enforced:**
  - A template counts only if its first-added author date is on or before the CVE's snapshot-month end (23:59:59 UTC).
  - Impossible dates (41 files, e.g. 1970) and bulk-commit dates (threshold 100 CVE templates per commit) are missing, not early.
  - `tests/test_new_data.py` checks this, and a mutation check, which lets later records in, proves the test fails then.
  - No banned column is used.
- **Distribution shift:** the share of CVEs with a dated template falls from about 0.4-0.5% in the practice pools to 0.29% on
  the 2026 scoreboard.

## Results (20-seed bags, v6's settings, forward first)
| variant | forward (train 2024 → test 2025) | stability (train 2025 → test 2024) | pooled | vs v6, 90% CVE-level / event-clustered | rule |
|---|---|---|---|---|---|
| v6 (reference) | 18 | 9 | 27 | | |
| A: v6 + Nuclei features | 18 | 9 | 27 | +0 [0, 0] / [0, 0] | fails (gain 0 < 4) |
| B: Nuclei features alone | 8 | 3 | 11 | −16 [−24, −9] / [−25, −9] | fails |

- **The rule (unchanged):** forward ≥ 18, stability ≥ 9, and a pooled gain of at least 2 and at least the noise floor of 4
  over 27. v6's own spread over four seed sets is 2.
- **The restricted variant was not run:** every feature passed the provenance audit, so a version restricted to the passing
  columns would equal A.
- **Why A is identical to v6:** the new columns get **zero split gain** in both directions, and so does the existing
  `nuclei` flag. v6's regularised settings require at least 200 rows in each leaf (`min_child_samples` 200). Only 135-142
  practice CVEs have a template by the snapshot, so no split on these columns can satisfy that. This is a property of the
  adopted settings, not of the data. Testing other settings would be a new declared variant; it was not run here.

## Placebo and leakage
- **Placebo:** variant A on labels shuffled within each snapshot month gives a mean of 0.6 pooled hits, against 27.0 for real
  labels (10 × 5-seed bags each; difference +26.4, p < 0.001). The model learns from the labels, as v6 did.
- **Leakage experiment:** A's honest columns score 18 / 9 / 27, and the same plus the banned after-the-fact columns scores
  21 / 12 / 33. That is exactly v6's own gap (27 → 33), so the new features add no retrospective bias, and none they could use.

## Multiple testing
Two sources were planned: Nuclei, and Metasploit if time allowed. If more than one is tested, a pass would carry extra
selection risk. The pre-declared rule is unchanged and applies to each source on its own; this source fails it outright.

## Ready-to-paste paragraph for docs/considered_not_adopted.md
> **Nuclei templates (projectdiscovery/nuclei-templates, MIT) as new features.** We dated each CVE template by the author
> date of the git commit that first added it, from a full clone with renames followed. A spot check of 20 files against
> per-file `git log --follow` agreed on all 20. Impossible dates and bulk-import dates count as missing. Three features
> counted only templates dated by the end of each CVE's snapshot month: has a template, days from publication to the
> first template, and the number of templates. They cover about 0.4% of each pool. Added to v6 the result is unchanged
> (18 / 9 / 27; the columns get zero split gain, because v6's regularised leaves need 200 rows and only about 140 practice
> CVEs have a dated template). On their own they score 8 / 3 / 11. Not adopted (`outputs/newdata_report.md`).
