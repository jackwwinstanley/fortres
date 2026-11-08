# Outside data test: review for Jack

Branch `b/outside` (no PR, as asked). Code: `src/b/outside.py`. Tables: `outputs/outside_eval.csv`,
`outputs/outside_leakcheck.csv`, `outputs/outside_v5_leakcheck_features.csv`. Nothing in top500*, headline.json,
runlog.csv, docs/, site/, app/ or README.md was changed. The VulnCheck token was read from the environment only. It is
in no file, log, commit or output (the staged files were scanned against it).

## Verdict: keep v5
Neither outside source gives an honest improvement we can use. VulnCheck fails the date rule. Vulnrichment passes it
but flags almost nothing (1 CVE in all years, 0 in 2026).

## Part 1: does v5 itself leak? No
- None of v5's 33 features come from nvd_status, n_affected_cpes, n_references, references.csv or
  affected_products.csv.
- v5 has no CVSS columns, and its features contain 0 blank (NaN) cells, so it cannot tell a blank CVSS score from a
  filled one, including through LightGBM's NaN handling.
- Nothing was flagged, so there was nothing to remove and re-test.

Per-feature table with source and importance share: `outputs/outside_v5_leakcheck_features.csv`.

## Part 2: what each source showed (table: `outputs/outside_leakcheck.csv`)

### VulnCheck KEV: rejected (hindsight dates)
We used VulnCheck's own `date_added`, as asked. In practice it is a "first exploitation" date filled in afterwards:
- `date_added` equals the earliest exploitation-report date in **5,803 of 5,809** entries.
- `updated_at` equals `date_added` everywhere. No field records when VulnCheck actually listed a CVE.
- **1,134** entries are dated before the CVE was even published, 2,103 before 2023, and 108 on a single day
  (2026-10-13). This looks like bulk backfilling.
- It flags 33 of the 75 practice positives and 358 negatives.
- For CVEs also in CISA KEV, VulnCheck's date minus the CISA KEV date is −368 days at minimum, −35 median and −2 at most.
- **Preliminary run, leaky, not for use:** the VulnCheck flag lifted pooled hits from **21 to 33** (A 23 + 10, B 19 + 14).
  A gain that large comes from the hindsight dates, so it is not a real one.
  Files: `outputs/*_PRELIMINARY_vulncheck_only.*`.

### CISA Vulnrichment: honest but nearly empty
- For each CVE we took the CISA ADP SSVC "Exploitation" value and its timestamp, and counted it only if the timestamp
  is on or before the end of the snapshot month.
- Most ratings are stamped after the snapshot (CISA re-scores later), so they count as unknown.
- Under that rule, only **1** CVE qualifies: CVE-2025-55177 (WhatsApp), rated "active" on 2025-08-30, CISA KEV
  2025-09-02, a 2025 positive.
- Coverage: 0 / 1 / 0 for the 2024 pool, the 2025 pool and the 2026 scoreboard.
- Caveat: a shallow clone shows only the latest SSVC value, not earlier ones.

## Results: `outside_exploited` built from Vulnrichment only (VulnCheck excluded), each candidate run once
| | forward (train 2024, test 2025) | stability (train 2025, test 2024) | pooled |
|---|---|---|---|
| v5 frozen | 12 | 9 | 21 |
| A: flagged CVEs first, then v5 order | 13 (+0 to +3) | 9 | 22 (+0 to +3) |
| B: v5 retrained with the flag | 12 | 9 | 21 |

**The fixed adoption rule** was "adopt A or B only if ≥ v5 in both directions and better pooled". A passes it on
paper by one CVE. But the flag is 0 for all 72,670 CVEs on the 2026 scoreboard, so **A's 2026 list is identical to
v5's**: adopting it changes nothing. B equals v5. So **v5 stays**.

## For Devpost: outside data we checked
| source | link | licence / terms | date rule | used? |
|---|---|---|---|---|
| VulnCheck KEV | https://vulncheck.com/kev | VulnCheck Community terms (free account); data not redistributed | dates are hindsight (no listing date), so it fails | no |
| CISA Vulnrichment | https://github.com/cisagov/vulnrichment | CC0-1.0 (public domain) | SSVC timestamp on or before the end of the snapshot month | checked; adds nothing to 2026 |

## Data kept on Aba's laptop (not deleted, waiting for Jack's call)
| what | where (gitignored, never committed) | size |
|---|---|---|
| VulnCheck KEV download | `data/outside/vulncheck_kev.json` | 86 MB |
| CISA Vulnrichment shallow clone | `data/outside/vulnrichment/` | 1.9 GB |

## Optional (only if Jack asks)
Step (d) taken literally, i.e. `outside_exploited` = VulnCheck **or** Vulnrichment, run as one formal row labelled
leaky. About 20 minutes. Not run, because VulnCheck fails the date rule.
