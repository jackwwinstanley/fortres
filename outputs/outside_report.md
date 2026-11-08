# Outside data test (local report, not committed): VulnCheck KEV + CISA Vulnrichment

Branch `b/outside` (worktree), code `src/b/outside.py`. Data in `data/outside/` (gitignored). The token was read from
the environment only. Nothing in top500*, headline.json, runlog.csv, docs/, site/, app/ or README.md was changed.

## Part 1: v5 leak check
33 features; **none** come from nvd_status, n_affected_cpes, n_references, references.csv, affected_products.csv or CVSS.
There are no CVSS columns in the v5 frame and **0 NaN cells** in v5 features, so blank-vs-filled CVSS cannot be encoded
(including through LightGBM NaN handling). Nothing is flagged, so nothing needs removing. Table with sources and gain
shares: `outputs/outside_v5_leakcheck_features.csv`.

## Part 2: outside sources
| source | link | licence / terms | date rule | result |
|---|---|---|---|---|
| VulnCheck KEV | https://vulncheck.com/kev (API `api.vulncheck.com/v3/index/vulncheck-kev`) | VulnCheck terms (free Community account); data not redistributed | **fails**: `date_added` equals the earliest exploitation-report date in 5,803 of 5,809 entries; `updated_at` = `date_added`; no field records when VulnCheck listed it | contribution set to **unknown**, not used |
| CISA Vulnrichment (ADP SSVC "Exploitation") | https://github.com/cisagov/vulnrichment | CC0-1.0 (public domain) | passes: counted only if the SSVC timestamp ≤ snapshot end; mirrored (timestamp ≥ CISA KEV date) excluded; shallow clone = latest value only | flags 1 CVE in all pools |

Leak table: `outputs/outside_leakcheck.csv`.
- **VulnCheck:** flags 33 of 75 replica positives and 358 negatives. VulnCheck date minus KEV date: min −368, median −35,
  max −2 days. Backfilling: 1,134 entries dated before CVE publication, 2,103 before 2023, and 108 on 2026-10-13. These
  are hindsight dates.
- **Vulnrichment:** "active" with a timestamp ≤ snapshot end flags 1 CVE (CVE-2025-55177, WhatsApp: SSVC active
  2025-08-30, KEV 2025-09-02, a 2025 positive). Coverage 0 / 1 / 0 in 2024 / 2025 / 2026. Most SSVC values are stamped
  after the snapshot (re-scored later), so they count as unknown.

## Evaluation of `outside_exploited` (Vulnrichment only), once each, no tuning
| test | v5 frozen | A two-tier | B v5 + feature |
|---|---|---|---|
| forward (train 2024 → test 2025) | 12 | 13 (+0 to +3) | 12 (+0 to +0) |
| stability (train 2025 → test 2024) | 9 | 9 | 9 |
| pooled | 21 | 22 (+0 to +3) | 21 |
Full table: `outputs/outside_eval.csv`.

**PRELIMINARY and LEAKY, not for use:** the VulnCheck-only flag, run before the date rule was applied, scored A 23 + 10 = 33
and B 19 + 14 = 33 vs v5 21. VulnCheck fails the date rule, so this is hindsight
(`outputs/outside_eval_PRELIMINARY_vulncheck_only.csv`).

## Verdict
By the fixed rule (≥ v5 in both directions and better pooled), **A technically qualifies by one CVE** (CVE-2025-55177). But
`outside_exploited` is 0 for every one of the 72,670 2026 CVEs, so **A's 2026 list is identical to v5's**: adopting it
changes nothing. B is identical to v5. **Stick with v5.** For the Devpost outside-data list: Vulnrichment was checked and
found almost empty under the date rule; VulnCheck was rejected because its dates are hindsight dates.
