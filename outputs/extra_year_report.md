# An older year the model never saw (2023): result

**Result: v6 did not beat the simple rule on 2023.** In the top 144 of 20,969 CVEs, v6 caught **4 of 22** later added to CISA's
KEV list. The simple rule caught 5 and v5 caught 6. With so few positives the differences are within noise
(v6 minus the rule: [-4, +3]). All are far above chance (0.15 expected at random). Reported as it came out: one run, no tuning.

Plan committed before any result: `outputs/extra_year_plan.md`, commit `8c19afb`. Code: `src/b/extra_year.py`.

## Read this first
- **Not forward in time.** Trained on 2024 and 2025, tested on 2023.
- **The 2023 signals are rebuilt from outside data**, because the competition data has no 2023 monthly signals. It is not a perfect replica.
- **EPSS changed models in the test year** (v3 launched on 2023-03-07), so January and February use the older model.
- **Small sample:** 22 positives from 21 distinct vendor/date events.

## Results (top k = 144, pool 20,969, positives 22, events 21)
| method | hits | recall | precision | lift vs chance | v6 minus this | 90% CVE-level | 90% event-clustered |
|---|---|---|---|---|---|---|---|
| **v6** | 4 | 18.2% | 2.8% | 26.5x |  |  |  |
| v5 | 6 | 27.3% | 4.2% | 39.7x | -2 | [-4, +0] | [-4, +0] |
| simple rule (public exploit, then EPSS) | 5 | 22.7% | 3.5% | 33.1x | -1 | [-4, +3] | [-4, +3] |
| EPSS alone | 3 | 13.6% | 2.1% | 19.9x | 1 | [-2, +5] | [-3, +5] |
| severity (CVSS) | 0 | 0.0% | 0.0% | 0.0x | 4 | [+1, +8] | [+2, +7] |
| random (expected) | 0.15 | 0.7% | 0.10% | 1.0x | | | |

**Depth each ranking needs to reach v6's 4 hits:** v6 60, v5 78, simple rule 93, EPSS alone 203, severity 1,866.

**Placebo (labels shuffled within month, 30 five-seed bags each):** real mean 4.43 (range 4 to 5), shuffled mean 0.13 (range 0 to 1); difference +4.3, p < 0.001.

## Fidelity check (the same recipe rebuilding the 2024 pool, 28,839 CVEs, compared with the datathon's file)
EPSS: equal at 5 decimals on 100.0% of the 27,557 CVEs with a score in both (Spearman 1.0).

| flag | datathon | rebuilt | both | agreement (all CVEs) | share of the datathon's flags found |
|---|---|---|---|---|---|
| exploitdb | 22 | 22 | 22 | 100.00% | 100.0% |
| metasploit | 18 | 34 | 18 | 99.94% | 100.0% |
| nuclei | 105 | 135 | 104 | 99.89% | 99.0% |
| poc_github | 556 | 517 | 485 | 99.64% | 87.2% |
| any_flag | 633 | 622 | 568 | 99.59% | 89.7% |

Among the 27 KEV additions of the 2024 pool, the datathon's flags mark 10 and the rebuilt flags 11. The recipe was not changed after this check.

## Rebuilt 2023 pool
21,037 CVEs published January to September 2023; 68 dropped as already in KEV by the snapshot; 20,969 kept. Flags in the pool: exploitdb 120, metasploit 23, nuclei 99, poc_github 414. EPSS missing: 437.

## One failed attempt before the run
The first attempt crashed before producing any score (PyTorch and LightGBM in one process). The embeddings were moved to their own step (`text`, cached), and the run was started once more. Nothing else changed.

## Ready to paste (docs/findings.md and the judge Q&A), not applied here so b/discovery's files are left alone
> **An older year the model never saw.** The competition data has no 2023 signals, so we rebuilt them from public sources (EPSS history and dated exploit records; rebuilding 2024 the same way matched the datathon's EPSS exactly and its flags on 99.6% or more of CVEs). Trained on 2024 and 2025, v6 caught 4 of 22 KEV additions in the top 144 of 20,969 CVEs in 2023, 26.5 times chance. The simple rule caught 5 and v5 6, so on that year v6 does not beat the simple rule; the differences are within noise. It is a backward test on rebuilt data, so it is weaker evidence than the 2024 and 2025 tests.

> **Q: Does it hold up on other years?** On an older year the model never saw, 2023, rebuilt from public data, it caught 4 of 22: far above chance, but one fewer than the simple rule. We report that plainly. With 22 positives the gap is within noise, and it is a test backwards in time on rebuilt signals.
