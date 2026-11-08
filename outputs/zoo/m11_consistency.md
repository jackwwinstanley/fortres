# m11 consistency check: I + m11 (regex exploit/PoC words) vs I

Rules: `outputs/zoo/m11_consistency_rules.md` (committed before any new result). Code: `src/b/zoo/m11_consistency.py`; every run went through the frozen harness's `evaluate()` (rows in `m11_regex.csv`, `m11_placebo.csv`).

**Honesty note:** the +1 bar was proposed AFTER seeing m11's +1 on seeds 0-19 (post hoc). The 3 old confirmation sets (1000/2000/3000) had also been run before the rules were written. The 6 fresh seed sets (4000-9019) are the real test.

## Verdict: **NOT consistent - m11 is not adopted, I stays**

| rule | result |
|---|---|
| (a) pooled >= I + 1 on >= 9 of 10 sets, never below I | FAIL: +1 or more on 4/10, below I on 3 |
| (b) forward never below I | pass: below on 0 sets |
| (c) stability never below I | FAIL: below on 3 sets |
| (d) 10-set mean gain >= +1 and 90% interval excludes 0 | FAIL: mean +0.1, 90% interval [-0.1, +0.4] |
| placebo (shuffled m11) gains less than real | pass: placebo mean +0.8 vs real +1 on seeds 0-19 |

Note on the placebo: it passes only by the letter of the rule (mean +0.8 < +1). 4 of the 5 shuffled versions gain exactly the same +1 as the real feature, so on seeds 0-19 the +1 is as large as what adding a meaningless column gives. That points to luck, not signal.

## Per seed set (forward / stability / pooled)

| seed set | fresh? | I | I + m11 | pooled delta | per-set 90% interval |
|---|---|---|---|---|---|
| 0-19 | no | 18 / 9 / 27 | 18 / 10 / 28 | +1 | [+0, +3] |
| 1000-1019 | no | 18 / 10 / 28 | 18 / 9 / 27 | -1 | [-3, +0] |
| 2000-2019 | no | 18 / 8 / 26 | 18 / 9 / 27 | +1 | [-1, +3] |
| 3000-3019 | no | 18 / 9 / 27 | 18 / 10 / 28 | +1 | [+0, +3] |
| 4000-4019 | yes | 18 / 9 / 27 | 18 / 9 / 27 | +0 | [+0, +0] |
| 5000-5019 | yes | 18 / 10 / 28 | 18 / 10 / 28 | +0 | [-2, +0] |
| 6000-6019 | yes | 18 / 9 / 27 | 18 / 10 / 28 | +1 | [+0, +3] |
| 7000-7019 | yes | 18 / 8 / 26 | 18 / 8 / 26 | +0 | [+0, +0] |
| 8000-8019 | yes | 18 / 10 / 28 | 18 / 9 / 27 | -1 | [-4, +0] |
| 9000-9019 | yes | 18 / 10 / 28 | 18 / 9 / 27 | -1 | [-3, +0] |

Mean pooled gain, all 10 sets: **+0.1** (90% interval [-0.1, +0.4]; paired bootstrap over CVEs, 1,000 draws per direction, the same resample applied to all 10 sets, i.e. pooled across seeds). Fresh 6 sets only: mean -0.17, +1 or more on 1/6, below I on 2/6.

## Placebo (m11 features shuffled within snapshot month, seeds 0-19)

| shuffle | forward | stability | pooled | delta vs I |
|---|---|---|---|---|
| 0 | 18 | 10 | 28 | +1 |
| 1 | 18 | 9 | 27 | +0 |
| 2 | 18 | 10 | 28 | +1 |
| 3 | 18 | 10 | 28 | +1 |
| 4 | 18 | 10 | 28 | +1 |

## Scoreboard picks that would change

If I+m11 replaced I: **9 of the 500** scoreboard picks change (approximation: both trained on both replicas with I's 2025 settings, seeds 0-19, top 500 by score, EPSS rank, cve_id; no top500 file written).
