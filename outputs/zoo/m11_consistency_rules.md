# m11 consistency check: rules (written and committed before any NEW result)

Question (Aba): is m11's gain (regex exploit/PoC words from descriptions, added to I) consistent, or luck? The bar may drop
from +2 to +1 only if the gain is consistent.

Honesty notes
- The +1 bar was set AFTER seeing m11's +1 on seeds 0-19 (post hoc). The 6 fresh seed sets are the real test.
- Before these rules were written I had already run I+m11 on seed sets 1000-1019, 2000-2019 and 3000-3019 (Aba's first
  message asked for a consistency test): pooled 27 vs I 28, 27 vs 26, 28 vs 27. So 4 of the 10 sets were already seen
  when these rules were written, and set 1000-1019 is already below I.

Setup (only the frozen harness's evaluate(); same m11 feature code, same I settings per training year)
- Seed sets: 0-19, 1000-1019, 2000-2019, 3000-3019 (already run) + 6 fresh sets never run before: 4000-4019, 5000-5019,
  6000-6019, 7000-7019, 8000-8019, 9000-9019. Plain I is run on every set (cached per seed), so each comparison uses the same seeds.
- "Consistent" means ALL of:
  (a) I+m11 pooled >= I pooled + 1 on at least 9 of the 10 seed sets, and never below I on any;
  (b) forward never below I's forward on any set;
  (c) stability never below I's stability on any set;
  (d) mean pooled gain over the 10 sets >= +1, and its 90% interval excludes 0. Interval: paired bootstrap over CVEs,
      1,000 draws per direction (seed = direction index, as in the harness); each draw resamples the CVEs ONCE and applies the
      same resample to all 10 seed sets, so the interval is for the 10-set mean gain (pooled across seeds).
- Placebo: I + the m11 features shuffled within snapshot month (5 shuffles, on seeds 0-19; same shuffle applied to both
  features of a row). If the shuffled version gains as much as the real one (mean placebo pooled gain >= real gain on
  seeds 0-19), the gain is just from adding a column and m11 fails.
- Extra (not a rule): how many of the 500 scoreboard picks would change if I+m11 replaced I. Approximation: both models
  trained on both replicas with I's 2025 settings, 20 seeds 0-19, scored on the 2026 scoreboard, top 500 by score, then
  EPSS rank, then cve_id. No top500 file is written.
