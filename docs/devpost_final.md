# Devpost submission text (DRAFT, for Aba or Jack to paste)

Claude can't log in to Devpost; paste each section into the matching Devpost field. Numbers match `outputs/headline.json`
(v5) and the Person B reports. Re-check the Guardian count and the leaky-arm figure (28 on v5) after PR #35 and Jack's
call on 28 vs 29.

---

## Project name
Before the Breach: which 2026 vulnerabilities end up on CISA's known-exploited list?

## Tagline (one line)
We rank 2026's 72,670 new vulnerabilities to find the ones most likely to be added to CISA KEV, using only what was
known at the time, with a plain-English reason for each pick from IBM Granite.

## Inspiration
Every year tens of thousands of software flaws are published, and only about 1 in 855 ends up on CISA's Known Exploited
Vulnerabilities (KEV) list. Security teams can only patch a few hundred, so which ones first? The standard answer is
"public attack code first, then the highest EPSS score". We wanted to see what that rule misses and whether reading the
description, the way an analyst would, can help.

## What it does
- Ranks all 72,670 CVEs on the 2026 scoreboard and picks 500.
- Gives each pick a one-sentence reason written by IBM Granite from facts our pipeline supplies. Each sentence passes a
  local fact checker and an IBM Granite Guardian groundedness check, or falls back to a plain template.
- Explains, for non-technical readers, which kinds of vulnerabilities are associated with ending up on KEV and where
  the standard rule is blind.

## How we built it
- **Honest practice years.** We rebuilt 2024 and 2025 exactly the way 2026 is scored: same snapshot timing, list size
  scaled to the pool, and only information available at the time. Every KEV-based feature uses the prior December 31
  as its cutoff. We train on one year and test on the other.
- **IBM Granite text features** (open models, run locally): `granite-embedding-30m-english` embeds 178,175 descriptions.
  From that we derive a KEV-likeness score (a classifier trained only on earlier years) and the similarity to the
  closest past KEV entry. Phrases that only appear after exploitation ("exploited in the wild", …) are removed first.
- **Model:** a 20-seed LightGBM bag on exploit signals, EPSS rank within the month, vendor and reporter history, and
  the Granite text features.
- **Reasons:** `granite-3.3-2b-instruct` rewrites a fact list into one sentence. A local checker blocks invented
  numbers, products, CVE ids and claims, and IBM Granite Guardian (`granite3-guardian:2b`, via Ollama) checks the rest is
  supported by the facts.
- Python (pandas, scikit-learn, LightGBM, DuckDB) and a Streamlit dashboard.

## Challenges we ran into
- **Leakage.** Today's NVD record is updated *after* a CVE becomes famous. Every CVE added to KEV in our practice years
  is marked "Analyzed" today, against 46% of the rest. Adding such fields lifted our model from 21 to 28 catches, too
  good to be true, so we banned them and show the test instead.
- **Drift.** EPSS jumped ~6× from the July 2026 snapshot (cause unknown). Those months are 62% of the 2026 list, so we
  rank EPSS within each month instead of using raw scores.
- **Low power.** Only 75 practice-year CVEs were added to KEV, so differences of a few catches are within noise.

## Accomplishments that we're proud of
- **Blind spots:** 44 of the 75 KEV additions in our practice years had no public attack code and a low EPSS score.
  The standard rule catches none of them by construction; our model caught 2 (both Fortinet FortiOS).
- **An honest result:** 21 vs 19 for the best simple rule across both years (+2, 90% range −4 to +8). On the
  strictest forward test we're one behind (12 vs 13), and we say so.
- **Reasons people can check:** 419 of 500 Granite-written reasons passed a groundedness check; the rest use a plain
  template.

## What we learned
- The standard signals and the text see *different* vulnerabilities. The rule catches high-EPSS flaws with public code
  from vendors rarely on KEV; the model catches enterprise and edge products whose descriptions read like past KEV
  entries.
- Some traits are associated with much higher KEV rates: enterprise software 25.5 per 1,000, edge devices 17.3, versus
  5.6 overall. WordPress plugins (3 of 13,777) and cross-site scripting (22 of 31,018) are rarely on KEV, but KEV skews
  toward enterprise and government software, so that doesn't mean they're safe.
- Groundedness checks catch unsupported claims, not every awkward phrase. We still read samples by hand.

## What's next for Before the Breach
- More practice years, so a difference of 2 means something.
- Properly test two promising hints: blending the model with the simple rule, and "track record" priors from similar
  past CVEs.
- Run the Granite steps on watsonx so they're governed and repeatable.

## Built with
python, ibm-granite, granite-guardian, ollama, lightgbm, scikit-learn, pandas, duckdb, streamlit, plotly

## Links
- Code: https://github.com/jackwwinstanley/ibm-breach
- Video: _[paste the YouTube or Drive link]_

## Track
IBM "Before the Breach" (+ any other tracks the team selected)
