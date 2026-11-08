# Devpost submission text (DRAFT, for Aba or Jack to paste)

Claude can't log in to Devpost; paste each section into the matching Devpost field. Numbers match `outputs/headline.json`
(v6) and the Person B reports. Guardian counts are from `outputs/explanations_summary.json`.

---

## Project name
Before the Breach: which 2026 vulnerabilities end up on CISA's known-exploited list?

## Tagline (one line)
We rank 2026's 72,670 new vulnerabilities to find the ones most likely to be added to CISA KEV, using only what was
known at the time, with a plain-English reason for each pick from IBM Granite.

## What it is
Fortres is a triage system for security holes: a statistical model ranks all 72,670 of 2026's new vulnerabilities and picks the 500 most likely to be attacked, and IBM Granite models help read the descriptions and explain every pick in plain language.

The ranking is 20 models that vote, each built from 150 small decision trees, not a chatbot: it's fast, it can be tested against what really happened, and it runs on a laptop. Granite Embedding reads each description and gives the ranking one clue, Granite 3.3 writes a one-sentence reason for each pick, and Granite Guardian checks that reason against the facts (a plain template is used if it fails). It doesn't predict who gets attacked, the language model never decides the ranking, and it still misses most holes that give no warning.

## What we found
The full list of ten, with sources, is in `docs/findings.md`.
1. **Most holes on CISA's list gave no warning.** In our 2024 and 2025 test, 44 of the 75 had no public attack code and a low EPSS score. The usual rule catches 0 of them, and fortres caught 5, three of which come from one Ivanti event.
2. **Severity labels hide danger.** 1 in 9 entries added to CISA's list from 2021 to 2025 (162 of 1,484) is rated only Medium, so a team that fixes Critical and High first reaches these last.
3. **Data that arrives after an attack makes results look better than they are.** In our 2024 and 2025 test, fields NVD fills in later would raise 27 catches to 33, so we left them out.
4. **Outside data can carry hindsight dates.** In Metasploit, for 249 of the 490 pairs of a hole and a module, the link to the hole was added more than 30 days after the module, and some 2025 holes are new numbers for exploits from 2010.
5. **Less work for the same catch.** Fortres caught those 27 with a list of only 441 fixes in our 2024 and 2025 test. To reach the same 27, the usual rule would have to go 1,116 deep, sorting by severity 6,858, and EPSS alone 10,026.

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
  the Granite text features, with regularised settings chosen from seven declared variants by a rule fixed before any
  result. On matched random seeds it beats our previous model by +2 to +5 catches, and part of its in-year skill is
  recognising vendors it has already seen.
- **Reasons:** `granite-3.3-2b-instruct` rewrites a fact list into one sentence. A local checker blocks invented
  numbers, products, CVE ids and claims, and IBM Granite Guardian (`granite3-guardian:2b`, via Ollama) checks the rest is
  supported by the facts.
- Python (pandas, scikit-learn, LightGBM, DuckDB) and a Streamlit dashboard.

## Challenges we ran into
- **Leakage.** Today's NVD record is updated *after* a CVE becomes famous. Every CVE added to KEV in our practice years
  is marked "Analyzed" today, against 46% of the rest. Adding such fields lifted our model from 27 to 33 catches, too
  good to be true, so we banned them and show the test instead.
- **Drift.** EPSS jumped ~6× from the July 2026 snapshot (cause unknown). Those months are 62% of the 2026 list, so we
  rank EPSS within each month instead of using raw scores.
- **Low power.** Only 75 practice-year CVEs were added to KEV, so differences of a few catches are within noise.

## Accomplishments that we're proud of
- **Blind spots:** 44 of the 75 KEV additions in our practice years had no public attack code and a low EPSS score.
  The standard rule catches none of them by construction. Our model caught 5 (three from one Ivanti EPM event,
  two Fortinet FortiOS). In a text-feature ablation on the previous model (v5), either part alone (keyword flags or
  Granite similarity scores) still caught two or three of the 44; with neither, none. The exact CVEs change between
  runs, so treat it as noise.
- **An honest result:** on the strictest forward test (train 2024, test 2025) we're five ahead of the best simple rule,
  18 vs 13. The stability check is 9 vs 6, so pooled over both years it's 27 vs 19 (+8, 90% range +2 to +14). With
  only 75 positives that is still a small sample, and we say so.
- **Reasons people can check:** 318 of 500 Granite-written reasons passed a groundedness check;
  the other 182 use a plain
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
- Revisit two ideas we considered but did not adopt (blending the model with the simple rule, and "track record"
  priors from similar past CVEs) on more practice years; see `docs/considered_not_adopted.md`.
- Run the Granite steps on watsonx so they're governed and repeatable.

## Best Use of Entire
We used Entire as an audit trail for the AI-assisted part of the work: Claude Code sessions captured as checkpoints and linked to
commits, inside our own repository. The evidence we publish is a counts-and-timestamps file (30 checkpoints from 2 sessions in
`outputs/entire_summary.json`) made by a script that never reads a prompt or transcript, with tests that fail if a path or an
address ever reaches it. The checkpoints themselves stay on Jack's laptop with `push_sessions` off, because the repository is public and
transcripts contain personal data (home-folder paths and e-mail-shaped strings); the remote has no Entire refs, and the page `docs/entire.md` has the read-only commands to check that. Of the
snapshot, 27 are imports of earlier history and 3 were captured live, since we enabled Entire part-way through, and it
covers only that one laptop.

## Built with
python, ibm-granite, granite-guardian, ollama, lightgbm, scikit-learn, pandas, duckdb, streamlit, plotly, entire

## Links
- Code: https://github.com/jackwwinstanley/ibm-breach
- Video: _[paste the YouTube or Drive link]_

## Track
IBM "Before the Breach" (+ any other tracks the team selected)
