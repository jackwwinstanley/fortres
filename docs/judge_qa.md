# Demo-table Q&A (DRAFT): Sunday 1:00–2:30 PM

Short, honest answers. Lead with the plain sentence; add the number if they lean in. Numbers are from
`outputs/headline.json`, `outputs/leakage_results.csv`, `site/data/why_traits.csv` and `outputs/explanations_summary.json`.
**Wording:** "added to CISA KEV" (not "attacked"), "associated with" (not "causes"), Guardian "passed a groundedness
check" (not "verified").

---

## The 60-second talk tracks

**Aba (the "what and why", for non-technical judges)**
> Every year tens of thousands of software flaws are published, and only about 1 in 855 ends up on CISA's list of flaws
> known to be exploited. Teams can only patch a few hundred, so the question is: which ones first? We looked at which
> *kinds* of flaws end up on that list. Flaws that need no login or sit in firewalls and VPNs show up about three times as often,
> and enterprise software about four and a half times. WordPress plugins almost never do, though that partly reflects what CISA tracks. The surprise
> was that 44 of the 75 flaws added to the list in our practice years had no public attack code and a low risk score, so
> the standard rule can't see them at all. Our model, which uses IBM Granite to read each description, caught two of those 44,
> both Fortinet firewall flaws, and without the Granite features it caught none. It's a trade-off, though: without
> them the model catches a few more of the visible ones, so overall it's about even. Small, and we say so.

**Jack (the "how and how honest", for technical and IBM judges)**
> We rebuilt 2024 and 2025 exactly the way 2026 is scored, used only information available at the time, and trained on
> one year to test on the other. Our final model is a 20-seed LightGBM bag using IBM Granite text features. Across both
> years it catches 21 flaws that were added to KEV, against 19 for the best simple rule. That's +2, with a 90% range from
> −4 to +8, so it could be luck. On the strictest forward test it's one behind, 12 vs 13. Two things make us trust the
> setup. First, EPSS jumped about 6× from the July 2026 snapshot, so we rank within each month. Second, a leakage test:
> adding database fields that are filled in after the fact lifts us to 28. Every CVE added to KEV is marked "Analyzed"
> today, so we never use those fields. Each of our 500 picks has a plain-English reason from Granite, checked by Granite
> Guardian for groundedness.

---

## Likely questions

**Where is IBM technology used? Does anything run on watsonx?**
IBM Granite does the text work: `granite-embedding-30m-english` turns every description into numbers, and
`granite-3.3-2b-instruct` writes the one-line reasons. IBM Granite Guardian (`granite3-guardian:2b`) checks those reasons.
All of these are **open models we run locally** on a laptop (Guardian via Ollama). **Nothing runs on watsonx** unless
Jack's #31 watsonx step is completed; if it is, describe exactly what ran there and nothing more.

**How do you know you didn't cheat?**
Three ways:
1. Every input is something known on the day you'd have to choose. Every KEV-based feature uses the prior December 31
   as its cutoff, and an independent column review found no leak (`docs/column_review.md`).
2. Phrases that only appear after exploitation ("exploited in the wild", …) are deleted before Granite reads anything.
3. A deliberate leakage test: adding fields NVD fills in *after* a CVE gets attention lifts the same model from 21 to 28.
   Every CVE added to KEV is marked "Analyzed" in today's NVD, against 46% of the rest. We show this to prove we know
   where the trap is, and that we stayed out of it.

**Is 21 vs 19 just luck?**
It could be. With only 75 CVEs added to KEV across the two practice years, +2 has a 90% range of −4 to +8. In the
strictest test (train on 2024, test on 2025) we're one behind, 12 vs 13. What *is* solid: the blind spots (44 of 75),
the July 2026 EPSS jump, and the leakage result.

**Why 500?**
That's the challenge rule: a team can realistically patch about 500 per year. On the smaller practice pools we scale it
(198 for 2024, 243 for 2025) so the share is the same.

**What's EPSS?**
A public score, updated daily, that estimates the chance a flaw will be exploited in the next 30 days. It's one of the
strongest single signals, which is why the simple rule uses it.

**Why did EPSS scores jump in July 2026?**
We don't know: cause unknown. What we measured is that January–May 2026 looks like past years, and from the July 2026
snapshot the typical score is about 6× higher. Those months are 62% of the 2026 list. We don't guess at the cause; we
make the model compare each flaw only with others from the same month, so the jump can't distort the ranking.

**What does Granite Guardian check?**
Groundedness: whether each sentence is supported by the facts we gave Granite. It does **not** check that the
sentence is true about the world, and it doesn't judge style. On top of it we run our own checks (no invented numbers,
products or CVE ids; no words like "critical" or "actively exploited"). Anything that fails gets a plain template
sentence instead. Current count: 419 of 500 reasons passed (`outputs/explanations_summary.json`, Jack's PR #35).

**What's the most interesting thing you found?**
That the standard signals can't see most of the flaws that end up on KEV. 44 of 75 had no public attack code and a low
risk score. Our model caught 2 of them, and without the Granite text features 0; but without the text it caught three
more of the visible ones (22 vs 21 overall), so the text trades visible catches for blind spots. Also, the model and the simple rule fail in *opposite* ways. The rule catches high-EPSS flaws with public
code from vendors rarely on KEV; the model catches enterprise and edge products whose descriptions read like past KEV
entries. A simple 50/50 mix looked promising, but it's not established (`outputs/b_error_analysis.md`).

**Are WordPress plugins and XSS really safe?**
No. They rarely end up on CISA's KEV list (3 of 13,777 and 22 of 31,018), but KEV leans toward enterprise and
government software. They're widely attacked in practice; they're just not what KEV tracks.

**What would you do with more time?**
- More practice years. 75 positives is too few to tell 21 from 19 reliably.
- Test the model + rule blend and the "track record" priors properly (seed and placebo checks), since both looked
  promising on the strict test (`outputs/b_priors_eval.md`, `outputs/b_error_analysis.md`).
- Run the Granite steps on watsonx so they're governed and repeatable.
- Ask CISA-adjacent analysts which reasons they find useful.

**Could this be used for real?**
As a triage aid, yes, alongside EPSS rather than instead of it. The reasons make each pick checkable by a human. As a
replacement for analyst judgement, no.
