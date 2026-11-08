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
> the standard rule can't see them at all. Our model, with simple keyword flags plus an IBM Granite score for how
> similar a description is to past KEV entries, caught five of those 44, three from one Ivanti incident. On our
> previous model, either text part alone still caught two or three; with neither, none. The exact flaws change between runs, so we treat it as noise. Small, and we say so.

**Jack (the "how and how honest", for technical and IBM judges)**
> We rebuilt 2024 and 2025 exactly the way 2026 is scored, used only information available at the time, and trained on
> one year to test on the other. Our final model is a 20-seed LightGBM bag with text features, including IBM Granite
> similarity scores, chosen from seven declared variants by a rule fixed before any result. On the strictest forward test it's five ahead of the best simple rule, 18 vs 13; the other direction
> is 9 vs 6, so across both years 27 vs 19. That's +8, with a 90% range from +2 to +14, on only 75 positives. Two things make us trust the
> setup. First, EPSS jumped about 6× from the July 2026 snapshot, so we rank within each month. Second, a leakage test:
> adding database fields that are filled in after the fact lifts us to 33. Every CVE added to KEV is marked "Analyzed"
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
3. A deliberate leakage test: adding fields NVD fills in *after* a CVE gets attention lifts the same model from 27 to 33.
   Every CVE added to KEV is marked "Analyzed" in today's NVD, against 46% of the rest. We show this to prove we know
   where the trap is, and that we stayed out of it.

**Is 27 vs 19 just luck?**
Partly, maybe. In the strictest test (train on 2024, test on 2025) we're five ahead, 18 vs 13; the other direction is
9 vs 6. With only 75 CVEs added to KEV across the two practice years, the pooled +8 has a 90% range of +2 to +14, and
rerun with other random seeds our gain over the previous model shrinks to +2 to +5. What *is* solid: the blind spots (44 of 75),
the July 2026 EPSS jump, and the leakage result.

**Did you use outside data?**
We tested four outside sources and adopted none. VulnCheck KEV failed our date rule: its "date added" is the earliest
exploitation report, filled in afterwards. CISA Vulnrichment follows the date rule, but almost nothing is rated "active"
before the snapshot (one practice CVE, none in 2026). GitHub proof-of-concept creation dates mostly repeat our own GitHub
flag (about 92% overlap). Adding them together with the monthly EPSS change lowered the score (18 against 21), so we
left them out. Links, licences and date rules are in the README.

**Why v6 over v5? How was it chosen?**
Seven variants were declared, each with settings chosen only inside the training year, and the adoption rule was fixed
before any result: at least as good as v5 in both directions, and a pooled gain of at least 2 and at least the seed noise.
The seed noise was measured first: v5 itself moves between 21 and 25 with other random seeds, so the bar was 4. Only the
regularised variant passed (27 against 21), so it became v6. Re-run on the same seeds as v5, its gain is +2 to +5. A later
round of eleven more methods found nothing better (`docs/considered_not_adopted.md`).

**Does it just learn vendors?**
Partly. If whole vendors are held out in cross-validation, v5's 2025 in-year hits roughly halve (19 → 10); 2024 shows no
gap. So part of the in-year skill is recognising vendors already associated with KEV additions. Our headline tests train
on one year and test on the other, and the vendor history features use only KEV entries from before the previous
31 December.

**Why are 498 of the 500 flagged with public exploit code?**
Public exploit code is strongly associated with being added to CISA KEV, and the 2026 scoreboard has far more than 500
flagged CVEs, so the model fills its list with them. Its value is in the order *within* the flagged CVEs: only 193 of its
500 are also in the simple rule's top 500. The other side of the trade-off is that only 2 of the 500 have no public exploit
code, so the 2026 list itself barely reaches the blind spots (`outputs/v6_overlap.csv`).

**Did you pick the model after seeing the results?**
No. Seven variants were declared, with an adoption rule fixed before any result: at least as good as the previous model in
both directions, and a pooled gain of at least 2 and at least the seed noise (4). Only one passed, so it became v6.
One caveat we found ourselves: if whole vendors are held out, the previous model's 2025 in-year hits roughly halve, so
part of the skill is recognising vendors it has seen before.

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
sentence instead. Count: 318 of 500 reasons passed the groundedness check; the other 182 use the template (`outputs/explanations_summary.json`).

**What's the most interesting thing you found?**
That the standard signals can't see most of the flaws that end up on KEV. 44 of 75 had no public attack code and a low
risk score. Our model caught 5 of them, three from one Ivanti EPM event. In a text-feature ablation on the previous model (v5),
either part alone (keyword flags or Granite similarity scores) still caught two or three of the 44; with neither, none; the exact CVEs change between runs, so treat it as noise. Without any text v5 caught three more of the visible ones (22 vs 21 overall), so the text trades
visible catches for blind spots. Also, the model and the simple rule fail in *opposite* ways. The rule catches high-EPSS flaws with public
code from vendors rarely on KEV; the model catches enterprise and edge products whose descriptions read like past KEV
entries. We tried a simple 50/50 mix and did not adopt it (`docs/considered_not_adopted.md`).

**Are WordPress plugins and XSS really safe?**
No. They rarely end up on CISA's KEV list (3 of 13,777 and 22 of 31,018), but KEV leans toward enterprise and
government software. They're widely attacked in practice; they're just not what KEV tracks.

**What would you do with more time?**
- More practice years. 75 positives is too few to measure a few catches reliably.
- Revisit the model + rule blend and the "track record" priors on more practice years. Both were considered and not
  adopted (`docs/considered_not_adopted.md`).
- Run the Granite steps on watsonx so they're governed and repeatable.
- Ask CISA-adjacent analysts which reasons they find useful.

**Could this be used for real?**
As a triage aid, yes, alongside EPSS rather than instead of it. The reasons make each pick checkable by a human. As a
replacement for analyst judgement, no.
