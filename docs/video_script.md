# Demo video: script (final draft, under 3 minutes)

Target: about 370 spoken words, roughly 2:35 at a calm pace, with every segment timed below. Judges score Discovery 35%, Data use 25%,
Communication 25% and Impact 15%, so we lead with findings, not code.
Numbers are from the v6 headline model (`outputs/headline.json`), `outputs/v6_leakage_results.csv` (leaky arm 33 on v6; 28 on v5 and 29 on the earlier v4 run), `outputs/explanations_summary.json` (Guardian count, PR #35), `outputs/v6_blindspots.csv` and `docs/findings.md`; recheck them if the final list changes. **[Bracketed text] = what's on screen.**

---

**0:00–0:15 · Hook** *(Aba)*
[Dashboard title]
"Every year, tens of thousands of vulnerabilities are published, and only about one in 855 ends up on
CISA's list of known-exploited vulnerabilities. We set out to find those few before it happens, using only what was known at the time."

**0:15–0:32 · What is fortres?** *(Aba)*
[The one sentence on screen]
"Fortres is a triage system for security holes: a statistical model ranks all 72,670 of 2026's new vulnerabilities and picks the 500 most likely to be attacked, and IBM Granite models help read the descriptions and explain every pick in plain language."

**0:32–0:52 · How we tested honestly** *(Jack)*
[replica diagram or baselines.png]
"We rebuilt 2024 and 2025 exactly as the 2026 challenge is scored: same snapshot timing, same list size, and only
information available at that moment. A model is trained on one year and tested on the other."

**0:52–1:12 · IBM Granite** *(Aba)*
[Top 500 tab: reasons column]
"IBM Granite, IBM's open models running right on our laptop, reads every description. It scores how much each one sounds like past known-exploited
vulnerabilities. Granite also writes a one-line reason for each pick; our checker and IBM Granite Guardian reject any
sentence that isn't supported by the facts we gave it."

**1:12–1:32 · Results, stated honestly** *(Jack)*
[baselines.png]
"In the strictest test, training on 2024 and testing on 2025, we were five ahead of the best simple rule, 18 to 13. The
other way round it was 9 to 6, so across both years 27 against 19, on only 75 positives. We show the
uncertainty rather than overclaim."

**1:32–2:12 · What we found (40 seconds, one big number each)** *(Aba, then Jack)*
[Big number: 44 of 75, over blindspots.png]
"Three things surprised us. First, in our 2024 and 2025 test, 44 of the 75 exploited holes gave no warning: no public attack code and a low EPSS score. The usual rule catches none of them. Fortres caught 5, and three of those are one Ivanti event."
[Big number: 27, not 33, over leakage.png]
"Second, data that arrives after an attack. Every hole CISA lists gets marked 'Analyzed' in NVD, so using those fields would raise 27 to 33. We left them out."
[Big number: 182 of 500]
"Third, the AI's reasons needed a referee. Of our 500, 182 show a plain template, because Guardian rejected 90 and our own checks stopped 92."

**2:12–2:24 · One more thing that protects the result** *(Jack)*
[drift_epss.png]
"EPSS jumped about six times from the July 2026 snapshot, cause unknown, so we compare each
hole only with others from the same month instead of trusting raw scores."

**2:24–2:34 · Close** *(Jack)*
[Top 500 list, scrolling]
"Here are our 500 for 2026, each with a reason a security team can act on."

---

### Recording checklist
- [ ] Dashboard running locally (`streamlit run app/dashboard.py`), browser zoom 110%, light mode
- [ ] Charts open in this order: blindspots → baselines → leakage → drift_epss
- [ ] Final numbers re-checked against `outputs/headline.json` after the final list
- [ ] Upload as public YouTube (unlisted is not enough) or a Google Drive link anyone can open
