# 2-minute demo video: script (draft v2)

Target: about 290 spoken words, roughly 2:00 at a calm pace. Judges score Discovery 35%, Data use 25%,
Communication 25% and Impact 15%, so we lead with findings, not code.
Numbers are from the v5 headline model (`outputs/headline.json`), `outputs/leakage_results.csv` (leaky arm 28 on v5; Jack to
confirm vs 29) and `outputs/explanations_summary.json` (Guardian count, PR #35); recheck them if the final list changes. **[Bracketed text] = what's on screen.**

---

**0:00–0:15 · Hook** *(Aba)*
[Dashboard title, then the "Blind spots" tab]
"Every year, tens of thousands of vulnerabilities are published, and only about one in 855 ends up on
CISA's list of known-exploited vulnerabilities. We set out to find those few before it happens, using only what was known at the time."

**0:15–0:35 · The surprise: blind spots** *(Aba)*
[blindspots.png]
"First surprise: in our 2024 and 2025 practice runs, 44 of the 75 vulnerabilities later added to CISA KEV had
no public exploit code and a low EPSS score. The standard rules catch exactly zero of them. That's the gap we
went after."

**0:35–0:55 · How we tested honestly** *(Jack)*
[replica diagram or baselines.png]
"We rebuilt 2024 and 2025 exactly as the 2026 challenge is scored: same snapshot timing, same list size, and only
information available at that moment. A model is trained on one year and tested on the other."

**0:55–1:15 · IBM Granite** *(Aba)*
[Top 500 tab: reasons column]
"IBM Granite, IBM's open models running right on our laptop, reads every description. It scores how much each one sounds like past known-exploited
vulnerabilities. Granite also writes a one-line reason for each pick; our checker and IBM Granite Guardian reject any
sentence that isn't supported by the facts we gave it."

**1:15–1:35 · Results, stated honestly** *(Jack)*
[baselines.png]
"Across the two test years our model catches 21 vulnerabilities that were added to KEV, against 19 for the best simple
rule. That's a small edge and it could be luck. In the strictest test, training on 2024 and testing on 2025, we were one
behind, 12 to 13. We show the uncertainty rather than overclaim."

**1:35–1:50 · Two discoveries that protect the result** *(Aba)*
[drift_epss.png, then leakage.png]
"Two things we caught. One: EPSS jumped about six times from the July 2026 snapshot, cause unknown, so we compare each
hole only with others from the same month instead of trusting raw scores. Two: columns filled in after a CVE is added to KEV would inflate our score from 21 to
28. Every vulnerability added to KEV is marked 'Analyzed' in today's NVD, so we banned those columns."

**1:50–2:00 · Close** *(Jack)*
[Top 500 list, scrolling]
"Here are our 500 for 2026, each with a reason a security team can act on."

---

### Recording checklist
- [ ] Dashboard running locally (`streamlit run app/dashboard.py`), browser zoom 110%, light mode
- [ ] Charts open in this order: blindspots → baselines → drift_epss → leakage
- [ ] Final numbers re-checked against `outputs/headline.json` after the final list
- [ ] Upload as public YouTube (unlisted is not enough) or a Google Drive link anyone can open
