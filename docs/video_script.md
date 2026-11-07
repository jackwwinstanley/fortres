# 2-minute demo video: script (draft v1)

Target: about 290 spoken words, roughly 2:00 at a calm pace. Judges score Discovery 35%, Data use 25%,
Communication 25% and Impact 15%, so we lead with findings, not code.
Numbers are from the v4 headline model (`outputs/headline.json`) and Person B's reports; recheck them if the
final list changes. **[Bracketed text] = what's on screen.**

---

**0:00–0:15 · Hook** *(Aba)*
[Dashboard title, then the "Blind spots" tab]
"Every year, tens of thousands of vulnerabilities are published, and only about one in a thousand ends up being
used by real attackers. We set out to find those few before it happens, using only what was known at the time."

**0:15–0:35 · The surprise: blind spots** *(Aba)*
[blindspots.png]
"First surprise: in our 2024 and 2025 practice runs, 44 of the 75 vulnerabilities that were later exploited had
no public exploit code and a low EPSS score. The standard rules catch exactly zero of them. That's the gap we
went after."

**0:35–0:55 · How we tested honestly** *(Jack)*
[replica diagram or baselines.png]
"We rebuilt 2024 and 2025 exactly as the 2026 challenge is scored: same snapshot timing, same list size, and only
information available at that moment. A model is trained on one year and tested on the other."

**0:55–1:15 · IBM Granite** *(Aba)*
[Top 500 tab: reasons column]
"IBM Granite reads every description. It scores how much each one sounds like past known-exploited
vulnerabilities and finds its closest match. Granite also writes a one-line reason for each pick, and a checker
rejects any sentence that mentions a fact we didn't give it."

**1:15–1:35 · Results, stated honestly** *(Jack)*
[baselines.png]
"Our model catches 21 exploited vulnerabilities across the two test years, against 19 for the best simple rule.
That's a small edge, and we show the uncertainty range rather than overclaim."

**1:35–1:50 · Two discoveries that protect the result** *(Aba)*
[drift_epss.png, then leakage.png]
"Two things we caught. One: from July 2026, risk scores suddenly jumped about six times, so we compare each
hole only with others from the same month instead of trusting raw scores. Two: columns filled in after an attack would inflate our score from 21 to
29. Every exploited vulnerability is marked 'Analyzed' in today's NVD, so we banned those columns."

**1:50–2:00 · Close** *(Jack)*
[Top 500 list, scrolling]
"Here are our 500 for 2026, each with a reason a security team can act on."

---

### Recording checklist
- [ ] Dashboard running locally (`streamlit run app/dashboard.py`), browser zoom 110%, light mode
- [ ] Charts open in this order: blindspots → baselines → drift_epss → leakage
- [ ] Final numbers re-checked against `outputs/headline.json` after the final list
- [ ] Upload as public YouTube (unlisted is not enough) or a Google Drive link anyone can open
