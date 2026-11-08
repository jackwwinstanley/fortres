# Page content (DRAFT, content only, no design)

What each section of the public page should *say* and which real numbers it shows. Written for very non-technical
judges: one plain sentence first, numbers second. Every number names its source file, and all of them are regenerated
by `python -m src.b.export_story` (→ `site/data/story.json`) unless another script is named. The visual design is
deliberately undecided.

**Wording rules (team):** nothing may imply watsonx unless a step actually ran there; say "IBM Granite (open models, run locally)" and "IBM Granite Guardian (run locally via Ollama)". "added to CISA KEV" (CVEs CISA lists as known-exploited), never "attacked"; "is associated
with", never "causes" or "leads to"; Granite Guardian reasons "passed a groundedness check", never "verified".

---

## 0. The haystack
**Message:** In 2026, 72,670 new security holes were published. Only about 1 in 855 ends up on CISA's list of
known-exploited vulnerabilities (KEV).
- 72,670 CVEs on the 2026 scoreboard (`outputs/scoreboard_features.parquet`)
- 75 of 64,119 practice-year CVEs were added to KEV, so 1 in 855. At that rate about 85 of 2026's would be
  (`outputs/replica_2024.parquet`, `replica_2025.parquet`, `label`)
- Defenders can patch 500 (the challenge rule).

## 1. Traits of CVEs that end up on KEV
**Message:** Out of every 1,000 CVEs, about 6 are added to CISA KEV. Some kinds are associated with a 3–4.6× higher
rate (no login 2.8×, edge devices 3.1×, browsers 3.3×, enterprise software 4.6×), and some scary-sounding kinds almost never appear on the list.

| kind of CVE | added to KEV per 1,000 | added to KEV / CVEs |
|---|---|---|
| all CVEs (2018–Sep 2025) | 5.6 | 1,131 / 201,494 |
| enterprise software | 25.5 | 295 / 11,555 |
| public attack code exists (2024–25 practice years) | 22.3 | 31 / 1,393 |
| web browser | 18.3 | 97 / 5,308 |
| network edge device (firewall, VPN) | 17.3 | 87 / 5,016 |
| takes over the machine | 15.9 | 404 / 25,429 |
| no login needed | 15.7 | 247 / 15,765 |
| cross-site scripting | 0.7 | 22 / 31,018 (few cases, treat as a hint) |
| WordPress plugin | 0.2 | 3 / 13,777 (few cases, treat as a hint) |

**Limitation (show wherever these numbers appear):** KEV skews toward enterprise and government-relevant software, so
WordPress plugins (3 of 13,777) and cross-site scripting (22 of 31,018) look safe here although they are widely attacked
in practice.
Source: `site/data/why_traits.csv` (KEV as of 2025-12-29). Traits are keyword tags on the description. Descriptive only:
never a model input (enforced by `tests/test_site_data_isolation.py`). Older CVEs had more time to be added.

## 2. Today's rule and its blind spots
**Message:** The usual rule ("public attack code first, then the highest risk score") caught 19 of the 75 CVEs added to
KEV in our practice years: 25%. 44 of the 75 had no public attack code and a low risk score, and the rule caught none of them.
- Best simple rule: 6 of 27 (2024), 13 of 48 (2025) → 19 of 75 (`outputs/runlog.csv`, `baseline_exploit_epss`)
- 31 visible (had public attack code) vs 44 blind spots (Person A's `st.group_of` definition)
- Simple rule on blind spots: 0. Our v5 model: 2, both Fortinet FortiOS (CVE-2025-24472, CVE-2024-23113)
  (`outputs/v5_blindspots.csv`, from `python -m src.b.leakage`, which reproduces the v5 headline bag: 12 + 9).
  **Say it honestly: small.** Without the Granite text features the same model catches 0 blind spots but 3 more visible
  ones (22 vs 21 overall), so the text is a trade-off, not a net gain.

## 3. What IBM Granite reads (open models, run locally)
**Message:** Granite reads the description the way an analyst would and recognises "this sounds like a past KEV entry."
- Example: CVE-2025-24472 (FortiOS, 2025): no public attack code, low risk score, so a blind spot. Granite's score
  puts it above 98% of 2025's CVEs. Its closest past KEV entry is CVE-2022-40684, the Fortinet authentication bypass
  added to KEV in 2022 (text similarity 0.90). Our model caught it. (`story.json → example`, `outputs/text_features.parquet`)
- Phrases that light up: "authentication bypass", "remote unauthenticated attacker", "super-admin privileges", "FortiOS".
- Leak guard: phrases that only appear after a CVE is known-exploited ("exploited in the wild", ...) are deleted before
  Granite reads anything. Removing them changed accuracy by less than 0.003 (`outputs/b_text_report.md`).

## 4. 2026 changed in July
**Message:** EPSS jumped ~6× from the July 2026 snapshot (cause unknown). January–May 2026 looked like past years.
The July–September snapshots are 62% of the 2026 list. A cut-off tuned on past years would break, so the model compares
each CVE only with others from the same month.
- Median EPSS: 0.043% (2024–25), 0.035% (Jan–May 2026), 0.274% (Jul–Sep 2026); Jul–Sep = 61.7% of the scoreboard
  (`story.json → heat`, `docs/figures/drift_epss.png`)
- Drift check (not a model score): a classifier can tell 2025 CVEs from 2026 CVEs with AUC 0.93 (`outputs/b_drift.json`)
- No June 2026 snapshot exists in the organisers' data; June's CVEs are scored in July.

## 5. Too good to be true (the leakage test)
**Message:** Some fields in today's database leak the answer. With them, our model would look like it catches 28
instead of 21, so we don't use them.
- Honest v5 bag 21 (12 + 9) vs with after-the-fact columns 28 (17 + 11) (`outputs/leakage_results.csv`; 29 was the earlier v4 run)
- 100% of CVEs added to KEV are marked "Analyzed" in today's NVD, vs 46% of the others (`story.json → leak`)
- No leak in the honest model: independent column review (`docs/column_review.md`) and Person A's audit (`outputs/v5_report.md`)

## 6. Our 500 for 2026, in plain groups
**Message:** These are the 500 CVEs we'd patch first, grouped by what they let an attacker do (from description
keywords; groups overlap, and each CVE is counted once, in its first matching group).
- 175 no login needed · 146 takes over the machine · 12 browser bugs · 8 read files they shouldn't · 7 get admin
  powers · 4 network edge devices · 4 database attacks · 1 WordPress plugin · 143 other kinds (`story.json → top`,
  list `outputs/top500_v5.csv`, groups from `txt_*` flags)
- Each one has a one-sentence reason (see section 8).

## 7. The honest result
**Message:** Tested on the past two years, we caught 21 CVEs that were added to KEV, against 19 for the best simple rule.
That's a small edge, and the uncertainty range says it could be luck. In the strictest test (train on 2024, test on
2025) we were one behind: 12 vs 13.
- v5 20-seed bag: 12 (2025) + 9 (2024) = 21 vs 13 + 6 = 19; pooled difference +2, 90% range −4 to +8;
  forward 12 vs 13 (−6 to +3); stability 9 vs 6 (`outputs/headline.json`)
- What we're sure of: the blind spots are real, EPSS jumped from July 2026, and we didn't use leaking data.

## 8. Granite reason examples (fill from the final list)
Two or three sentences from `outputs/explanations.csv` after Person A's IBM Granite Guardian gate (run locally via Ollama, PR #35) is merged: one that
passed the groundedness check and one that fell back to the plain template. Say that a checker rejects any sentence
mentioning a fact we didn't give it, and that Guardian checks groundedness (support by the facts), not truth.
- _[to fill once #35 is merged]_
