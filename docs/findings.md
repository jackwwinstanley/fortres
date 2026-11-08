# What is fortres, and what we found

Every number on this page comes from a file in this repository, and `scripts/number_sweep.py` compares them with those files.
Results marked "in our 2024 and 2025 test" come from the practice years: we trained on one year, ranked the other, and
checked which holes CISA later added to its Known Exploited Vulnerabilities (KEV) list.

## What is fortres?

Fortres is a triage system for security holes: a statistical model ranks all 72,670 of 2026's new vulnerabilities and picks the 500 to fix first, ranked by the warning signs known at the time, and IBM Granite models help read the descriptions and explain every pick in plain language.

- **The ranking is 20 models that vote, each built from 150 small decision trees.** It is not a chatbot. It's fast, it can be tested against what really happened, and it runs on a laptop.
- **IBM Granite does the reading and the explaining.** Granite Embedding reads each description and gives the ranking one clue. Granite 3.3 writes a one-sentence reason for each pick, and Granite Guardian checks that reason against the facts. If it fails, a plain template sentence is used instead.
- **What it is not.** It doesn't predict who gets attacked. The language model never decides the ranking. And it still misses most holes that give no warning.

## What we found

### 1. Most holes on CISA's list gave no warning
**44 of the 75.** In our 2024 and 2025 test, 44 of the 75 exploited holes had no public attack code and a low EPSS score. The usual rule catches 0 of them, and fortres caught 5, three of which come from one Ivanti event.
**Why it matters:** any rule built on those two signs cannot see this group. The gap is real, and most of it is still open.
**Source:** `outputs/v6_blindspots.csv`, `outputs/discovery_events.csv` (the Ivanti event).

### 2. Severity labels hide danger
**1 in 9.** Of the 1,484 entries added to CISA's list from 2021 to 2025, 162 of 1,484 are rated only Medium by CVSS 3.
**Why it matters:** a team that fixes Critical and High first reaches these last.
**Source:** `outputs/discovery_kev_severity.csv`, written by `scripts/discovery_tables.py`.

### 3. Data that arrives after an attack makes results look better than they are
**27, not 33.** In our 2024 and 2025 test, adding fields NVD fills in later would raise 27 catches to 33. The fields are `nvd_status`, `n_affected_cpes`, `n_references`, and whether CVSS 3, CVSS 4 and CWE are blank or filled.
**Why it matters:** NVD reviews holes on CISA's list first, so every one of them is marked "Analyzed", against 42% (2024) and 50% (2025) of the rest. That field is close to the answer itself, so we left these out.
**Source:** `outputs/v6_leakage_results.csv`, `docs/column_review.md`, `src/b/leakage.py` (the field list).

### 4. Outside data can carry hindsight dates
**249 of 490.** In Metasploit, for 249 of the 490 pairs of a hole and a module, the link to the hole was added more than 30 days after the attack module itself. Some 2025 holes are new numbers for exploits from 2010, such as CVE-2010-10015. VulnCheck's KEV dates match the first exploitation report in 5,803 of 5,809 entries, which looks like backfilling.
**Why it matters:** a date that looks like "known on this day" can be written years later. We rejected VulnCheck for this, dated Metasploit by when the link was added, and adopted neither.
**Source:** `outputs/newdata_provenance.md`, `outputs/outside_report.md`.

### 5. Simpler beat clever
**7 + 11 tried, one kept.** We declared 7 model variants (one, XGBoost, could not run because the library was not installed) and tested 11 extra methods. In our 2024 and 2025 test the winner was the more constrained model, and no extra method passed the rule we fixed first.
**Why it matters:** that constraint is also why rare signals add nothing. The model needs 200 rows in each leaf and only about 140 practice holes have a dated Nuclei template, so those flags can never be used.
**Source:** `outputs/rank_summary.csv`, `outputs/rank_report.md`, `outputs/zoo_summary.md`, `outputs/newdata_report.md`.

### 6. Attackers return to the same vendors
**19 to 10.** In our 2024 and 2025 test, holding out whole vendors from training cuts the 2025 cross-validation from 19 catches to 10. In 2024 it moves only from 7 to 6.
**Why it matters:** a vendor's track record is a strong clue, and that is also a limit. A brand-new vendor gets less help.
**Source:** `outputs/rank_vendor_cv.csv`.

### 7. Attacks come in bursts
**67 events behind 75 holes.** In our 2024 and 2025 test the 75 holes come from 67 separate events, where one vendor's holes are added to CISA's list on the same day.
**Why it matters:** linked holes are not independent evidence, so we also report ranges that resample whole events. For our lead of +8 that range is +1 to +15, next to +2 to +14 when each hole counts on its own.
**Source:** `outputs/discovery_events.csv`, `outputs/headline.json` (`pooled.diff_event_clustered_90`).

### 8. The AI's reasons needed a referee
**182 of 500.** Granite Guardian rejected 90 reasons and 92 more failed our own checks, so 182 picks show a plain template sentence. The most common failure was a word that isn't in the facts (91 drafts).
**Why it matters:** a language model writes fluent sentences that go beyond what it was given, so nothing it writes is shown unchecked.
**Source:** `outputs/explanations_summary.json` (`guardian_verdicts`, `local_check_failures`).

### 9. Less work for the same catch
**441 fixes, not 10,026.** Fortres caught those 27 with a list of only 441 fixes in our 2024 and 2025 test. To reach the same 27, the usual rule would have to go 1,116 deep, sorting by severity 6,858, and EPSS alone 10,026.
**Why it matters:** the order decides how much of a team's time goes to holes nobody uses. The depths add the two test years together, and fortres's 27th catch is at position 353, so 441 is the cautious figure.
**Source:** `outputs/discovery_workload.csv`, written by `scripts/discovery_tables.py`.

### 10. Risk scores jumped in July 2026
**6.37×.** From the July 2026 snapshots on, EPSS scores were 6.37 times the 2024 to 2025 median, so fortres compares each hole only with others scored in the same month.
**Why it matters:** a model trained on raw scores would treat most of 2026 as high risk. We compared median with median, and we don't know why the scores rose.
**Source:** `outputs/discovery_epss_jump.csv`, written by `scripts/discovery_tables.py`.
