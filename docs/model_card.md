# Model card: Before the Breach ranking model (v6)

**Status:** final. The model is the 20-seed LightGBM bag called v6 (v5's features with regularised settings), chosen from seven declared variants by a rule fixed before any result (`outputs/rank_report.md`, `outputs/v6_report.md`); the list is `outputs/top500_v6.csv`. v5 is the previous model (`docs/considered_not_adopted.md`).
**LOW POWER:** the model is tested on 75 CVEs added to CISA KEV in two practice years, so no result below is strong evidence of a gain.

**Where IBM technology runs.** IBM Granite and IBM Granite Guardian are open models that run locally on our own machines. **Nothing in this project runs on watsonx.**
`src/b/embed.py` loads the Granite embedding model with sentence-transformers; `src/b/explain.py` loads `granite-3.3-2b-instruct` with transformers and calls Guardian through a
local Ollama server (`http://localhost:11434`). A search of `src/`, `scripts/`, `tests/`, `app/` and `requirements.txt` finds no call to watsonx (only two planning strings in `scripts/create_board.py` mention it).

How to read the citations: every number below is read from a file in the repo, and the file is named next to it. `python scripts/number_sweep.py` checks the repo's documents against
`outputs/headline.json`, `outputs/v6_leakage_results.csv`, `outputs/v6_blindspots.csv` and `outputs/explanations_summary.json`.

## 1. Purpose

Rank the 72,670 CVEs in `data/scoreboard_2026.csv` so that the 500 at the top contain as many as possible of the CVEs CISA adds to its Known Exploited Vulnerabilities (KEV) catalog by 2026-11-04 (`README.md`).

The thing being ranked for is **a listing event, "added to CISA KEV after the end of its snapshot month"**. It is not "attacked", and it is not a probability of attack. Output: the ranked list
`outputs/top500_v6.csv`, and one plain-English reason per CVE in `outputs/explanations.csv`, written for the v6 list (`top_list` in `outputs/explanations_summary.json`; `outputs/v6_missing_explanations.csv` lists none missing).

## 2. Model

- **What it is:** a bag of 20 LightGBM models (`outputs/headline.json`, `seeds.bag_seeds`), each seed's scores rank-normalised within the pool and averaged; ties broken by `epss_rank_in_month`, then `cve_id` (`outputs/v6_report.md`, "Final settings and list").
- **Trained on:** both practice years (2024 and 2025 replicas) for the final list. For testing, it is trained on one year and scored on the other (section 4).
- **Settings:** chosen by cross-validated average precision with whole snapshot months held out, never on a test replica (`CONTRACT.md`, "Model rules"). v6 searched candidate I's small regularisation grid (shallower trees, larger leaves, fewer features per tree, stronger L2) with the same rule; the final parameters are `final_params` in `outputs/headline.json`.
- **The practice years ("replicas")** copy how 2026 is scored: CVEs published January to September of the year, not already on KEV at the end of their snapshot month, labelled 1 if CISA adds them to KEV after that month and by 4 November of that year (`CONTRACT.md`, "Exact replica definition"; built by `src/replicas.py`).
  Positives: 27 in 2024 and 48 in 2025 (`outputs/headline.json`, `positives`).
- **Compared against:** the best simple rule, "public exploit code first, then highest EPSS" (called `Exploit code, then EPSS` in `outputs/leakage_results.csv`).

## 3. Data

### 3.1 What we take from each source file (`data/`, not committed)

| source | what the model uses |
|---|---|
| `exploit_signals_2024.csv`, `exploit_signals_2025.csv`, `scoreboard_2026.csv` | `epss` and the four exploit-code flags, as of the end of `snapshot_month` |
| `vulnerabilities.csv` | `published`, `assigner`, and the `description` text only |
| `known_exploited.csv` (KEV) | the label, and KEV history dated on or before 31 December of the year before the pool |

### 3.2 Every column the final model uses (33)

The list is `ALLOWED_FEATURES` in `src/common/schema.py` (which equals `V5_FEATURES`). `src/models/train_v5.py` sets `FEATURES_V5 = list(ALLOWED_FEATURES)`, asserts that the feature guard passes, and asserts raw `epss` is absent.

| group | columns | built from |
|---|---|---|
| EPSS (2) | `epss_missing`, `epss_rank_in_month` | EPSS at the end of the snapshot month. The rank is the percentile **within the same snapshot month and pool**. Raw `epss` is **not** a model column (section 8). |
| Exploit code (6) | `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_flags`, `any_exploit` | the four flags at the end of the snapshot month, their count and their maximum |
| Timing (2) | `days_to_snapshot`, `days_to_cutoff` | calendar arithmetic from the publish date, the end of the snapshot month and 4 November |
| Assigner history (4) | `assigner_prior_cves_pctrank`, `assigner_kev_share`, `assigner_kev_12m_share`, `assigner_kev_rate_smooth_pctrank` | CVEs and KEV rows of the same assigner dated on or before the prior 31 December. `_pctrank` = percentile rank within the pool; `_share` = scale-free share of everything known by that cutoff |
| Vendor history (3) | `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max` | vendor names found in the description, matched to the KEV vendor list as of the prior 31 December |
| Granite text scores (2) | `kev_text_score`, `nearest_kev_sim` | description embedded with `ibm-granite/granite-embedding-30m-english` after post-attack phrases are removed; a logistic regression trained only on earlier CVEs, and the closest cosine similarity to KEV entries added by the prior 31 December |
| Keyword flags (14) | `txt_rce`, `txt_unauth`, `txt_auth_bypass`, `txt_cmd_injection`, `txt_deserialization`, `txt_path_traversal`, `txt_sqli`, `txt_priv_esc`, `txt_memory`, `txt_edge_device`, `txt_enterprise`, `txt_browser`, `txt_wordpress`, `txt_xss` | regular expressions on the description |

For each scale-sensitive history feature the form (raw, rank or share) was chosen by drift alone, never by hits (`V5_TRANSFORMS` in `src/common/schema.py`; the PSI table is in `outputs/v5_report.md`).
Column-by-column time-safety review: `docs/column_review.md`.

### 3.3 Columns we excluded, and why

The datathon README warns that NVD fills in some fields after an attack (`docs/DATA_DICTIONARY.md`, "Watch out for"). The repo README lists what the model does not use (`README.md`); the rule is in `CONTRACT.md` ("BANNED").

| column | why it is excluded |
|---|---|
| `nvd_status` | NVD reviews KEV-listed CVEs first, so the status is filled in *because of* the attack. Every KEV addition in both practice years is `Analyzed` in today's NVD, against 42% (2024) and 50% (2025) of the other CVEs (`docs/column_review.md`, "Why the banned list matters"). |
| `n_affected_cpes` | the number of product rows in today's `affected_products.csv`; product details are added after an attack (`docs/DATA_DICTIONARY.md`) |
| `n_references` | the number of links in today's `references.csv`; links are added after an attack (`docs/DATA_DICTIONARY.md`) |
| blank vs filled severity scores (CVSS 3, CVSS 4, CWE) | scores stay blank until NVD analyses the CVE, and NVD analyses KEV first, so blankness stands in for the status |
| news and threat references (`references.csv` links, tag `Exploit`, links to exploit-hosting sites) | links to security-company research or news are often added after an attack (`docs/DATA_DICTIONARY.md`) |

Also not used: NVD-sourced CVSS scores (CVSS appears only in the CVSS-first baseline), `cwe_ids`, `affected_products.csv`, `last_modified`, the signals file's `in_kev` (used only to drop already-listed CVEs from the pool), KEV rows added after the snapshot,
and any 2026 KEV information. Post-attack phrases ("exploited in the wild" and similar) are removed from descriptions before embedding and before the keyword flags (`src/b/phrases.py`).
The guard is `BANNED_NAMES` and `check_feature_list` in `src/common/schema.py`, tested by `tests/test_feature_guard.py`. These columns appear only in the labelled leakage experiment (section 5).

### 3.4 The time rule: rank using only what was known at the end of `snapshot_month`

- Signals (EPSS, exploit flags) are the values at the end of the CVE's `snapshot_month` (`docs/DATA_DICTIONARY.md`, `scoreboard_2026.csv`).
- Every KEV-based feature uses a fixed cutoff, **31 December of the year before the pool** (2023 for the 2024 replica, 2024 for the 2025 replica, 2025 for the 2026 scoreboard); no 2026 KEV information is ever used (`CONTRACT.md`, "History-cutoff rule").
- The text classifier is trained only on CVEs published before the pool year (`CONTRACT.md`).
- EPSS is ranked within its own snapshot month, so a CVE is compared only with CVEs scored in the same month.
- Testing goes forward in time first (section 4).

## 4. Evaluation

A **hit** is a CVE added to KEV after its snapshot month that lands in the top *k*. *k* scales 500 to each pool's size (`CONTRACT.md`, "Scoring rule"); the values are in `outputs/leakage_results.csv`.
The interval is a 90% bootstrap range for (v6 bag minus the simple rule). "CVE-level" resamples CVEs; "event-clustered" treats positives added to KEV by the same vendor on the same date as one event (`outputs/v6_report.md`, `outputs/v6_bootstrap.csv`).

| test | k | positives | v6 bag | simple rule | difference | 90% interval, CVE-level / event-clustered | v5 (previous) | v6 − v5, 90% CVE-level / event-clustered |
|---|---|---|---|---|---|---|---|---|
| **forward:** train 2024, test 2025 | 243 | 48 | 18 | 13 | +5 | 0 to +10 / −2 to +12 | 12 | +6: +2 to +10 / +1 to +12 |
| stability: train 2025, test 2024 (**not forward in time**) | 198 | 27 | 9 | 6 | +3 | 0 to +7 / 0 to +7 | 9 | +0: −2 to +2 / −2 to +2 |
| **pooled** | 441 | 75 | 27 | 19 | +8 | +2 to +14 / +1 to +15 | 21 | +6: +2 to +11 / +1 to +13 |

Sources: bag and rule hits, intervals and positives from `outputs/headline.json` and `outputs/v6_bootstrap.csv`; *k* from `outputs/leakage_results.csv`; differences and the pooled *k* are subtractions and a sum of those.

What this does and does not show:

- Forward in time, the model is **five hits ahead** of the simple rule. In the other direction it is three ahead. Pooled it is eight ahead (interval +2 to +14). With 75 positives that is still a small sample, and on matched seeds v6 beats v5 by only +2 to +5 (`outputs/v6_seed_spread.csv`).
- Single seeds of the same model average 26.75 pooled hits (lowest 25, highest 28) (`outputs/headline.json`, `seeds`), so one seed's result is not a safe number.
- Seed sets: forward is 18 on all four seed sets and pooled 26 to 28 (`outputs/v6_seed_spread.csv`).
- The 2026 list: 498 of 500 have public exploit code; 193 are also in the simple rule's top 500 and 429 in v5's (`outputs/v6_overlap.csv`).
- A like-for-like placebo compares 30 real 5-seed bags with 30 bags trained on labels shuffled within each month: 27.0 against 0.57 pooled hits (`outputs/v6_placebo.csv`). It shows the model learns from the labels; it does not by itself show the model beats the simple rule.
- Other simple rules, pooled hits over both directions (`outputs/leakage_results.csv`): highest CVSS 3 first 5, highest EPSS first 11, exploit code then EPSS 19.

## 5. Leakage result

We deliberately re-ran the same model with the banned after-the-fact columns added (NVD status, CPE and reference counts, blank-vs-filled CVSS and CWE, NVD-sourced CVSS 3, exploit-tagged links; `src/b/leakage.py`). **This model is never submitted.**

| model | forward (train 2024, test 2025) | stability (train 2025, test 2024) | pooled |
|---|---|---|---|
| honest (the submitted model) | 18 | 9 | 27 |
| with after-the-fact columns | 21 | 12 | 33 |

Source: `outputs/v6_leakage_results.csv`, copied into `outputs/headline.json` (`leakage`). Adding the columns lifts the same model from 27 to 33, which shows what leaked information looks like. The honest model does not have them.

## 6. Blind spots

A **blind spot** is a KEV addition with no public exploit code (Exploit-DB, Metasploit, Nuclei, GitHub proof of concept) and a within-month EPSS rank too low to reach a top-*k* EPSS list (`group_of` in `src/models/stress_v2.py`). Source: `outputs/v6_blindspots.csv` (simple rule vs v5 vs v6: `outputs/v6_blindspots_compare.csv`), summed over both years.

| group | KEV additions | caught by the simple rule | caught by v6 |
|---|---|---|---|
| flagged (public exploit code) | 31 | 19 | 22 |
| **blind spot** | **44** | **0** | **5** |
| unflagged but EPSS-visible | 0 | 0 | 0 |
| all | 75 | 19 | 27 |

- **44 of the 75** KEV additions are blind spots. The simple rule cannot catch them by construction, and the v6 model catches 5: `CVE-2024-13159`, `CVE-2024-13160`, `CVE-2024-13161` (one Ivanti EPM event), `CVE-2025-24472` and `CVE-2024-23113` (`ours_caught_cves` in `outputs/v6_blindspots.csv`).
- The two catches come from the text features (keyword flags and Granite similarity). In the ablation in `docs/writeup_person_b.md` (section 1), removing one text part still leaves some blind-spot catches and removing both leaves none, and the exact CVEs change between runs. **Two catches is within noise.** We report the blind spots as the finding, not the two catches as a result.
- Without any text features the model catches more flagged CVEs, so the text features trade visible catches for blind-spot catches rather than adding net hits (`docs/writeup_person_b.md`, section 1).

## 7. Explanation layer

Each of the 500 picks gets one sentence of the form "Prioritised because ..." that restates at most three facts (`README.md`, "Explanations").

- **Facts:** built only from tracked files: EPSS percentile and exploit flags (`outputs/features_scoreboard.parquet`), text tags and Granite scores (`outputs/text_features.parquet`) and the final model's contributions grouped by feature (`outputs/v5_top500_contrib.parquet`) (`src/b/explain.py`, header).
- **Writing:** IBM Granite (`ibm-granite/granite-3.3-2b-instruct`, run locally) rewrites the facts into one sentence.
- **Local checks:** a draft is rejected if it contains a number, name, CVE id or claim that is not in the facts, or a blocked phrase (for example "actively", "in the wild", "critical", "confirmed"). The list is `BLOCKED_PHRASES` in `src/b/explain.py`, tested by `tests/test_explain.py`.
- **Guardian gate:** IBM Granite Guardian (`granite3-guardian:2b`, run locally via Ollama, risk = groundedness) must clearly answer "No" (no risk). "Yes", empty, unparseable, timeout or any error means the plain template sentence is used instead.
- **Honest labelling:** no sentence is labelled Guardian-checked unless Guardian returned "No" for it. `outputs/explanations.csv` records `source` and `guardian_verdict` per row.

Counts, read from `outputs/explanations_summary.json`:

| item | count | field |
|---|---|---|
| CVEs with a reason | 500 | `total` |
| Granite sentences kept (Guardian answered "No") | 318 | `passed_guardian`, `guardian_verdicts.No` |
| template sentences used | 182 | `template_fallback` |
| of those: Guardian answered "Yes" | 90 | `guardian_verdicts.Yes` |
| of those: draft failed a local check, never shown to Guardian | 92 | `guardian_verdicts.not_run` |
| Granite drafts sent to Guardian | 408 | `rewritten` |
| rows still pending | 0 | `pending` |

The file also records the models (`granite_model`, `guardian_model`), `prompt_version` and `generated_at`. Why the local checks rejected drafts is tallied in `local_check_failures`.

**What the gate means.** Guardian checks that a sentence is *supported by the facts we gave Granite*. It does not check that the facts are true about the world, it does not check causality, and the facts themselves are a summary of the model's main drivers, not a full account of why a score is high.
So the wording is "passed a groundedness check", never "verified" (`docs/judge_qa.md`).

## 8. Known limits

1. **Low power.** 75 positives (`outputs/headline.json`, `positives` and `note`), from a few dozen KEV events. The forward event-clustered interval includes zero and negative values (section 4), and on matched seeds the gain over v5 is only +2 to +5 (`outputs/v6_seed_spread.csv`).
   **Vendor familiarity:** holding out whole vendors roughly halves v5's 2025 in-year hits (19 → 10; `outputs/rank_vendor_cv.csv`), so part of the in-year skill is recognising vendors already seen.
2. **The stability direction is not forward in time.** Training on 2025 and testing on 2024 uses the future to predict the past. It is reported second for that reason.
3. **Drift in 2026.** A classifier can tell 2025 practice CVEs from 2026 scoreboard CVEs with ROC AUC 0.934, and EPSS is the main reason (`outputs/b_drift_report.md`). EPSS jumped about 6× from the July 2026 snapshot; the cause is unknown (`docs/writeup_person_b.md`, section 3).
   Raw EPSS is therefore **removed** (its PSI against the scoreboard is 2.866, `outputs/v4_report.md`) and replaced by the within-month rank. Some assigner-history features and `days_to_cutoff` still have a PSI above 0.25 after the treatment (`outputs/v5_report.md`), so the practice years are an imperfect guide to 2026.
4. **KEV coverage skew.** KEV skews toward enterprise and government software, so a trait such as "WordPress plugin" or "cross-site scripting" looks safe in KEV data although those are widely attacked in practice (`docs/page_content.md`, "Limitation"). Because the target *is* KEV, features such as vendor and assigner KEV history carry that tilt by design. We did not correct for it.
5. **Descriptions are today's NVD text**, which can be edited after publication. Post-attack phrases are stripped, but this remains a limit (`docs/column_review.md`, limit 1).
6. **The feature guard checks names, not how a column was computed.** The column review is the check on computation (`docs/column_review.md`, limit 4).
7. **The June 2026 snapshot uses July signals** because June 2026 signals are missing, a gap in the organisers' data (`docs/DATA_DICTIONARY.md`).
8. **The Granite-derived scores are kept but not claimed to add hits.** The ablation shows them neutral within noise (`README.md`, "Final feature set").
9. **The explanations come from a 2-billion-parameter model** and a small groundedness checker; 182 of the sentences fall back to a template (section 7).
10. **We do not know the 2026 answer.** We cannot say how many of our 500 will be added to KEV.

Ideas we tested and left out are in `docs/considered_not_adopted.md`.

## 9. Intended use

**Use it as a prioritisation aid.** It orders a patch queue, alongside EPSS and exploit-code information, so a person can look first at CVEs that resemble past KEV additions, with a reason they can check. It is meant to add a view, not to replace one.

**It is not a prediction of attacks.** The score is not a probability, and "added to KEV" is not "attacked" (`docs/judge_qa.md`, wording rules).

Do not use it:

- as a statement that a low-ranked CVE is safe. KEV is not a complete record of attacks (limit 4), and 44 of the 75 KEV additions were blind spots the standard signals could not see (section 6);
- to replace analyst judgement, or to decide on its own which systems to patch;
- for one organisation's risk. The model knows nothing about your assets, exposure or patch state;
- on another period or a pool built differently from the 2026 scoreboard without re-running the drift check (`python -m src.b.drift`);
- as proof that Granite or Guardian "explains" the model. Each reason is a groundedness-checked restatement of a few facts.

Wording rules we follow: "added to CISA KEV" (not "attacked"), "associated with" (not "causes"), "passed a groundedness check" (not "verified") (`docs/judge_qa.md`).

## 10. Where each number comes from

| file | numbers taken from it |
|---|---|
| `outputs/headline.json` | forward, stability and pooled hits; baseline hits; intervals; positives; seed spread; the `leakage` block |
| `outputs/v6_leakage_results.csv` | honest and leaky hits per direction; *k*; other simple rules |
| `outputs/v6_blindspots.csv`, `outputs/v6_blindspots_compare.csv` | blind-spot, flagged and EPSS-visible counts; the five blind-spot CVEs caught; rule vs v5 vs v6 |
| `outputs/explanations_summary.json` | explanation counts, models, prompt version |
| `outputs/v6_report.md`, `outputs/v6_bootstrap.csv`, `outputs/v6_seed_spread.csv`, `outputs/v6_placebo.csv`, `outputs/v6_overlap.csv` | intervals vs the rule and vs v5, seed sets, placebo, list overlap |
| `outputs/v5_report.md`, `outputs/v4_report.md`, `outputs/b_drift_report.md` | the drift figures (PSI, ROC AUC), v5's settings |

Risk names and the mitigations behind them: `docs/risk_mapping.md`.
