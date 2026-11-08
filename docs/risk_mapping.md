# Risk mapping: our risks and the IBM AI Risk Atlas

This maps the risks of the Before the Breach ranking model to risk names in the **IBM AI Risk Atlas**, with the mitigation we actually built and the file that shows it. Model details: `docs/model_card.md`.

**Where IBM technology runs.** IBM Granite and IBM Granite Guardian are open models that run locally on our own machines. **Nothing in this project runs on watsonx.** The mitigations below are our own code and tests; none is a watsonx governance feature.

## How the IBM names were obtained

- **Reached:** the index of the [IBM AI Risk Atlas](https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas). The risk names and category headings below are copied from it, and each name used here appears on that page. They were read by an automated page reader, so compare them with the live page before a submission.
- **IBM's definitions are not quoted.** The Atlas pages for the individual risks were not readable when I fetched them, so this file does not rely on IBM's own wording. Every description of a risk below is **our own, in our words, and is not IBM's definition**. Read IBM's page for what IBM means by each name.
- **No exact match exists for some of our risks.** No entry on the index page is named "data leakage", "drift" or "small sample". For those I chose the closest name, and the choice is our judgement, not IBM's. Where the fit is partial, the row says so.
- **Names seen but not used.** "Overfitting" and "Temporal gap" appear on the index page, but I could not confirm what they cover, so I do not rely on them.

## Quick look

IBM names and categories are copied from the index of the [IBM AI Risk Atlas](https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas).

| our risk | IBM AI Risk Atlas name (category) | mitigation we built | main file |
|---|---|---|---|
| data leakage (information from after the snapshot reaching the model) | **Data contamination** (Training data risks › Accuracy) | feature allow/ban guard; prior-31-December KEV cutoff; post-attack phrases stripped; independent column review; a labelled leakage experiment | `src/common/schema.py`, `docs/column_review.md`, `outputs/leakage_results.csv` |
| unfaithful explanations | **Hallucination** (Output risks › Robustness); **Unexplainable output** (Output risks › Explainability) | facts-only prompt; local checks; Granite Guardian groundedness gate; template fallback; honest labelling | `src/b/explain.py`, `outputs/explanations_summary.json` |
| distribution drift in 2026 EPSS | **Poor model accuracy** (Inference risks › Accuracy), closest fit | drift check; raw EPSS removed; EPSS ranked within each month; PSI-chosen transforms | `outputs/b_drift_report.md`, `outputs/v5_report.md` |
| few positives | **Poor model accuracy** (Inference risks › Accuracy); **Unrepresentative data** (Training data risks › Accuracy) | low-power labelling; intervals; 20-seed bag; placebo; forward test first; no claim of a gain | `outputs/headline.json`, `outputs/v5_report.md` |
| KEV coverage skew | **Unrepresentative data** (Training data risks › Accuracy) | **no correction built**; disclosure and wording only | `docs/page_content.md`, `docs/judge_qa.md` |

### What each IBM name means here: our descriptions, not IBM's

One line each, in our words, for how we use the name. They are not IBM's definitions; for those see the [IBM AI Risk Atlas](https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas).

| IBM AI Risk Atlas name (category) | what we mean by it (our description) |
|---|---|
| **Data contamination** (Training data risks › Accuracy) | Information that should not be available to the model gets in, so results look better than they are; for us, after-the-fact NVD columns or KEV information from after the snapshot. |
| **Hallucination** (Output risks › Robustness) | A generated sentence says something its source facts do not support; for us, a Granite reason that adds a claim we did not give it. |
| **Unexplainable output** (Output risks › Explainability) | It is hard to say why the model ranked a CVE where it did; for us, a 33-feature model bag whose one-sentence reasons explain only part of the ranking. |
| **Poor model accuracy** (Inference risks › Accuracy) | The model does not do its job well enough; for us, no clear gain over the simple rule, and inputs such as EPSS that moved in 2026. |
| **Unrepresentative data** (Training data risks › Accuracy) | What we learn from is not a fair sample of what we are scored on; for us, two practice years, and a label list (KEV) that leans toward enterprise and government software. |

## 1. Data leakage

**IBM name:** *Data contamination* (Training data risks › Accuracy). Our description is in the table above.
**Fit:** partial. The Atlas has no "data leakage" entry. Our risk is a specific kind of contamination: columns that NVD fills in *after* a CVE is attacked, or KEV information from after the snapshot, entering the features and making the model look better than it is.

**Mitigations we built:**

- **A feature guard.** `ALLOWED_FEATURES` and `BANNED_NAMES` with `check_feature_list` in `src/common/schema.py`; `tests/test_feature_guard.py` fails if a model uses a banned or unlisted name, and `src/models/train_v5.py` asserts the guard on the final feature list.
- **A fixed history cutoff.** Every KEV-based feature uses KEV rows dated on or before 31 December of the year before the pool; no 2026 KEV information is used (`CONTRACT.md`, "History-cutoff rule"; built in `src/features/build.py`).
- **Post-attack wording removed.** Phrases such as "exploited in the wild" are removed from descriptions before embedding and before the keyword flags (`src/b/phrases.py`). The description scan in `outputs/v5_report.md` ("Leakage audit") finds none left.
- **An independent column review** of every model input, with its source and whether it was known at the snapshot (`docs/column_review.md`).
- **A labelled leakage experiment, never submitted.** The same model with the banned columns added goes from 27 to 33 pooled hits (honest 18 + 9, with after-the-fact columns 21 + 12) (`src/models/train_v6.py`, `outputs/v6_leakage_results.csv`, copied into `outputs/v6_headline_candidate.json` under `leakage`; the v5 version, 21 to 28, is written up in `outputs/b_leakage_report.md`).
  It shows what leaked information looks like and that the submitted model does not have it.
- **Forward-in-time testing first**, so the headline test never trains on the future (`outputs/headline.json`).

**Not mitigated:** the guard checks column names, not how a column was computed (`docs/column_review.md`, limit 4). Descriptions are today's NVD text and may have been edited after publication (limit 1).

## 2. Unfaithful explanations

**IBM names:**

- *Hallucination* (Output risks › Robustness). The closest fit for Granite writing a claim that is not in the facts we gave it.
- *Unexplainable output* (Output risks › Explainability). Covers the wider point that a 33-feature model bag is hard to explain, which a one-sentence reason only partly addresses.

**Fit:** partial. Neither name says "unfaithful explanation"; these are the two nearest.

**Mitigations we built** (`src/b/explain.py`, header and `BLOCKED_PHRASES`):

- **Facts only.** Each sentence is built from tracked files: EPSS percentile, exploit flags, text tags, Granite scores, and the final model's contributions grouped by feature (`outputs/v5_top500_contrib.parquet`).
- **Local checks.** A draft is rejected if it contains a number, name, CVE id or claim that is not in the facts, or a blocked phrase (predictions, severity words, causal links). `tests/test_explain.py` exercises every pattern in the list.
- **A Granite Guardian groundedness gate.** Guardian (`granite3-guardian:2b`, run locally) must clearly answer "No"; "Yes", empty, unparseable, a timeout or any error means the plain template sentence is used.
- **Honest labelling.** No sentence is labelled Guardian-checked unless Guardian returned "No" for it. `outputs/explanations.csv` has `source` and `guardian_verdict` for every row.
- **Counts published, not asserted.** In `outputs/explanations_summary.json`, 347 Granite sentences were kept after a Guardian "No" (`passed_guardian`) and 153 rows use the template (`template_fallback`): Guardian answered "Yes" for 78, and 75 drafts failed a local check and never reached Guardian (`guardian_verdicts`), out of 500 (`total`).

**Not mitigated:** Guardian checks that a sentence is *supported by the facts*, not that the facts are true, not causality, and not that they are the full reason the model ranked a CVE highly. So we write "passed a groundedness check", never "verified" (`docs/judge_qa.md`).

## 3. Distribution drift in 2026 EPSS

**IBM name:** *Poor model accuracy* (Inference risks › Accuracy). Our description is in the table above.
**Fit:** closest available. The Atlas index has no drift entry; we use this name because inputs that shift after training can lower accuracy.

**The evidence:** a classifier can tell 2025 practice CVEs from 2026 scoreboard CVEs with ROC AUC 0.934, and EPSS is the main reason (`outputs/b_drift_report.md`). EPSS jumped about 6× from the July 2026 snapshot, cause unknown (`docs/writeup_person_b.md`, section 3).
Raw EPSS has a PSI of 2.866 against the scoreboard (`outputs/v4_report.md`).

**Mitigations we built:**

- **A drift check** that compares every feature in the practice years with the 2026 scoreboard (`src/b/drift.py` → `outputs/b_drift_report.md`).
- **Raw EPSS removed from the model** (`RAW_REMOVED` in `src/common/schema.py`; `tests/test_feature_guard.py` and `src/models/train_v5.py` assert it is absent).
- **EPSS ranked within its own snapshot month** (`epss_rank_in_month`), so a month-wide jump cannot move the ranking (`CONTRACT.md`).
- **Every other scale-sensitive feature uses the form (raw, rank or share) with the lowest PSI**, chosen before looking at hits (`V5_TRANSFORMS`, `src/features/drift_fix.py`; `tests/test_drift_fix.py` recomputes the choice and fails if it changes; PSI table in `outputs/v5_report.md`).

**Not mitigated:** some assigner-history features and `days_to_cutoff` still have a PSI above 0.25 after the treatment (`outputs/v5_report.md`), so the practice years remain an imperfect guide to 2026.

## 4. Few positives

**IBM names:**

- *Poor model accuracy* (Inference risks › Accuracy), read honestly: with this little data the model's performance may not beat the simple rule.
- *Unrepresentative data* (Training data risks › Accuracy). Two practice years are a thin sample of what 2026 will look like.

**Fit:** partial. The Atlas has no small-sample entry; these are the nearest.

**The evidence:** 27 positives in 2024 and 48 in 2025 (`outputs/headline.json`, `positives`), 75 in total.

**Mitigations we built:**

- **Low power is stated wherever results appear.** `outputs/headline.json` (`note`), `outputs/v5_report.md` (opening banner and "How strong is the evidence?").
- **Intervals, not single numbers.** 90% bootstrap ranges, CVE-level and event-clustered, for forward and pooled results (`outputs/headline.json`).
- **A 20-seed bag, with the spread of single seeds reported** (`outputs/headline.json`, `seeds`).
- **A like-for-like placebo** against shuffled text columns (`outputs/headline.json`, `seeds.placebo`, `placebo_bootstrap_p`).
- **Small trees, and settings chosen by month-held-out cross-validation on the training year only**, never on a test year (`CONTRACT.md`, "Model rules"; parameters in `outputs/v5_report.md`).
- **Forward direction reported first; the reverse direction labelled "NOT forward in time"** (`outputs/v5_report.md`, `outputs/leakage_results.csv`).
- **We claim only a small-sample gain.** Forward the model is five ahead of the simple rule (18 vs 13); pooled it is 27 vs 19 with a range of +2 to +14 (`outputs/v6_headline_candidate.json`), on 75 positives.

**Not mitigated:** more data was not available. We cannot tell 21 from 19.

## 5. KEV coverage skew

**IBM name:** *Unrepresentative data* (Training data risks › Accuracy), the same name as in section 4. Here the issue is the **label**: KEV lists what CISA tracks, which skews toward enterprise and government software, so a model trained on it learns "what gets added to KEV", not "what gets attacked".
**Fit:** partial. The Atlas does not describe a biased label source separately.

**Mitigations we built: none that changes the model.** We did not reweight, rebalance or correct for the skew. Because the target is KEV, vendor and assigner KEV-history features carry the tilt by design. What we did build is disclosure:

- **The limitation is stated wherever trait numbers appear:** "KEV skews toward enterprise and government-relevant software, so WordPress plugins and cross-site scripting look safe here although they are widely attacked in practice" (`docs/page_content.md`, "Limitation").
- **Wording:** we say "added to CISA KEV", never "attacked" (`docs/judge_qa.md`). `scripts/number_sweep.py` checks our documents for banned wording and for numbers that do not match the outputs.
- **The descriptive trait analysis is kept out of the model.** It uses today's NVD fields and is never a model input (`tests/test_site_data_isolation.py`; `outputs/why_attacked_report.md`).
- **The intended-use limits say a low rank is not a safety claim** (`docs/model_card.md`, sections 8 and 9).

**Not mitigated:** the skew itself. A CVE in software CISA does not track is under-counted in both our training labels and our test labels.
