**What is fortres?** Fortres is a triage system for security holes: a statistical model ranks all 72,670 of 2026's new vulnerabilities and picks the 500 to fix first, ranked by the warning signs known at the time, and IBM Granite models help read the descriptions and explain every pick in plain language.
The ranking is 20 models that vote, each built from 150 small decision trees, not a chatbot; IBM Granite reads the descriptions for one clue and writes a checked one-sentence reason for each pick.

# IBM "Before the Breach" – predicting which CVEs get exploited

Sheridan Datathon 2026. Rank the 72,670 CVEs in `data/scoreboard_2026.csv` and submit
`top500.csv` (one column `cve_id`, 500 unique IDs). Judges count how many were added to
CISA KEV by 2026-11-04. Only information known at the snapshot may be used; see `CONTRACT.md`.

**Live site:** https://fortres.us, served from a Vultr server (every response carries `X-Served-By: Vultr`; setup in [deploy/README.md](deploy/README.md)).

## What we found
All four are from files in this repository; the full list of ten, with sources, is in [docs/findings.md](docs/findings.md).
1. **Most holes on CISA's list gave no warning.** In our 2024 and 2025 test, 44 of the 75 had no public attack code and a low EPSS score. The usual rule catches 0 of them, and fortres caught 5, three of which come from one Ivanti event.
2. **Severity labels hide danger.** 1 in 9 entries added to CISA's list from 2021 to 2025 (162 of 1,484) is rated only Medium.
3. **Data that arrives after an attack makes results look better than they are.** In our 2024 and 2025 test, fields NVD fills in later would raise 27 catches to 33, so we left them out.
4. **Less work for the same catch.** Fortres caught those 27 with a list of only 441 fixes in our 2024 and 2025 test. To reach the same 27, the usual rule would have to go 1,116 deep, sorting by severity 6,858, and EPSS alone 10,026.

## Reproduce the final list
This rebuild **rewrites `outputs/` in place**, so run it in a fresh clone, not in a working copy with changes.
```
git clone https://github.com/jackwwinstanley/ibm-breach.git && cd ibm-breach
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt                         # pinned versions
# put the datathon CSVs in ./data (not committed)
cp outputs/top500_v5.csv /tmp/top500_v5_committed.csv   # keep the committed list for the comparison
python -m src.replicas                                  # practice pools (2024, 2025)
python -m src.features.build                            # features
python -m src.models.train_v5                           # previous model (v5) -> outputs/top500_v5.csv
python scripts/check_top500.py outputs/top500_v5.csv    # format check: PASS
cmp outputs/top500_v5.csv /tmp/top500_v5_committed.csv && echo "identical"   # byte-for-byte
python -m src.models.train_v6                           # primary model (v6) -> outputs/top500_v6.csv and its checks
python scripts/check_top500.py outputs/top500_v6.csv    # format check: PASS
```
v6 is the primary model (`src/common/primary.py`); `train_v6` reuses v5's features and data steps above. In a fresh clone
`python -m src.models.train_v6` took 6 min 23 s with no caches, including its checks (placebo, leakage, seed sets), and
rewrote `outputs/top500_v6.csv` byte-for-byte identical to the committed file. The v5 timing below is for the v5 steps.

**Both checkers need the competition data.** `scripts/check_top500.py` and `scripts/check_contract.py` compare the IDs with
`data/scoreboard_2026.csv`. Without `data/` they stop with one line, "needs data/scoreboard_2026.csv (competition data, not
in the repo)", and a non-zero exit. The rebuild steps say the same about `data/vulnerabilities.csv`. `pytest -q` runs
without `data/` (3 tests that need it are skipped).
- **Time:** a full rebuild takes about 10 minutes on a laptop CPU. In a fresh clone it took 8 min 38 s: replicas 1 s,
  features 6 s, train_v5 8 min 30 s (most of it hyper-parameter grids and the placebo). Allow up to ~30 minutes on a
  slower machine.
- **Text features:** the description/embedding step (`python -m src.b.texts && python -m src.b.embed && python -m src.b.text_features`)
  needs the IBM Granite embedding model locally and is **optional**: `outputs/text_features.parquet` is tracked, so the
  rebuild above uses the committed text features.
- **Tested on:** the result was byte-for-byte identical on Python 3.14.7, macOS 27.2 arm64, with the pinned
  `requirements.txt`. The pins were first checked on Python 3.14.5, macOS arm64.
- **Other files it rewrites:** besides the identical list, the rebuild adds rows to `outputs/runlog.csv` and regenerates
  `outputs/v5_report.md` without its hand-written "Considered, not adopted" section; `git checkout outputs/` restores them.
- **Tests:** `pytest -q` and `python scripts/check_contract.py` run the test suite and the column contract.

## Layout
`src/common/` shared paths, schema, scoring · `src/legacy/` first practice-pool script ·
`scripts/` validators · `tests/` · `outputs/` handoff files · `notebooks/`

## What v6 uses, and what it deliberately doesn't
v6 uses the 33 frozen v5 features (`ALLOWED_FEATURES` in `src/common/schema.py`); only the model settings changed.
- **Exploit signals at the snapshot:** Exploit-DB, Metasploit, Nuclei and GitHub proof-of-concept flags, plus their count.
- **EPSS, ranked within the snapshot month:** raw EPSS is dropped because of the July 2026 jump; a missing-EPSS flag is kept.
- **Timing:** days from publication to the snapshot and to the cutoff.
- **Reporter (assigner) and vendor history:** counts and shares of past CVEs added to CISA KEV, all as of 31 December of
  the previous year.
- **Description text:** 14 keyword flags (`txt_*`) and two IBM Granite embedding scores, `kev_text_score` and
  `nearest_kev_sim`, computed against KEV entries known at the snapshot.

**Deliberately not used**, because they are filled in after the fact and leak the answer:
- `nvd_status`;
- the counts of affected products (CPEs) and of references;
- the reference links;
- CVSS, blank or filled (CVSS is used only as a baseline);
- CWE ids;
- any 2026 KEV information.

The leakage test shows what they would add (27 → 33). An independent review (`docs/column_review.md`) found no leak.
A feature-by-feature leak check of the v5 features ([table](outputs/outside_v5_leakcheck_features.csv)) found none of them coming from those sources and
no blank-vs-filled CVSS signal.

## Outside data we checked (none adopted)
Each source was kept only if its records are dated on or before the end of the CVE's snapshot month ([round 1](outputs/outside_report.md),
[round 2](outputs/outside2_report.md)).

| source | link | licence / terms | date rule | result |
|---|---|---|---|---|
| VulnCheck KEV | https://vulncheck.com/kev | VulnCheck Community terms (free account), not redistributed | needs a listing date; `date_added` is the earliest exploitation-report date (hindsight) | rejected: fails the date rule |
| CISA Vulnrichment | https://github.com/cisagov/vulnrichment | CC0-1.0 | SSVC "Exploitation" timestamp on or before the snapshot end | allowed; flags 1 practice CVE and none in 2026 |
| PoC-in-GitHub | https://github.com/nomi-sec/PoC-in-GitHub | CC0-1.0 | repo `created_at` on or before the snapshot end (never stars, forks or push dates) | about 92% overlap with our own GitHub PoC flag |
| EPSS daily archive | https://epss.empiricalsecurity.com (FIRST EPSS) | free public data, FIRST's EPSS usage terms | the daily file's score date on or before the snapshot end; change over the month | tested |

The combined test, v5 + PoC repo counts + the monthly EPSS change, scored 18 against v5's 21 pooled, so it was rejected.

## Columns used in v1 (history; allowed columns only; see CONTRACT.md)
- **signals:** `epss`, `epss_missing`, `epss_rank_in_month`
- **exploit flags:** `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_flags`, `any_exploit`
- **timing:** `days_to_snapshot`, `days_to_cutoff`
- **assigner history** (KEV as of Dec 31 of the previous year): `assigner_prior_cves`, `assigner_kev_count`, `assigner_kev_12m`, `assigner_kev_rate_smooth`
- **vendor history** (same cutoff): `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max`

Not used by the model: `nvd_status`, `n_affected_cpes`, `n_references`, CVSS (baseline only), `cwe_ids`, references, affected products, any 2026 KEV information.
Results and caveats (low power: 75 positives): `outputs/v1_report.md`. Run: `python -m src.replicas && python -m src.features.build && python -m src.models.train_v1`.

## Results (v6, `outputs/headline.json`; low power: 75 CVEs added to KEV in the two practice years)
v6 is a 20-seed LightGBM bag on the v5 features with regularised settings, **chosen from seven declared variants by a rule
fixed before any result** (`outputs/rank_report.md`, `outputs/v6_report.md`). v5 is kept as the previous model.

| test | v6 (20-seed bag) | best simple rule (public exploit, then EPSS) | v5 (previous) | v6 − rule, 90% CVE-level / event-clustered | v6 − v5, 90% CVE-level / event-clustered |
|---|---|---|---|---|---|
| forward: train 2024 → test 2025 | 18 | 13 | 12 | +5 [0, +10] / [−2, +12] | +6 [+2, +10] / [+1, +12] |
| stability: train 2025 → test 2024 | 9 | 6 | 9 | +3 | +0 [−2, +2] / [−2, +2] |
| pooled | 27 | 19 | 21 | +8 [+2, +14] / [+1, +15] | +6 [+2, +11] / [+1, +13] |

- **Seeds:** forward is 18 on all four seed sets and pooled 26 to 28 (`outputs/v6_seed_spread.csv`). Against v5 on the same
  seeds the gain is only +2 to +5.
- **Placebo:** real labels 27.0 vs labels shuffled within each month 0.57 pooled hits, 30 bags each (`outputs/v6_placebo.csv`).
- **Leakage test** (after-the-fact NVD columns added, never submitted): 27 → 33 (`outputs/v6_leakage_results.csv`).
- **Blind spots:** 44 of 75 KEV additions had no public exploit code and a low EPSS. The simple rule catches 0 of them,
  v5 2 and v6 5; three of v6's five are one Ivanti EPM event (`outputs/v6_blindspots.csv`).
- **The 2026 list:** 498 of v6's 500 have public exploit code; 193 are also in the simple rule's top 500 and 429 in v5's
  (`outputs/v6_overlap.csv`).
- **Caveat:** in a diagnostic that holds out whole vendors, v5's 2025 in-year hits roughly halve (19 → 10), so part of the
  in-year skill is familiarity with vendors already seen (`outputs/rank_vendor_cv.csv`).
Explanations: 318 of 500 reasons passed a groundedness check (Granite Guardian answered "No"); the other 182 use the plain template (`outputs/explanations_summary.json`).
IBM Granite and IBM Granite Guardian are open models run locally; nothing here runs on watsonx. Ideas tested and not adopted: `docs/considered_not_adopted.md`.
Regenerate Person B outputs with `python -m src.b.refresh_all`; `python scripts/number_sweep.py` checks every number in docs/site/app/README against the outputs.

## Final feature set (v5, drift-robust; the last feature-set change)
Raw EPSS (`epss`) was **removed** because its scale shifted in 2026 (PSI 2.87 pooled replicas vs the scoreboard; 1.70 against the 2025 replica alone): EPSS jumped ~6× from
the July 2026 snapshot (cause unknown), while January–May 2026 looks like past years. A model that uses raw EPSS would see a different distribution in 2026. `epss_rank_in_month` and `epss_missing` remain. For each scale-sensitive history feature the transformation with the
lowest PSI against the 2026 scoreboard was used (raw, within-pool percentile rank, or a scale-free share of everything known by the history cutoff), chosen by drift alone, never by hits.
The 33 model features are: `epss_missing`, `epss_rank_in_month`, the four exploit flags, `n_flags`, `any_exploit`, `days_to_snapshot`, `days_to_cutoff` (raw),
`assigner_prior_cves_pctrank`, `assigner_kev_share`, `assigner_kev_12m_share`, `assigner_kev_rate_smooth_pctrank`, `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max`,
`kev_text_score`, `nearest_kev_sim` and the 14 `txt_*` flags. The final model is a 20-seed LightGBM bag. `kev_text_score` and `nearest_kev_sim` (the Granite-derived scores) are kept: the
ablation shows them neutral within noise, so they are not claimed to add hits. Some assigner-history features still have a PSI above 0.25 after this treatment; `outputs/v5_report.md`
explains why and gives the intervals and caveats (low power: 75 positives). Final list: `outputs/top500_v5.csv`. A descriptive analysis of the traits of CVEs added to CISA KEV
(`outputs/why_attacked_report.md`) uses today's NVD fields and is not used by any model or list.

## Columns used in v2 (history; adds Person B's text features)
`kev_text_score`, `nearest_kev_sim` and the 14 `txt_*` flags from `outputs/text_features.parquet`, joined by `cve_id` only
(KEV part uses the same prior-December-31 cutoff). v2 / two-channel results: `outputs/v2_report.md`.
Run: `python -m src.models.train_v2 && python -m src.analysis.depth_curves && python -m src.models.two_channel &&
python -m src.analysis.blindspot_profile && python -m src.models.report_v2 && python -m src.models.stress_v2 && python -m src.models.train_v4 && python -m src.models.train_v5`.
Stress tests, the policy and the final candidate list (`outputs/top500_v3.csv`, same v2 columns): `outputs/v3_report.md`.

## Text feature columns
### Text features (Person B, `outputs/text_features.parquet`)
Run `python -m src.b.texts && python -m src.b.embed && python -m src.b.text_features`
(about 2 min on a Mac; the embeddings are not committed). Then `python -m src.b.report --label ...`
writes `outputs/b_text_report.md`.
- Text: only `description` and `published` from `vulnerabilities.csv`. Post-attack phrases
  ("exploited in the wild", "actively exploited", ...; `src/b/phrases.py`) are removed **before**
  embedding with `ibm-granite/granite-embedding-30m-english`.
- `kev_text_score`: for pool year Y, a logistic regression on embeddings is trained on CVEs published
  before Y-01-01, labelled by KEV `date_added` <= (Y-1)-12-31.
- `nearest_kev_sim`: max cosine similarity to KEV entries with `date_added` <= (Y-1)-12-31
  (2023-12-31 for replica 2024, 2024-12-31 for replica 2025, 2025-12-31 for the 2026 scoreboard).
- `txt_*`: int8 regex flags on the description (RCE, unauthenticated, edge device, ...).

## Explanations (Person B's file, Guardian gate)
`python -m src.b.explain --granite` writes `outputs/explanations.csv` (columns `cve_id`, `explanation`, `source`, `guardian_verdict`, plus `reason`, a copy of `explanation` for the dashboard) and
`outputs/explanations_summary.json`. Granite (granite-3.3-2b-instruct) rewrites facts built only from tracked columns and the v5 contribution file; local checks and then
Granite Guardian (`ollama pull granite3-guardian:2b`, risk = groundedness) must clearly answer "No", otherwise the template sentence is used. Results are cached in `outputs/.cache/`
and the run resumes after a crash. The sentence must restate at most three facts in the form "Prioritised because ...". Local checks: a blocked-phrase list (`BLOCKED_PHRASES` at the top of `src/b/explain.py`, including predictions, interpretation and causal links), a check that every percentage stays attached to its own fact (EPSS only to EPSS), and a glue/unknown-word detector that uses the English word list `src/b/english_words.txt.gz`. The prompt version is part of the cache key, so changing the prompt regenerates every row, and cached Granite sentences that fail the current checks are regenerated automatically. `--time-box MINUTES` stops after that long: unfinished rows keep the template and are marked `pending`; run the same command again to continue. The committed files cover the v6 list (`top500_v6.csv`, `top_list` in the summary): 318 of 500 reasons passed a groundedness check, 182 use the plain template and 0 are pending (`passed_guardian`, `template_fallback`, `pending` in `outputs/explanations_summary.json`); the full model rebuild itself takes about 8.5 minutes (see "Reproduce the final list"). No sentence is labelled Guardian-checked unless the Guardian model returned "No" for it.

## Built with Entire
We used [Entire](https://docs.entire.com/overview) to keep an audit trail of the AI-assisted work in this repository: checkpoints of Claude Code sessions, linked to commits.
`outputs/entire_summary.json` is a counts-and-timestamps snapshot: 30 checkpoints from 2 sessions (27 imported from earlier Claude Code history, 3 captured live), first and last dated in it (made by `python scripts/entire_summary.py`). It covers only Jack's laptop.
The checkpoints, prompts and transcripts stay on that laptop (`push_sessions` is false and the remote has no `refs/entire/*` ref) because the repository is public and transcripts contain personal data (home-folder paths and e-mail-shaped strings).
What Entire shows, what it does not, and the read-only commands to check it: [docs/entire.md](docs/entire.md).
A 25-second screen-recording plan that uses only those commands: [docs/entire_demo.md](docs/entire_demo.md).
Screen recording: https://youtu.be/_rM3jJBfXMg
We tried Entire's Graph and Brain add-ons only at the end, on a fresh clone of the repository; they were not used throughout the project.
