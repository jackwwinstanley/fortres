# IBM "Before the Breach" – predicting which CVEs get exploited

Sheridan Datathon 2026. Rank the 72,670 CVEs in `data/scoreboard_2026.csv` and submit
`top500.csv` (one column `cve_id`, 500 unique IDs). Judges count how many were added to
CISA KEV by 2026-11-04. Only information known at the snapshot may be used; see `CONTRACT.md`.

## Run
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# put the datathon CSVs in ./data (not committed)
pytest -q
python scripts/check_contract.py
python scripts/check_top500.py outputs/top500_v1.csv
```

## Layout
`src/common/` shared paths, schema, scoring · `src/legacy/` first practice-pool script ·
`scripts/` validators · `tests/` · `outputs/` handoff files · `notebooks/`

## Columns used (v1, allowed columns only; see CONTRACT.md)
- **signals:** `epss`, `epss_missing`, `epss_rank_in_month`
- **exploit flags:** `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_flags`, `any_exploit`
- **timing:** `days_to_snapshot`, `days_to_cutoff`
- **assigner history** (KEV as of Dec 31 of the previous year): `assigner_prior_cves`, `assigner_kev_count`, `assigner_kev_12m`, `assigner_kev_rate_smooth`
- **vendor history** (same cutoff): `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max`

Not used by the model: `nvd_status`, `n_affected_cpes`, `n_references`, CVSS (baseline only), `cwe_ids`, references, affected products, any 2026 KEV information.
Results and caveats (low power: 75 positives): `outputs/v1_report.md`. Run: `python -m src.replicas && python -m src.features.build && python -m src.models.train_v1`.

## Results (v6, `outputs/v6_headline_candidate.json`; low power: 75 CVEs added to KEV in the two practice years)
| test | v6 (20-seed bag) | best simple rule (public exploit, then EPSS) |
|---|---|---|
| forward: train 2024 → test 2025 | 18 | 13 |
| stability: train 2025 → test 2024 | 9 | 6 |
| pooled | 27 | 19 (+8, 90% range +2 to +14) |

Leakage test (after-the-fact NVD columns added, never submitted): 27 → 33 (`outputs/v6_leakage_results.csv`). Blind spots: 44 of 75 KEV additions had no
public exploit code and a low EPSS; the simple rule catches 0 of them, the v6 bag 5, three of them one Ivanti EPM event (`outputs/v6_blindspots.csv`). Explanations: TODO(#35): fill from outputs/explanations_summary.json after PR #35 merges.
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

## Columns used (v2 adds Person B's text features)
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
and the run resumes after a crash. The sentence must restate at most three facts in the form "Prioritised because ...". Local checks: a blocked-phrase list (`BLOCKED_PHRASES` at the top of `src/b/explain.py`, including predictions, interpretation and causal links), a check that every percentage stays attached to its own fact (EPSS only to EPSS), and a glue/unknown-word detector that uses the English word list `src/b/english_words.txt.gz`. The prompt version is part of the cache key, so changing the prompt regenerates every row, and cached Granite sentences that fail the current checks are regenerated automatically. `--time-box MINUTES` stops after that long: unfinished rows keep the template and are marked `pending`; run the same command again to continue. The committed files come from a 30-minute run: rows marked `pending` in `guardian_verdict` were not processed yet and show the template. No sentence is labelled Guardian-checked unless the Guardian model returned "No" for it.
