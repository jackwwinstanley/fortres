# Independent review: allowed vs banned columns (issue #11)

Reviewer: Person B (Aba), 2026-11-07. Scope: every model input in `src/common/schema.py`
(`V1_FEATURES` + `TEXT_FEATURES`) as built by `src/features/build.py`, `src/replicas.py` and `src/b/*`,
checked against CONTRACT.md ("ALLOWED" / "BANNED").

**Verdict: no leak found.** Every input is either an allowed column or history computed with the fixed
prior-December-31 KEV cutoff. `check_feature_list(V1_FEATURES + TEXT_FEATURES)` returns no problems. Four
known limits are listed at the end; none is a reason to drop a feature.

## Feature by feature

| feature(s) | source | known at the snapshot? | verdict |
|---|---|---|---|
| `epss`, `epss_missing`, `epss_rank_in_month` | exploit_signals, row for the snapshot month | yes, monthly snapshot value | OK. The rank is within the pool's own snapshot month, which also absorbs the EPSS level shift found in the drift check |
| `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_flags`, `any_exploit` | exploit_signals, snapshot month | yes | OK |
| `days_to_snapshot`, `days_to_cutoff` | publish date and snapshot month | yes, calendar arithmetic | OK |
| `assigner_prior_cves` | count of CVEs from the same CNA published <= Dec 31 of the prior year | yes | OK. Uses today's file, so CVEs deleted since are not counted (tiny effect) |
| `assigner_kev_count`, `assigner_kev_12m`, `assigner_kev_rate_smooth` | KEV rows with `date_added` <= Dec 31 of the prior year, joined by CNA | yes | OK |
| `n_vendors_mentioned`, `vendor_kev_count_max`, `vendor_kev_12m_max` | KEV vendor lexicon with `date_added` <= Dec 31 of the prior year, matched in the description | lexicon yes; description see limit 1 | OK |
| `kev_text_score` | Granite embeddings; logistic regression trained on CVEs published before the pool year, KEV labels as of Dec 31 of the prior year | yes | OK |
| `nearest_kev_sim` | cosine similarity to KEV entries with `date_added` <= Dec 31 of the prior year | yes | OK |
| `txt_*` (14 flags) | regexes on the description after post-attack phrases are stripped | description see limit 1 | OK |

Not used anywhere as a model input (confirmed by grep and the feature guard): `nvd_status`,
`n_affected_cpes`, `n_references`, any CVSS or CWE field, `references.csv`, `affected_products.csv`,
`last_modified`, the signals file's `in_kev` (used only to exclude already-listed CVEs from the pools),
and any 2026 KEV information.

## Why the banned list matters (measured)

In today's NVD data, **100% of the exploited CVEs** in both replicas have `nvd_status = Analyzed`,
against 42% (2024) and 50% (2025) of the rest. NVD analyses KEV-listed CVEs first, so this field is close to
the answer itself. The leakage experiment (`python -m src.b.leakage`, `docs/figures/leakage.png`) shows the
same model jumps from 21 to 29 pooled hits when such columns are added.

## Known limits (not leaks, but worth stating in the write-up)

1. **Descriptions are today's NVD text.** They can be edited after publication. Post-attack phrases are stripped
   before embedding and before the `txt_*` flags (0 remain), and Person A's description scan finds no other
   suspicious wording. Vendor matching uses the unstripped text, but vendor names don't change with an attack.
2. **`epss_missing` behaves inconsistently.** In 2024, CVEs with no EPSS row had a higher exploit rate (3 of
   1,282, 0.23%) than CVEs with one (0.09%); in 2025 it was the reverse (0.12% vs 0.14%). With 3–4 cases this
   is noise. The scoreboard has far fewer missing values (2.0% vs 4.4% / 9.8%), so the feature can't carry much.
3. **The 2026 June snapshot uses July signals** (June 2026 signals are missing). That's the organisers' data
   and the same for everyone. It explains part of the `days_to_snapshot` shift seen in the drift check.
4. **Feature-name guard only.** `check_feature_list` checks names, not how a column was computed. This
   review is the check on computation; rerun it if a feature is added after the freeze.
