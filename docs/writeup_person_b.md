# Write-up sections: Person B (draft v1)

For Jack to merge into the main README write-up (#23). Numbers: v4 headline model, `outputs/headline.json`,
`outputs/b_*_report.md`. Each section is short on purpose: lead with the finding, then how we know.

## 1. Blind spots: what the standard signals can't see
Of the 75 CVEs that were exploited in our two practice years, **44 (59%) were blind spots**: no public exploit
code (Exploit-DB, Metasploit, Nuclei, GitHub PoC) and a within-month EPSS rank too low for a top-k EPSS list.
The best simple rule (public exploit first, then EPSS) catches **0** of them by construction. Our v4 model catches
**2** (a VMware ESXi flaw in 2024 and a Fortinet flaw in 2025). That's few, but it's the only part of the problem
where text and vendor history add signal the standard feeds don't have.
*Figure: `docs/figures/blindspots.png`.*

## 2. IBM Granite text features
- **Embeddings:** `ibm-granite/granite-embedding-30m-english` (384 dimensions) embeds 178,175 descriptions in
  about a minute on a laptop.
- **`kev_text_score`:** for pool year Y, a logistic regression on the embeddings, trained only on CVEs published
  before Y with KEV labels as of Dec 31 of Y−1. Held-out ROC AUC 0.82 (2024) and 0.80 (2025).
- **`nearest_kev_sim`:** cosine similarity to the closest KEV entry added by Dec 31 of Y−1.
- **`txt_*` flags:** 14 transparent regex tags (RCE, no login needed, edge device, ...).
- **Leak guard:** post-attack phrases ("exploited in the wild", "actively exploited", ...) are removed before
  embedding. Removing them changed AUC by less than 0.003, so the score never relied on them.
- **Honest caveat:** in Person A's ablation, the regex flags carry more of the lift than the embedding scores;
  differences are within seed noise.

## 3. The 2026 scoreboard is not like past years (drift)
A classifier can tell 2025 practice CVEs from 2026 scoreboard CVEs with **ROC AUC 0.93**, and EPSS is the main
reason. The shift is a **mid-year step**: January–May 2026 looks like 2024–25 (median EPSS ~0.035%), but from the
**July 2026 snapshot the median is ~6× higher** (0.274% vs 0.043% in 2024–25). Those July–September snapshots
are **62%** of the 2026 list. A threshold or raw-score split learned on past years would land in the wrong place,
so v4 drops raw EPSS and ranks it within each snapshot month. Assigner mix (PSI 0.66) and time-to-snapshot (0.49)
also moved. *Figures: `drift_psi.png`, `drift_epss.png`.*

## 4. Leakage experiment: what cheating would look like
Same v4 model, plus columns NVD fills in *after* a CVE gets attention (analysis status, reference and product
counts, blank-vs-filled CVSS/CWE, exploit-tagged links): pooled hits jump from **21 to 29** (2025: 12 → 17;
2024: 9 → 12). The reason is stark: **every** exploited CVE in both practice years is "Analyzed" in today's NVD,
against about half of the rest, because NVD analyses attacked CVEs first. None of these columns are in our model;
an independent column review (`docs/column_review.md`) found no leak.
*Figure: `leakage.png`.*

## 5. Explanations you can act on
Each of the 500 picks gets one sentence built only from facts our pipeline has: reporting CNA, text tags, EPSS
percentile within its year, public exploit sources, and the most similar past KEV entry. IBM Granite
(`granite-3.3-2b-instruct`, run locally) rewords them. A checker rejects any sentence that adds a number,
product, CVE or claim ("critical", "actively exploited") not in the facts; those picks keep the plain template.
On the v3 list, 373 of 500 passed and 127 fell back.

## Limits
Low power (75 positives, so a few hits are within noise). Descriptions are today's NVD text and can be edited
after publication. The 2026 June snapshot uses July signals (an organiser data gap).
