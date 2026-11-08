# Write-up sections: Person B (draft v2)

For Jack to merge into the main README write-up (#23). Numbers: v5 headline model, `outputs/headline.json`,
`outputs/b_*_report.md`. Each section is short on purpose: lead with the finding, then how we know.

## 1. Blind spots: what the standard signals can't see
Of the 75 CVEs added to CISA KEV in our two practice years, **44 (59%) were blind spots**: no public exploit
code (Exploit-DB, Metasploit, Nuclei, GitHub PoC) and a within-month EPSS rank too low for a top-k EPSS list.
The best simple rule (public exploit first, then EPSS) catches **0** of them by construction. Our v5 model catches
**2** (two Fortinet FortiOS flaws, CVE-2024-23113 and CVE-2025-24472). Without the Granite text features the same v5 setup catches **0** blind spots, but three more flagged CVEs (22 vs 21
overall, one bag each, within noise). So the text trades a few visible catches for blind spots rather than adding net
catches, in line with Person A's ablation.
*Figure: `docs/figures/blindspots.png`.*

## 2. IBM Granite text features
- **Embeddings:** IBM Granite (open models, run locally): `ibm-granite/granite-embedding-30m-english` (384 dimensions) embeds 178,175 descriptions in
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
**July 2026 snapshot EPSS jumped ~6× (cause unknown)**: median 0.274% vs 0.043% in 2024–25. Those July–September snapshots
are **62%** of the 2026 list. A threshold or raw-score split learned on past years would land in the wrong place,
so the model drops raw EPSS and ranks it within each snapshot month (v4/v5). Assigner mix (PSI 0.66) and time-to-snapshot (0.49)
also moved. *Figures: `drift_psi.png`, `drift_epss.png`.*

## 4. Leakage experiment: what cheating would look like
Same v5 model, plus columns NVD fills in *after* a CVE gets attention (analysis status, reference and product
counts, blank-vs-filled CVSS/CWE, exploit-tagged links): pooled hits jump from **21 to 28** (2025: 12 → 17;
2024: 9 → 11; 29 was the earlier v4 run). The reason is stark: **every** CVE added to KEV in both practice years is "Analyzed" in today's NVD,
against about half of the rest, because NVD analyses KEV-listed CVEs first. None of these columns are in our model;
an independent column review (`docs/column_review.md`) found no leak.
*Figure: `leakage.png`.*

## 5. Explanations you can act on
Each of the 500 picks gets one sentence built only from facts our pipeline has: text tags, EPSS percentile within its
month, public exploit sources, IBM Granite KEV-likeness and the model's strongest reasons. IBM Granite
(`granite-3.3-2b-instruct`, open model run locally) rewords them. A local checker rejects any sentence that adds a
number, product, CVE id or blocked claim ("critical", "actively exploited", …), and IBM Granite Guardian
(`granite3-guardian:2b`, run locally via Ollama) checks that the rest is supported by the facts. Sentences that fail
keep the plain template. The current counts are in `outputs/explanations_summary.json` (`passed_guardian`,
`template_fallback`); Guardian checks support by the facts, not truth, fluency or causality ("passed a groundedness check",
never "verified").

## 6. Understanding the errors
The model and the simple rule fail in **opposite** ways (`outputs/b_error_analysis.md`). In the forward test the rule
alone catches five high-EPSS CVEs with public exploit code from vendors rarely on KEV (FreeType, Erlang, Dassault, Adobe
×2). The model alone catches four enterprise/edge CVEs whose descriptions read like past KEV entries (Fortinet, Cisco ISE,
Citrix NetScaler, VMware). Ideas we tested from this (track-record priors, a 50/50 blend) were **considered, not
adopted**; see `docs/considered_not_adopted.md`.

## Honest results (v5 headline model, `outputs/headline.json`)
Pooled over both practice years, the v5 model catches **21** CVEs added to KEV against **19** for the best simple rule
(+2, 90% range −4 to +8). In the strict forward-in-time test (train 2024 → test 2025) it is **one behind**: 12 vs 13
(range −6 to +3). The stability check (train 2025 → test 2024) is 9 vs 6. The gain is small and could be luck. What holds
up: the blind spots, the July 2026 shift, and the leakage test.

## Limits
Low power (75 positives, so a few hits are within noise). Descriptions are today's NVD text and can be edited
after publication. The 2026 June snapshot uses July signals (an organiser data gap).
