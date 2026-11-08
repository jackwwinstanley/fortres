# Switching the docs to v6: what this branch does and what is still left

Branch `b/v6-docs` is b/v6 with origin/main merged in. It is prepared and **not merged; no PR**. Use it only if Jack picks v6.

## Done here (numbers only from `outputs/v6_headline_candidate.json`, `v6_leakage_results.csv`, `v6_blindspots.csv`)
- **Headline results** (18 / 9 / 27 vs the simple rule's 13 / 6 / 19, ranges +2 to +14 pooled and 0 to +10 forward) in:
  - README.md;
  - docs/writeup_person_b.md, devpost_final.md, judge_qa.md, video_script.md, page_content.md, model_card.md and
    risk_mapping.md;
  - site/index.html (fallback numbers).
- **Leakage:** 27 → 33 (21 + 12).
- **Blind spots:** 5 of 44, three of them one Ivanti EPM event (CVE-2024-13159/13160/13161), plus CVE-2025-24472 and
  CVE-2024-23113.
- **"One behind 12 vs 13 / could be luck" sentences** are rewritten to "five ahead 18 vs 13, still a small sample".
- **Text ablation:** the ablation numbers (2 / 3 / 2 / 0 blind spots) are now labelled as measured on v5. They were not
  re-run for v6.
- **Checker:** `python scripts/number_sweep_v6.py` checks every doc against the v6 files. Result: 0 problems.

## Still needed when switching (this branch leaves v5 files alone, as asked)
- Make v6 the submitted model:
  - copy `outputs/top500_v6.csv` to `top500.csv`;
  - swap `outputs/headline.json` for `v6_headline_candidate.json`, `leakage_results.csv` for `v6_leakage_results.csv`,
    and `v5_blindspots.csv` for a v6 version.
  - Then `scripts/number_sweep.py` (which reads headline.json) passes again. Until then its repository test fails on
    this branch, as expected.
- Regenerate `site/data/story.json` and the dashboard data from the v6 files (`python -m src.b.export_story` after the
  swap).
- Write explanations for the 71 CVEs in `outputs/v6_missing_explanations.csv`, then fill the Guardian counts.
- Re-run the text-feature ablation on v6 if the pitch keeps the "either part alone" sentence.
