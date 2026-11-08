# Person B runbook: refresh everything from Person A's final files

One command regenerates every Person B output. Run it from the repo root with the project's Python environment, after
pulling Person A's final model files (`outputs/headline.json`, `outputs/runlog.csv`, `outputs/top500_v*.csv`,
`outputs/features_*.parquet`).

```
python -m src.b.refresh_all            # fast path, ~1.5 min
```

| flag | adds | time | when |
|---|---|---|---|
| (none) | drift check, leakage + v5 blind spots, error analysis, charts, story/dashboard data, tests, contract check | ~1.5 min | after any change to Person A's model or list |
| `--text` | descriptions → Granite embeddings → `text_features.parquet` (before everything else) | ~5 min | only if the pools or descriptions change |
| `--priors` | #12 track-record priors and their v5 evaluation | ~15 min | optional, research only |
| `--explanations` | Granite reasons through Person A's `explain.py` (Granite Guardian gate; needs Ollama) | ~30+ min | once, after the final top-500 list exists and PR #35 is merged |
| `--all` | all of the above | ~1 h | rarely |

It stops at the first failing step and names it. Every step is safe to re-run.

## What each step writes

| step | script | writes (tracked = committed) |
|---|---|---|
| descriptions | `src/b/texts.py` | `outputs/b_texts.parquet` (not tracked) |
| Granite embeddings | `src/b/embed.py` | `outputs/emb_small.npy`, `outputs/emb_ids.csv` (not tracked; ~275 MB) |
| text features | `src/b/text_features.py` | `outputs/text_features.parquet` (tracked) |
| drift check | `src/b/drift.py` | `outputs/b_drift.json`, `outputs/b_drift_report.md` (tracked), PNGs (not tracked) |
| leakage + blind spots | `src/b/leakage.py` | `outputs/leakage_results.csv`, `outputs/b_leakage_report.md`, `outputs/v5_blindspots.csv` (tracked) |
| priors | `src/b/priors.py`, `src/b/eval_priors.py` | `outputs/b_priors.parquet` (not tracked), `outputs/b_priors_eval.{md,json}` (tracked) |
| error analysis | `src/b/error_analysis.py` | `outputs/b_error_analysis.{md,json}` (tracked) |
| Granite reasons | `src/b/explain.py` (Person A's version after #35) | `outputs/explanations.csv`, `outputs/explanations_summary.json` (tracked) |
| charts | `src/b/charts.py` | `docs/figures/*.png` (tracked) |
| story / dashboard data | `src/b/export_story.py` | `site/data/story.json`, `site/data/why_traits.csv` (tracked; `git add -f`, because `.gitignore` has `data/`) |
| checks | `pytest -q`, `scripts/check_contract.py`, `scripts/number_sweep.py` (every number in docs/site/app/README vs the outputs) | none |

Granite fact extraction (#12, `python -m src.b.extract [--profile]`, ~1 h) is **not** part of the refresh. Its output
`outputs/extracted_features.parquet` is descriptive, and it only needs a re-run if the pools change.

## After a refresh
1. `git status`: commit only the tracked files above. Never commit `data/`, `*.npy` or `b_texts.parquet`.
2. Re-read the numbers the write-up quotes against `outputs/headline.json`, `outputs/leakage_results.csv` and
   `outputs/explanations_summary.json`. They are quoted in `docs/writeup_person_b.md`, `docs/video_script.md`,
   `docs/judge_qa.md`, `docs/devpost_final.md` and `docs/page_content.md`.
3. Dashboard: `streamlit run app/dashboard.py`. Story site: `python -m http.server -d site 8765`.
