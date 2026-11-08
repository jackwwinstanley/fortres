# App demo: "Rank a dataset"

Start it from the repository root:
```bash
streamlit run app/dashboard.py
```
The two sample files are not in the repository. Make them once with `python scripts/make_app_samples.py` (needs `data/scoreboard_2026.csv`).

The app opens on the **Rank a dataset** tab; **Overview** is the team dashboard. The saved v6 models are in `models/v6/` (1.5 MB). `python scripts/save_v6_models.py` recreates them.

## 90-second click path for the video
| step | click | say |
|---|---|---|
| 1 Start page | open the "Rank a dataset" page | "This is Fortres as a working triage tool. It uses the same saved v6 models as our submitted list." |
| 2 Upload | drag in `app/samples/2026_one_month_2026-05.csv` | "Here is one month of 2026 vulnerabilities." |
| 3 Run | press **Run** | "It ranks them in a fraction of a second on this laptop." |
| 4 Summary | point at the three cards and the chart | "How many we scored, how many are in our 2026 top 500, and how many of the top picks have public exploit code." |
| 5 Guardian-checked pick | in **All rows**, click a row marked "Guardian-checked" | "Each top pick has a reason from IBM Granite. Granite Guardian checked this one against its facts, and it passed a groundedness check." |
| 6 Template pick | click a row marked "Template" | "When a draft doesn't hold up, we show a plain template instead." |
| 7 Outside the 500 | search for a CVE outside the top 500 | "Outside the 500 there's no AI reason, only the facts, labelled as such." |
| 8 Download | press **Download the top 500** | "The result downloads in the same one-column format as our submission." |

## What is live and what is not
The ranking runs live with the saved models. The Granite text scores and the reasons were computed in our earlier run; no AI model runs in the app. Say "ranks", "prioritises" and "flags".

A row that is not in the 2026 scoreboard is scored from its own columns, with the Granite text score marked as not available. Upload limit: 100,000 rows.
