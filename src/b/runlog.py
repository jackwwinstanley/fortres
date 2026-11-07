"""Read outputs/runlog.csv into one row per (model version, test year) for charts and the dashboard.

Person A logs baselines with replica = 2024/2025, and models with replica = "train2024_test2025",
"train2025_test2024" (honest train-on-one-year, test-on-the-other) or "lomo2024" (leave-one-month-out,
optimistic; skipped here). The test year is the last 4 digits of the train/test label.
"""
import re

import pandas as pd

from src.common.paths import OUT_DIR

NICE = {"baseline_cvss": "Highest CVSS", "baseline_epss": "Highest EPSS",
        "baseline_exploit_epss": "Public exploit, then EPSS"}


def model_name(version: str) -> str:
    if version in NICE:
        return NICE[version]
    m = re.match(r"v(\d+)_(lgbm|logreg|bag)", version)
    if not m:
        return version
    kind = {"lgbm": "LightGBM", "logreg": "logistic", "bag": "LightGBM bag"}[m[2]]
    text = " + text" if int(m[1]) >= 2 else ", no text"
    return f"Ours v{m[1]} ({kind}{text})"


def results(path=OUT_DIR / "runlog.csv") -> pd.DataFrame:
    """Columns: version, name, is_baseline, test_year (int), k, hits, ci_lo, ci_hi, timestamp."""
    if not path.exists():
        return pd.DataFrame(columns=["version", "name", "is_baseline", "headline", "test_year", "k", "hits", "ci_lo", "ci_hi", "timestamp"])
    rl = pd.read_csv(path)
    rep = rl["replica"].astype(str)
    keep = rep.str.fullmatch(r"\d{4}") | rep.str.fullmatch(r"train\d{4}_test\d{4}")
    rl = rl[keep].copy()
    rl["test_year"] = rl["replica"].astype(str).str[-4:].astype(int)
    rl["is_baseline"] = rl["version"].str.startswith("baseline")
    ci = rl["notes"].astype(str).str.extract(r"boot90=\[(\d+)\s*[-,]\s*(\d+)\]").astype(float)
    rl["ci_lo"], rl["ci_hi"] = ci[0], ci[1]
    rl["name"] = rl["version"].map(model_name)
    rl["headline"] = rl["notes"].astype(str).str.contains("headline model", case=False)
    rl = rl.sort_values("timestamp").drop_duplicates(["version", "test_year"], keep="last")
    return rl[["version", "name", "is_baseline", "headline", "test_year", "k", "hits", "ci_lo", "ci_hi", "timestamp"]]


def latest_model(res: pd.DataFrame) -> str | None:
    """The model Person A marks as 'headline model' in the runlog notes; otherwise the newest model version with
    results for both test years (prefers LightGBM on ties)."""
    m = res[~res["is_baseline"]]
    if "headline" in m and m["headline"].any():
        h = m[m["headline"]].sort_values("timestamp")
        return h.iloc[-1]["version"]
    both = m.groupby("version")["test_year"].nunique()
    m = m[m["version"].isin(both[both == 2].index)]
    if m.empty:
        return None
    m = m.assign(vnum=m["version"].str.extract(r"v(\d+)")[0].astype(float),
                 lgbm=m["version"].str.contains("lgbm"))
    return m.sort_values(["vnum", "lgbm", "timestamp"]).iloc[-1]["version"]
