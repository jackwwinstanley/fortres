"""Person B, issue #9: does the 2026 scoreboard look like the 2024/2025 practice pools?

Run:  python -m src.b.drift

If the scoreboard looks very different from the replicas, hits measured on the replicas are a
weaker guide to how the top 500 will do. Two views, both on ALLOWED columns only (CONTRACT.md):

1. Per-feature shift, 2024 -> 2026 and 2025 -> 2026, measured with PSI (population stability
   index; < 0.1 small, 0.1-0.25 moderate, > 0.25 large).
2. A "spot the year" classifier: gradient boosting trained to tell replica-2025 rows from
   scoreboard rows (5-fold CV ROC AUC; 0.5 = indistinguishable). Its top features say what moved.
   Calendar columns (published, snapshot_month) are left out: they differ by construction.

Writes outputs/b_drift_report.md, outputs/b_drift.json and two PNG charts (outputs/b_drift_*.png).
CVSS columns are not allowed model inputs, so they are not used here either.
"""
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import roc_auc_score

from src.common.paths import DATA_DIR, OUT_DIR

FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
NUMERIC = ["epss", "days_to_snapshot", "kev_text_score", "nearest_kev_sim"]
TOP_ASSIGNERS = 15
POOLS = {"2024": "replica_2024.parquet", "2025": "replica_2025.parquet", "2026": "scoreboard_features.parquet"}


def psi(a, b, bins=10) -> float:
    """PSI of b relative to a. Numeric: quantile bins of a. Categorical/binary: categories."""
    a, b = pd.Series(a).dropna(), pd.Series(b).dropna()
    if a.dtype.kind in "fc" and a.nunique() > 2:
        edges = np.unique(np.quantile(a, np.linspace(0, 1, bins + 1)))
        edges[0], edges[-1] = -np.inf, np.inf
        pa = pd.cut(a, edges).value_counts(normalize=True, sort=False)
        pb = pd.cut(b, edges).value_counts(normalize=True, sort=False)
    else:
        cats = sorted(set(a) | set(b), key=str)
        pa = a.value_counts(normalize=True).reindex(cats, fill_value=0)
        pb = b.value_counts(normalize=True).reindex(cats, fill_value=0)
    pa, pb = np.clip(pa.to_numpy(), 1e-4, None), np.clip(pb.to_numpy(), 1e-4, None)
    return float(np.sum((pb - pa) * np.log(pb / pa)))


def load() -> dict:
    tf = pd.read_parquet(OUT_DIR / "text_features.parquet")
    assigner = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "assigner"])
    pools = {}
    for y, f in POOLS.items():
        d = pd.read_parquet(OUT_DIR / f).drop(columns=["label"], errors="ignore")
        d = d.merge(tf, on="cve_id", how="left").merge(assigner, on="cve_id", how="left")
        d["assigner"] = d["assigner"].fillna("unknown")
        pools[y] = d
    return pools


def shift_table(pools: dict) -> pd.DataFrame:
    txt = [c for c in pools["2026"].columns if c.startswith("txt_")]
    top = pools["2026"]["assigner"].value_counts().index[:TOP_ASSIGNERS]
    rows = []
    for col in NUMERIC + FLAGS + txt + ["assigner"]:
        r = {"feature": col}
        for y in ("2024", "2025"):
            a, b = pools[y][col], pools["2026"][col]
            if col == "assigner":
                a, b = a.where(a.isin(top), "other"), b.where(b.isin(top), "other")
            r[f"psi_{y}_vs_2026"] = round(psi(a, b), 4)
        for y in POOLS:
            s = pools[y][col]
            r[f"mean_{y}"] = None if col == "assigner" else round(float(s.mean()), 4)
        rows.append(r)
    return pd.DataFrame(rows).sort_values("psi_2025_vs_2026", ascending=False).reset_index(drop=True)


def spot_the_year(pools: dict) -> tuple[float, pd.DataFrame]:
    txt = [c for c in pools["2026"].columns if c.startswith("txt_")]
    top = pools["2026"]["assigner"].value_counts().index[:TOP_ASSIGNERS]
    a, b = pools["2025"].assign(is_2026=0), pools["2026"].assign(is_2026=1)
    d = pd.concat([a, b], ignore_index=True)
    X = d[NUMERIC + FLAGS + txt].astype(float)
    X["assigner"] = pd.Categorical(d["assigner"].where(d["assigner"].isin(top), "other")).codes
    y = d["is_2026"].to_numpy()
    clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, random_state=0,
                                         categorical_features=[X.columns.get_loc("assigner")])
    cv = StratifiedKFold(5, shuffle=True, random_state=0)
    p = cross_val_predict(clf, X, y, cv=cv, method="predict_proba")[:, 1]
    auc = float(roc_auc_score(y, p))
    clf.fit(X, y)
    sample = np.random.default_rng(0).choice(len(X), size=min(20_000, len(X)), replace=False)
    imp = permutation_importance(clf, X.iloc[sample], y[sample], scoring="roc_auc",
                                 n_repeats=3, random_state=0)
    imp = (pd.DataFrame({"feature": X.columns, "auc_drop": imp.importances_mean})
             .sort_values("auc_drop", ascending=False).reset_index(drop=True))
    return auc, imp


def charts(shift: pd.DataFrame, imp: pd.DataFrame) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ink, muted, accent, grid = "#1f2933", "#7b8794", "#2563eb", "#e4e7eb"
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": grid, "axes.labelcolor": ink,
                         "xtick.color": muted, "ytick.color": ink, "axes.spines.top": False,
                         "axes.spines.right": False})

    top = shift.head(12).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(top["feature"], top["psi_2025_vs_2026"], color=accent)
    for lim, lab, yy in ((0.1, "moderate", 0.5), (0.25, "large", 1.5)):
        ax.axvline(lim, color=muted, lw=0.8, ls="--")
        ax.text(lim, yy - 1, f" {lab} > {lim}", color=muted, fontsize=8, va="center")
    ax.set_xlabel("Population stability index, 2025 practice pool vs 2026 scoreboard")
    worst = shift.iloc[0]
    ax.set_title(f"Biggest shift: {worst['feature']} (PSI {worst['psi_2025_vs_2026']:.2f})",
                 loc="left", color=ink, fontsize=12, fontweight="bold")
    ax.grid(axis="x", color=grid, lw=0.6)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "b_drift_psi.png", dpi=160)
    plt.close(fig)

    top = imp.head(10).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(top["feature"], top["auc_drop"], color=accent)
    ax.set_xlabel("Drop in 'spot the year' AUC when the feature is shuffled")
    ax.set_title("What gives a 2026 CVE away", loc="left", color=ink, fontsize=12, fontweight="bold")
    ax.grid(axis="x", color=grid, lw=0.6)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "b_drift_classifier.png", dpi=160)
    plt.close(fig)


def write_report(pools, shift, auc, imp) -> str:
    big = shift[shift["psi_2025_vs_2026"] > 0.25]["feature"].tolist()
    mod = shift[(shift["psi_2025_vs_2026"] > 0.1) & (shift["psi_2025_vs_2026"] <= 0.25)]["feature"].tolist()
    verdict = ("hard to tell apart" if auc < 0.6 else "somewhat different" if auc < 0.75
               else "clearly different")
    lines = [
        "# Drift check: 2026 scoreboard vs the 2024/2025 practice pools (issue #9)", "",
        "Produced by `python -m src.b.drift`. Allowed columns only (CONTRACT.md).", "",
        "## In plain words",
        f"- A model trying to tell 2025 practice CVEs from 2026 scoreboard CVEs reaches ROC AUC "
        f"**{auc:.3f}** (0.5 = can't tell them apart), so the two sets are **{verdict}**.",
        f"- Large shifts (PSI > 0.25): {', '.join(big) or 'none'}.",
        f"- Moderate shifts (PSI 0.1-0.25): {', '.join(mod) or 'none'}.",
        f"- The features that most give a 2026 CVE away: {', '.join(imp['feature'].head(3))}.", "",
        f"Pool sizes: " + ", ".join(f"{y}: {len(d):,}" for y, d in pools.items()), "",
        "## Per-feature shift (sorted by PSI 2025 vs 2026)", "",
        shift.to_markdown(index=False), "",
        "## Spot-the-year classifier: permutation importance", "",
        imp.round(4).to_markdown(index=False), "",
        "Charts: `outputs/b_drift_psi.png`, `outputs/b_drift_classifier.png`.",
    ]
    return "\n".join(lines)


def main() -> dict:
    pools = load()
    shift = shift_table(pools)
    auc, imp = spot_the_year(pools)
    charts(shift, imp)
    (OUT_DIR / "b_drift_report.md").write_text(write_report(pools, shift, auc, imp))
    res = {"spot_the_year_auc": round(auc, 4), "shift": shift.to_dict("records"),
           "importance": imp.round(4).to_dict("records")}
    (OUT_DIR / "b_drift.json").write_text(json.dumps(res, indent=1))
    print(f"spot-the-year AUC {auc:.3f}")
    print(shift.head(10).to_string(index=False))
    print(imp.head(5).to_string(index=False))
    return res


if __name__ == "__main__":
    main()
