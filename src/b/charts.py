"""Person B, issue #14: presentation charts in one style -> docs/figures/*.png

Run:  python -m src.b.charts

Each chart is drawn only if its inputs exist, so this can be rerun as files land:
  baselines.png      hits@k with 90% bootstrap ranges per practice year (outputs/baseline_results.json;
                     model versions from outputs/model_results.json if Person A writes one, else runlog.csv)
  timing.png         positive rate by snapshot month vs days left to the cutoff (positive_rate_by_month.csv)
  drift_psi.png      biggest feature shifts 2025 -> 2026 (outputs/b_drift.json)
  drift_epss.png     EPSS distribution by pool (replica / scoreboard parquet files)
  leakage.png        honest vs leaky model hits (outputs/leakage_results.csv, issue #8)
"""
import json

import numpy as np
import pandas as pd

from src.b.style import ACCENT, ACCENT_LIGHT, GREYS, INK, MUTED, WARN, mpl, titles
from src.common.paths import OUT_DIR, REPO_ROOT

FIG_DIR = REPO_ROOT / "docs" / "figures"
BASE_NAMES = {"baseline_cvss": "Highest CVSS", "baseline_epss": "Highest EPSS",
              "baseline_exploit_epss": "Public exploit,\nthen EPSS"}


def _save(fig, name):
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG_DIR / name)
    print(f"wrote docs/figures/{name}")


def baselines(plt):
    p = OUT_DIR / "baseline_results.json"
    if not p.exists():
        return
    res = json.loads(p.read_text())
    rl = pd.read_csv(OUT_DIR / "runlog.csv") if (OUT_DIR / "runlog.csv").exists() else pd.DataFrame()
    models = (rl[~rl["version"].str.startswith("baseline")]
              .sort_values("timestamp").drop_duplicates(["version", "replica"], keep="last")
              if len(rl) else pd.DataFrame(columns=["version", "replica", "hits"]))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharey=True)
    for ax, y in zip(axes, ("2024", "2025")):
        r = res[y]
        names, hits, lo, hi, colors = [], [], [], [], []
        for i, (key, label) in enumerate(BASE_NAMES.items()):
            if key in r:
                names.append(label); hits.append(r[key]["hits"]); colors.append(GREYS[i])
                lo.append(r[key]["hits"] - r[key]["ci90"][0]); hi.append(r[key]["ci90"][1] - r[key]["hits"])
        for _, m in models[models["replica"].astype(str) == y].iterrows():
            names.append(f"Ours\n({m['version']})"); hits.append(m["hits"]); colors.append(ACCENT)
            ci = pd.Series(str(m.get("notes", ""))).str.extract(r"boot90=\[(\d+),\s*(\d+)\]").iloc[0]
            lo.append(m["hits"] - float(ci[0]) if ci.notna().all() else 0)
            hi.append(float(ci[1]) - m["hits"] if ci.notna().all() else 0)
        x = np.arange(len(names))
        ax.bar(x, hits, color=colors, width=0.62)
        ax.errorbar(x, hits, yerr=[lo, hi], fmt="none", ecolor=INK, elinewidth=1, capsize=4)
        for xi, h in zip(x, hits):
            ax.text(xi, h + 0.3, f"{h}", ha="center", va="bottom", color=INK, fontsize=10, fontweight="bold",
                    bbox=dict(facecolor="white", edgecolor="none", pad=1))
        ax.set_xticks(x, names, fontsize=9)
        titles(ax, f"{y} practice year", f"top {r['k']} of {r['pool']:,} CVEs · {r['positives']} became exploited", 11)
        ax.yaxis.get_major_locator().set_params(integer=True)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("Exploited CVEs caught in the top k")
    title = ("Our model vs simple rules on past years" if len(models) else
             "Best simple rule: public exploit, then EPSS. That's the bar to beat.")
    fig.suptitle(title, x=0.01, ha="left", fontsize=14, fontweight="bold", color=INK)
    fig.text(0.01, -0.02, "Error bars: 90% bootstrap range. k scales 500 picks to each pool's size.",
             color=MUTED, fontsize=8.5)
    fig.tight_layout()
    _save(fig, "baselines.png")
    plt.close(fig)


def timing(plt):
    p = OUT_DIR / "positive_rate_by_month.csv"
    if not p.exists():
        return
    d = pd.read_csv(p)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    for y, color in (("2024", GREYS[1]), ("2025", ACCENT)):
        g = d[d["replica"].astype(str) == y].sort_values("mean_days_to_cutoff", ascending=False)
        rate = g["positive_rate"] * 1000
        ax.plot(g["mean_days_to_cutoff"], rate, marker="o", color=color, lw=2, ms=5, label=y)
        last = g.iloc[-1]
        ax.annotate(y, (last["mean_days_to_cutoff"], last["positive_rate"] * 1000), xytext=(6, 0),
                    textcoords="offset points", color=color, fontweight="bold", va="center")
    ax.invert_xaxis()
    ax.set_xlabel("Days from the snapshot month to the 4 Nov cutoff")
    ax.set_ylabel("Became exploited (per 1,000 CVEs)")
    titles(ax, "Fewer than 2 in every 1,000 CVEs get exploited, whatever the month",
           "Rates swing month to month with no steady trend, so a few lucky picks move the score a lot")
    _save(fig, "timing.png")
    plt.close(fig)


def drift(plt):
    p = OUT_DIR / "b_drift.json"
    if not p.exists():
        return
    res = json.loads(p.read_text())
    s = pd.DataFrame(res["shift"]).head(8).iloc[::-1]
    nice = {"epss": "EPSS score", "assigner": "Who reported it (CNA)", "days_to_snapshot": "Age at snapshot",
            "kev_text_score": "Granite KEV-likeness", "nearest_kev_sim": "Closest past KEV match"}
    labels = [nice.get(f, f.replace("txt_", "text: ").replace("_", " ")) for f in s["feature"]]
    colors = [WARN if v > 0.25 else ACCENT if v > 0.1 else GREYS[0] for v in s["psi_2025_vs_2026"]]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.barh(labels, s["psi_2025_vs_2026"], color=colors, height=0.6)
    for yi, v in enumerate(s["psi_2025_vs_2026"]):
        ax.text(v + 0.02, yi, f"{v:.2f}", va="center", color=INK, fontsize=9)
    ax.axvline(0.25, color=MUTED, lw=0.8, ls="--")
    ax.text(0.26, len(s) - 0.55, "large shift →", color=MUTED, fontsize=8.5)
    ax.set_xlabel("Population stability index, 2025 practice pool vs 2026 scoreboard")
    titles(ax, "2026 CVEs look different from past years, mostly in EPSS",
           f"A model can tell 2025 and 2026 CVEs apart with AUC {res['spot_the_year_auc']:.2f} "
           "(0.5 = indistinguishable)")
    ax.grid(axis="y", visible=False)
    _save(fig, "drift_psi.png")
    plt.close(fig)

    pools = {"2024": "replica_2024.parquet", "2025": "replica_2025.parquet", "2026": "scoreboard_features.parquet"}
    if not all((OUT_DIR / f).exists() for f in pools.values()):
        return
    q = {y: pd.read_parquet(OUT_DIR / f, columns=["epss"])["epss"].dropna().quantile([0.5, 0.9]) * 100
         for y, f in pools.items()}
    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(3)
    med = [q[y][0.5] for y in pools]
    p90 = [q[y][0.9] for y in pools]
    ax.bar(x - 0.18, med, 0.34, color=GREYS[0], label="Median CVE")
    ax.bar(x + 0.18, p90, 0.34, color=[ACCENT_LIGHT, ACCENT_LIGHT, ACCENT], label="90th-percentile CVE")
    for xi, v in zip(x, med):
        ax.text(xi - 0.18, v, f"{v:.2f}", ha="center", va="bottom", fontsize=8.5, color=INK)
    for xi, v in zip(x, p90):
        ax.text(xi + 0.18, v, f"{v:.2f}", ha="center", va="bottom", fontsize=8.5, color=INK)
    ax.set_xticks(x, ["2024 practice", "2025 practice", "2026 scoreboard"])
    ax.set_ylabel("EPSS (% chance of exploitation in 30 days)")
    ratio = q["2026"][0.5] / q["2025"][0.5]
    titles(ax, f"The typical 2026 CVE has a ~{ratio:.0f}× higher EPSS score than past years",
           "So rank EPSS within each year; a cutoff learned on past years would not transfer")
    ax.legend(loc="upper left")
    ax.grid(axis="x", visible=False)
    _save(fig, "drift_epss.png")
    plt.close(fig)


def leakage(plt):
    p = OUT_DIR / "leakage_results.csv"
    if not p.exists():
        print("skip leakage.png: outputs/leakage_results.csv not produced yet (#8)")
        return
    d = pd.read_csv(p)
    fig, ax = plt.subplots(figsize=(7, 4))
    years = sorted(d["replica"].astype(str).unique())
    x = np.arange(len(years))
    for off, model, color in ((-0.18, "honest", ACCENT), (0.18, "leaky", WARN)):
        g = d[d["model"] == model].set_index(d["replica"].astype(str)).reindex(years)
        ax.bar(x + off, g["hits"], 0.34, color=color, label=model.capitalize())
    ax.set_xticks(x, [f"{y} practice" for y in years])
    ax.set_ylabel("Exploited CVEs caught in the top k")
    titles(ax, "Columns filled in after the fact make a model look far better than it is")
    ax.legend()
    _save(fig, "leakage.png")
    plt.close(fig)


def main():
    plt = mpl()
    for f in (baselines, timing, drift, leakage):
        f(plt)


if __name__ == "__main__":
    main()
