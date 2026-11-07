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
import re

import numpy as np
import pandas as pd

from src.b import runlog
from src.b.style import ACCENT, ACCENT_LIGHT, GREYS, INK, MUTED, WARN, mpl, titles
from src.common.paths import OUT_DIR, REPO_ROOT

FIG_DIR = REPO_ROOT / "docs" / "figures"
BASE_NAMES = {"baseline_cvss": "Highest CVSS", "baseline_epss": "Highest EPSS",
              "baseline_exploit_epss": "Public exploit,\nthen EPSS"}


def diff90(h: dict):
    """Pooled 90% range of (ours - best baseline) from Person A's headline.json (v4 and v5 formats)."""
    return h.get("pooled", {}).get("diff_cve_level_90") or h["diff_vs_baseline_cve_level_90"]


def mechanism_file():
    """Newest outputs/vN_mechanism.csv in the gained/lost format (no 'comparison' column)."""
    fs = sorted(OUT_DIR.glob("v*_mechanism.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[0]), reverse=True)
    for f in fs:
        if "comparison" not in pd.read_csv(f, nrows=1).columns:
            return f
    return None


def _save(fig, name):
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG_DIR / name)
    print(f"wrote docs/figures/{name}")


def baselines(plt):
    p = OUT_DIR / "baseline_results.json"
    if not p.exists():
        return
    res = json.loads(p.read_text())
    rl = runlog.results()
    best = runlog.latest_model(rl)
    models = rl[rl["version"] == best].assign(replica=lambda d: d["test_year"].astype(str))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharey=True)
    for ax, y in zip(axes, ("2024", "2025")):
        r = res[y]
        names, hits, lo, hi, colors = [], [], [], [], []
        for i, (key, label) in enumerate(BASE_NAMES.items()):
            if key in r:
                names.append(label); hits.append(r[key]["hits"]); colors.append(GREYS[i])
                lo.append(r[key]["hits"] - r[key]["ci90"][0]); hi.append(r[key]["ci90"][1] - r[key]["hits"])
        for _, m in models[models["replica"].astype(str) == y].iterrows():
            names.append(f"Ours\n({m['version'].split('_')[0]} model)"); hits.append(m["hits"]); colors.append(ACCENT)
            lo.append(m["hits"] - m["ci_lo"] if pd.notna(m["ci_lo"]) else np.nan)
            hi.append(m["ci_hi"] - m["hits"] if pd.notna(m["ci_hi"]) else np.nan)
        x = np.arange(len(names))
        ax.bar(x, hits, color=colors, width=0.62)
        ok = ~np.isnan(np.array(lo, dtype=float))
        ax.errorbar(x[ok], np.array(hits)[ok], yerr=[np.array(lo)[ok], np.array(hi)[ok]], fmt="none", ecolor=INK,
                    elinewidth=1, capsize=4)
        for xi, h in zip(x, hits):
            ax.text(xi, h + 0.3, f"{h}", ha="center", va="bottom", color=INK, fontsize=10, fontweight="bold",
                    bbox=dict(facecolor="white", edgecolor="none", pad=1))
        ax.set_xticks(x, names, fontsize=9)
        titles(ax, f"{y} practice year", f"top {r['k']} of {r['pool']:,} CVEs · {r['positives']} became exploited", 11)
        ax.yaxis.get_major_locator().set_params(integer=True)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("Exploited CVEs caught in the top k")
    title = (f"Our model vs the best simple rule: {int(models['hits'].sum())} vs "
             f"{sum(res[y]['baseline_exploit_epss']['hits'] for y in ('2024', '2025'))} exploited CVEs caught" if len(models) else
             "Best simple rule: public exploit, then EPSS. That's the bar to beat.")
    fig.suptitle(title, x=0.01, ha="left", fontsize=14, fontweight="bold", color=INK)
    note = "Error bars: 90% bootstrap range for the simple rules. k scales 500 picks to each pool's size."
    hp = OUT_DIR / "headline.json"
    if hp.exists() and len(models):
        h = json.loads(hp.read_text())
        lo_, hi_ = diff90(h)
        note += (f" Ours vs best rule, both years: {h['pooled_hits_bag'] - h['baseline_pooled_hits']:+d} "
                 f"(90% range {lo_:+.0f} to {hi_:+.0f}), so the gain is within the noise.")
    fig.text(0.01, -0.02, note, color=MUTED, fontsize=8.5)
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
    fig, ax = plt.subplots(figsize=(8, 4.3))
    med = {}
    for (y, f), color in zip(pools.items(), (GREYS[0], GREYS[2], WARN)):
        d = pd.read_parquet(OUT_DIR / f, columns=["snapshot_month", "epss"])
        m = d.groupby("snapshot_month")["epss"].median() * 100
        mo = m.index.str[-2:].astype(int)
        med[y] = m
        ax.plot(mo, m.values, marker="o", ms=5, lw=2.2, color=color, label=y)
        ax.annotate(y, (mo[-1], m.values[-1]), xytext=(8, 0), textcoords="offset points", color=color,
                    fontweight="bold", va="center")
    late = pd.read_parquet(OUT_DIR / pools["2026"], columns=["snapshot_month", "epss"])
    past = pd.concat([pd.read_parquet(OUT_DIR / pools[y], columns=["epss"]) for y in ("2024", "2025")])["epss"].median() * 100
    late_med = late[late["snapshot_month"] >= "2026-07"]["epss"].median() * 100
    share = (late["snapshot_month"] >= "2026-07").mean()
    ax.axvline(6.5, color=MUTED, lw=0.8, ls="--")
    ax.text(6.4, ax.get_ylim()[1] * 0.92, "July 2026 →", ha="right", color=MUTED, fontsize=9)
    ax.set_xticks(range(1, 10), ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep"])
    ax.set_xlim(0.6, 9.9)
    ax.set_ylabel("Median EPSS of new CVEs (%)")
    titles(ax, f"2026 tracked past years until July, then EPSS jumped ~{late_med / past:.0f}×",
           f"Jul–Sep snapshots are {share:.0%} of the 2026 list (no June data). Rank EPSS within the month.")
    ax.grid(axis="x", visible=False)
    _save(fig, "drift_epss.png")
    plt.close(fig)


def leakage(plt):
    p = OUT_DIR / "leakage_results.csv"
    if not p.exists():
        print("skip leakage.png: outputs/leakage_results.csv not produced yet (#8)")
        return
    d = pd.read_csv(p)
    d["replica"] = d["replica"].astype(str)
    fig, ax = plt.subplots(figsize=(8, 4.3))
    years = ["2025", "2024"]
    x = np.arange(len(years))
    series = (("Exploit code, then EPSS", "Best simple rule", GREYS[1]),
              ("honest", "Our honest model", ACCENT),
              ("leaky", "Same model + banned columns", WARN))
    w = 0.26
    for j, (model, label, color) in enumerate(series):
        g = d[d["model"] == model].set_index("replica").reindex(years)
        xs = x + (j - 1) * w
        ax.bar(xs, g["hits"], w * 0.92, color=color, label=label)
        ax.errorbar(xs, g["hits"], yerr=[g["hits"] - g["ci_lo"], g["ci_hi"] - g["hits"]], fmt="none",
                    ecolor=INK, elinewidth=0.9, capsize=3)
        for xi, h in zip(xs, g["hits"]):
            ax.text(xi, h + 0.4, f"{h:.0f}", ha="center", va="bottom", fontsize=9.5, fontweight="bold", color=INK,
                    bbox=dict(facecolor="white", edgecolor="none", pad=1))
    pos = d.drop_duplicates("replica").set_index("replica").reindex(years)
    ax.set_xticks(x, [f"Test on {y}\n(trained on {2024 if y == "2025" else 2025}), "
                      f"{int(p)} exploited" for y, p in zip(years, pos["positives"])])
    ax.set_ylabel("Exploited CVEs caught in the top k")
    ax.yaxis.get_major_locator().set_params(integer=True)
    h = d[d["model"] == "honest"]["hits"].sum()
    lk = d[d["model"] == "leaky"]["hits"].sum()
    titles(ax, f"After-the-fact columns inflate results: {lk:.0f} hits instead of {h:.0f}",
           "LEAKAGE EXPERIMENT, never submitted. Every exploited CVE is 'Analyzed' in today's NVD vs about half "
           "of the rest")
    ax.legend(loc="upper left", ncols=3, fontsize=9, bbox_to_anchor=(0, -0.2))
    ax.grid(axis="x", visible=False)
    _save(fig, "leakage.png")
    plt.close(fig)


def blind_spot_counts():
    """Per test year: exploited CVEs split into flagged / blind-spot, and hits of the best simple rule vs our headline
    model in each group. Uses Person A's outputs/blindspot_positives.csv and the newest mechanism file
    (v4_mechanism.csv: gained/lost vs the baseline for the headline model; else v2_mechanism.csv for v1/v2 LightGBM)."""
    bp = OUT_DIR / "blindspot_positives.csv"
    res = runlog.results()
    if not bp.exists() or res.empty:
        return None
    mf = mechanism_file()
    if mf is not None:
        m = pd.read_csv(mf)
        n = re.findall(r"\d+", mf.stem)[0]  # the model version the breakdown was measured on
        comps = {runlog.model_name(f"v{n}_bag"): m}
    elif (OUT_DIR / "v2_mechanism.csv").exists():
        m = pd.read_csv(OUT_DIR / "v2_mechanism.csv")
        comps = {runlog.model_name(v): m[m["comparison"] == f"{v}_vs_baseline"] for v in ("v1_lgbm", "v2_lgbm")}
    else:
        return None
    blind = pd.read_csv(bp).groupby("replica").size()
    rows = []
    for y in (2024, 2025):
        r = res[res["test_year"] == y].set_index("version")["hits"]
        pos = int(pd.read_parquet(OUT_DIR / f"replica_{y}.parquet", columns=["label"])["label"].sum())
        total = {"blind-spot": int(blind.get(y, 0))}
        total["flagged"] = pos - total["blind-spot"]
        for grp in ("flagged", "blind-spot"):
            # by definition the exploit-then-EPSS top k contains no blind-spot CVE
            base = int(r.get("baseline_exploit_epss", 0)) if grp == "flagged" else 0
            row = {"year": y, "group": grp, "exploited": total[grp], "Public exploit, then EPSS": base}
            for name, mm in comps.items():
                g = mm[(mm["test_replica"] == y) & (mm["group"] == grp)]
                row[name] = base + int((g["kind"] == "gained").sum()) - int((g["kind"] == "lost").sum())
            rows.append(row)
    return pd.DataFrame(rows)


def blindspots(plt):
    d = blind_spot_counts()
    if d is None:
        print("skip blindspots.png: Person A's blind-spot files not found")
        return
    d.to_csv(OUT_DIR / "b_blindspot_counts.csv", index=False)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), sharey=True)
    models = [c for c in d.columns if c.startswith("Ours")]
    series = [("Public exploit, then EPSS", GREYS[1])] + [(c, ACCENT if c == models[-1] else ACCENT_LIGHT) for c in models]
    for ax, y in zip(axes, (2025, 2024)):
        g = d[d["year"] == y].set_index("group").loc[["flagged", "blind-spot"]]
        x = np.arange(2)
        ax.bar(x, g["exploited"], 0.8, color="none", edgecolor=GREYS[0], lw=1, ls="--", label="All exploited")
        w = 0.24
        for j, (col, color) in enumerate(series):
            xs = x + (j - 1) * w
            ax.bar(xs, g[col], w * 0.9, color=color, label=col)
            for xi, v in zip(xs, g[col]):
                ax.text(xi, v + 0.3, f"{v}", ha="center", va="bottom", fontsize=9, color=INK, fontweight="bold")
        for xi, v in zip(x, g["exploited"]):
            ax.text(xi, v + 0.3, f"{v} exploited", ha="center", va="bottom", fontsize=9, color=MUTED)
        ax.set_xticks(x, ["Had public exploit code", "Blind spot: no exploit code,\nlow EPSS"])
        titles(ax, f"Test on {y}", "", 11)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("Exploited CVEs")
    tot_b = int(d[d["group"] == "blind-spot"]["exploited"].sum())
    tot = int(d["exploited"].sum())
    v2b = int(d[d["group"] == "blind-spot"][models[-1]].sum())
    fig.suptitle(f"{tot_b} of {tot} exploited CVEs were blind spots: simple rules caught 0, our model {v2b}",
                 x=0.01, ha="left", fontsize=14, fontweight="bold", color=INK)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower left", ncols=4, fontsize=9, bbox_to_anchor=(0.01, -0.06), frameon=False)
    fig.tight_layout()
    _save(fig, "blindspots.png")
    plt.close(fig)


def main():
    plt = mpl()
    for f in (baselines, blindspots, timing, drift, leakage):
        f(plt)


if __name__ == "__main__":
    main()
