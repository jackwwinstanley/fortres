"""Depth curves: cumulative hits at several list depths, to see where each signal's hits come from.
Run after `python -m src.models.train_v2` (needs outputs/.cache/test_preds.parquet):
    python -m src.analysis.depth_curves
v1 curves use out-of-replica predictions (train on the other replica). The score-only rankings
(kev_text_score, nearest_kev_sim, assigner_kev_rate_smooth, vendor_kev_count_max) have no fitting at all
and tie heavily, so tie-aware EXPECTED hits are plotted. LOW POWER: 27 and 48 positives.
"""
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from src.common.paths import DATA_DIR, OUT_DIR, REPO_ROOT  # noqa: E402
from src.common.scoring import expected_hits_at_k, k_for_pool  # noqa: E402
from src.models.train_v2 import load_with_text  # noqa: E402

SCORES = {"kev_text_score": ["kev_text_score"], "nearest_kev_sim": ["nearest_kev_sim"],
          "assigner_kev_rate_smooth": ["assigner_kev_rate_smooth"], "vendor_kev_count_max": ["vendor_kev_count_max"]}
# categorical slots 1-7 of the reference palette (fixed order); baseline gets slot 1
COLORS = ["#2a78d6", "#eb6834", "#6250d6", "#1baf7a", "#eda100", "#e87ba4", "#008300"]


def depths_for(k):
    return [("10", 10), ("25", 25), ("50", 50), ("100", 100), ("k/2", round(k / 2)), ("k", k),
            ("1.5k", round(1.5 * k)), ("2k", 2 * k)]


def blind_mask(meta, k):
    flags = meta[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1)
    return (flags == 0) & (meta["epss_rank_in_month"] < 1 - k / len(meta))


def build(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, _, _ = load_with_text(out_dir, data_dir)
    preds = pd.read_parquet(out_dir / ".cache" / "test_preds.parquet")
    rows, marginal = [], {}
    for y in (2024, 2025):
        meta = data[y]["meta"].copy()
        p = preds[preds["test_year"] == y].set_index("cve_id")
        meta["v1_lgbm"] = p["lgbm_v1"].reindex(meta["cve_id"]).to_numpy()
        meta["v1_logreg"] = p["logreg_v1"].reindex(meta["cve_id"]).to_numpy()
        k = k_for_pool(len(meta))
        rankings = {"Exploit code, then EPSS (baseline)": ["exploit_epss"],
                    "v1 LightGBM": ["v1_lgbm", "epss_rank_in_month"],
                    "v1 logistic regression": ["v1_logreg", "epss_rank_in_month"], **SCORES}
        subsets = {"all": meta, "blind-spot": meta[blind_mask(meta, k)].reset_index(drop=True)}
        for sname, sub in subsets.items():
            for rname, cols in rankings.items():
                for dlabel, d in depths_for(k):
                    e = expected_hits_at_k(sub, cols, min(d, len(sub)))
                    rows.append(dict(replica=y, subset=sname, ranking=rname, depth_label=dlabel, depth=d, k=k,
                                     positives_in_subset=int(sub["label"].sum()), hits_arbitrary=e["arbitrary"],
                                     hits_expected=round(e["expected"], 3)))
        # baseline marginal hits per 25 slots (arbitrary order), whole pool
        base = [expected_hits_at_k(meta, ["exploit_epss"], d)["arbitrary"] for d in range(0, 2 * k + 1, 25)]
        base[0] = 0
        marginal[y] = None
        for i in range(1, len(base)):
            if base[i] - base[i - 1] < 1:
                marginal[y] = (i * 25, base[i - 1], base[i])
                break
    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "depth_curves.csv", index=False)
    return df, marginal


def plot(df, path):
    fig, axes = plt.subplots(2, 2, figsize=(11, 8), sharey="row")
    rn = list(df["ranking"].unique())
    for r, subset in enumerate(["all", "blind-spot"]):
        for c, y in enumerate([2024, 2025]):
            ax = axes[r, c]
            sub = df[(df["replica"] == y) & (df["subset"] == subset)]
            k = int(sub["k"].iloc[0])
            for i, name in enumerate(rn):
                s = sub[sub["ranking"] == name]
                ax.plot(s["depth"], s["hits_expected"], color=COLORS[i], lw=2.4 if i == 0 else 1.6,
                        marker="o", ms=4, label=name)
            ax.axvline(k, color="#9a9890", lw=1, ls=":")
            ax.set_title(f"Replica {y}, {'all CVEs' if subset == 'all' else 'blind-spot CVEs only'} "
                         f"({int(sub['positives_in_subset'].iloc[0])} positives)", fontsize=10, loc="left")
            ax.set_xlabel("list depth (CVEs taken from the top)")
            ax.grid(color="#e6e5e1", lw=0.6)
            for sp in ("top", "right"):
                ax.spines[sp].set_visible(False)
            if c == 0:
                ax.set_ylabel("cumulative expected hits")
    h, lab = axes[0, 0].get_legend_handles_labels()
    fig.legend(h, lab, loc="lower center", ncol=4, frameon=False, fontsize=9)
    fig.suptitle("Where the hits come from (dotted line = k). LOW POWER: 27 and 48 positives", x=0.01, ha="left", fontsize=11)
    fig.tight_layout(rect=(0, 0.07, 1, 0.96))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)


def main():
    df, marginal = build()
    plot(df, REPO_ROOT / "docs" / "figures" / "depth_curves.png")
    (OUT_DIR / ".cache" / "depth_marginal.json").write_text(json.dumps({str(y): m for y, m in marginal.items()}))
    for y, m in marginal.items():
        if m is None:
            print(f"replica {y}: baseline still adds >= 1 hit per 25 slots up to 2k")
        else:
            d, a, b = m
            print(f"replica {y}: baseline marginal hits per 25 slots first drops below 1 at depth {d} "
                  f"(slots {d - 25}-{d} add {b - a}; cumulative {b})")
    print(df[(df["subset"] == "all") & df["depth_label"].isin(["25", "100", "k", "2k"])]
          .pivot_table(index=["replica", "ranking"], columns="depth_label", values="hits_expected").round(1).to_string())


if __name__ == "__main__":
    main()
