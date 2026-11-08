"""Person B: what do the blind spots look like? DESCRIPTIVE ONLY (post-hoc; never used to build or pick a model).

Run after src.b.extract:  python -m src.b.profile

Groups (practice years 2024 + 2025): exploited blind spots, exploited with public exploit code (from Person A's
outputs/blindspot_positives.csv) and, for context, the 2026 top-500 picks. For each group: share of product types,
"no login needed" and "reachable over the network" from the Granite labels (outputs/extracted_features.parquet).
Writes outputs/b_blindspot_profile.md and docs/figures/blindspot_profile.png.
"""
import re

import pandas as pd

from src.b.style import ACCENT, GREYS, INK, MUTED, mpl, titles
from src.common.paths import OUT_DIR, REPO_ROOT

NICE = {"network_edge_device": "VPN / firewall / edge", "web_application": "Web application",
        "wordpress_plugin": "WordPress plugin", "operating_system": "Operating system", "browser": "Browser",
        "enterprise_server_software": "Enterprise server software", "iot_or_firmware": "IoT / firmware",
        "library_or_framework": "Library / framework", "desktop_application": "Desktop application",
        "mobile_app": "Mobile app", "other": "Other", "unlabelled": "Unlabelled"}


def groups() -> dict:
    ex = pd.read_parquet(OUT_DIR / "b_extract_cache.parquet").drop(columns=["guard_changes"], errors="ignore")  # includes the profile-only rows
    blind = set(pd.read_csv(OUT_DIR / "blindspot_positives.csv")["cve_id"])
    pos = pd.concat([pd.read_parquet(OUT_DIR / f"replica_{y}.parquet", columns=["cve_id", "label"]) for y in (2024, 2025)])
    pos = set(pos.loc[pos["label"] == 1, "cve_id"])
    tops = sorted(OUT_DIR.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    g = {"Exploited blind spots": blind, "Exploited, had exploit code": pos - blind}
    if tops:
        g[f"Our 2026 picks ({tops[-1].stem})"] = set(pd.read_csv(tops[-1])["cve_id"])
    return {k: ex[ex["cve_id"].isin(v)].assign(group=k) for k, v in g.items()}, {k: len(v) for k, v in g.items()}


def main():
    gs, sizes = groups()
    d = pd.concat(gs.values(), ignore_index=True)
    d["product_type"] = d["product_type"].fillna("unlabelled")
    prod = pd.crosstab(d["product_type"], d["group"], normalize="columns").reindex(columns=list(gs)) * 100
    prod = prod.loc[prod.max(axis=1).sort_values(ascending=False).index]
    flags = pd.DataFrame({
        "no login needed (%)": d.groupby("group")["auth_required"].apply(lambda s: (s == "no").mean() * 100),
        "network reachable (%)": d.groupby("group")["network_reachable"].apply(lambda s: (s == "yes").mean() * 100),
        "labelled CVEs": d.groupby("group").size(),
    }).reindex(list(gs))
    flags["CVEs in group"] = [sizes[k] for k in flags.index]
    impact = pd.crosstab(d["impact_type"].fillna("unlabelled"), d["group"], normalize="columns").reindex(columns=list(gs)) * 100

    lines = ["# What do the blind spots look like? (DESCRIPTIVE ONLY)", "",
             "Labels by IBM Granite (granite-3.3-2b-instruct): small local model, noisy (21% of rows corrected by the "
             "consistency guard). Small groups. "
             "Post-hoc description of the practice years; never used to build or select a model. "
             "Small groups: read as rough shares.", "",
             "## Login and network", "", flags.round(0).astype(int).to_markdown(), "",
             "## Product type (% of each group)", "", prod.round(0).astype(int).rename(index=NICE).to_markdown(), "",
             "## Main impact (% of each group)", "", impact.round(0).astype(int).to_markdown(), ""]
    (OUT_DIR / "b_blindspot_profile.md").write_text("\n".join(lines))
    print("\n".join(lines))

    plt = mpl()
    top = prod.head(7).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8.5, 4.6))
    cols = list(gs)[:2]
    import numpy as np
    y = np.arange(len(top))
    for j, (c, color) in enumerate(zip(cols, (ACCENT, GREYS[1]))):
        ax.barh(y + (0.2 if j == 0 else -0.2), top[c], 0.38, color=color, label=f"{c} ({sizes[c]})")
    ax.set_yticks(y, [NICE.get(i, i) for i in top.index])
    ax.set_xlabel("% of exploited CVEs in the group")
    lead = prod[cols[0]].idxmax()
    titles(ax, f"Blind spots are mostly {NICE.get(lead, lead).lower()} flaws",
           "Practice years 2024 + 2025, Granite labels from descriptions; descriptive only")
    ax.legend(loc="lower right")
    ax.grid(axis="y", visible=False)
    out = REPO_ROOT / "docs" / "figures" / "blindspot_profile.png"
    fig.savefig(out)
    print(f"wrote {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
