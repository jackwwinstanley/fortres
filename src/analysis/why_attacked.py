"""Why are some vulnerabilities attacked?  DESCRIPTIVE ONLY.  Run:  python -m src.analysis.why_attacked

This analysis explains the past; it is NOT a model input and feeds nothing into any model, feature file or top500 file.
Scope: CVEs in vulnerabilities.csv published 2022-01-01 .. 2025-09-30. "Attacked" = the cve_id appears in known_exploited.csv
(KEV, added on or before 2025-12-31; the file ends there). Because the CVEs are historical and the aim is to explain, today's
NVD fields (CVSS vector parts, cwe_ids, affected products) are used; they are NOT time-safe and must never be used as
prediction features. Everything is association, never cause.
"""
import json
import re

import duckdb
import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR, REPO_ROOT

SCOPE_START, SCOPE_END = "2022-01-01", "2025-09-30"
MIN_N, MIN_ATTACKED = 200, 10
CVSS_ATTRS = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope",
              "confidentiality_impact", "integrity_impact", "availability_impact", "cvss3_severity"]
COMBO = "network + no privileges + no user interaction"


# ---- statistics helpers (tested) --------------------------------------------------------------
def wilson_interval(k, n, z: float = 1.96):
    """95% Wilson score interval for a proportion k/n; (nan, nan) when n == 0."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def filter_min_count(table: pd.DataFrame, min_n: int = MIN_N, min_attacked: int = MIN_ATTACKED) -> pd.DataFrame:
    """Keep categories with at least `min_n` CVEs OR at least `min_attacked` attacked CVEs."""
    return table[(table["n"] >= min_n) | (table["attacked"] >= min_attacked)]


def rate_table(df: pd.DataFrame, key: str, overall: float, attribute: str | None = None) -> pd.DataFrame:
    """n, attacked, attack rate, lift vs the overall rate and Wilson interval per category of `key` (NaN -> '(missing)')."""
    cat = df[key].fillna("(missing)")
    g = df.assign(_cat=cat).groupby("_cat")["attacked"].agg(n="size", attacked="sum").reset_index().rename(columns={"_cat": "category"})
    g["rate"] = g["attacked"] / g["n"]
    g["lift"] = g["rate"] / overall
    ci = [wilson_interval(a, n) for a, n in zip(g["attacked"], g["n"])]
    g["ci_low"], g["ci_high"] = [c[0] for c in ci], [c[1] for c in ci]
    g.insert(0, "attribute", attribute or key)
    return g


def shown(table: pd.DataFrame) -> pd.DataFrame:
    return filter_min_count(table).sort_values("lift", ascending=False).reset_index(drop=True)


# ---- loading ----------------------------------------------------------------------------------
def load_scope(data_dir=DATA_DIR):
    con = duckdb.connect()
    cols = ", ".join(CVSS_ATTRS + ["assigner", "cwe_ids"])
    v = con.execute(f"""SELECT cve_id, CAST(published AS DATE) AS published, {cols}
        FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)
        WHERE CAST(published AS DATE) BETWEEN DATE '{SCOPE_START}' AND DATE '{SCOPE_END}'""").df()
    kev = con.execute(f"""SELECT cve_id, vendor AS kev_vendor, CAST(date_added AS DATE) AS date_added, known_ransomware_use
        FROM read_csv_auto('{data_dir}/known_exploited.csv', all_varchar=true)""").df().drop_duplicates("cve_id")
    v = v.merge(kev, on="cve_id", how="left")
    v["attacked"] = v["kev_vendor"].notna().astype(int)
    v["published"] = pd.to_datetime(v["published"])
    v["date_added"] = pd.to_datetime(v["date_added"])
    v["combo"] = np.where(v["attack_vector"].isna(), None,
                          np.where((v["attack_vector"] == "NETWORK") & (v["privileges_required"] == "NONE") & (v["user_interaction"] == "NONE"),
                                   COMBO, "all other CVSS 3 CVEs"))
    v["publish_year"] = v["published"].dt.year.astype(str)
    return v, con


def cwe_table(v: pd.DataFrame, overall: float, data_dir=DATA_DIR) -> pd.DataFrame:
    e = v[["cve_id", "attacked", "cwe_ids"]].assign(cwe=lambda d: d["cwe_ids"].fillna("(missing)").str.split(";")).explode("cwe")
    e["cwe"] = e["cwe"].str.strip()
    t = rate_table(e.drop_duplicates(["cve_id", "cwe"]), "cwe", overall, "cwe_id").rename(columns={"category": "cwe_id"})
    names = pd.read_csv(data_dir / "weakness_types.csv", usecols=["cwe_id", "name"])
    t = t.merge(names, on="cwe_id", how="left")
    fallback = pd.Series(np.select([t["cwe_id"] == "(missing)", t["cwe_id"].str.startswith("NVD-")],
                                   ["(no CWE listed)", "(NVD placeholder)"], "(not in weakness_types.csv)"), index=t.index)
    t["name"] = t["name"].where(t["name"].notna(), fallback)
    return t


def vendor_product_table(v: pd.DataFrame, overall: float, con, data_dir=DATA_DIR):
    """Vendors from affected_products.csv (vulnerable == 'Y'); also CVEs with no listed vulnerable product."""
    ap = con.execute(f"""SELECT DISTINCT cve_id, vendor FROM read_csv_auto('{data_dir}/affected_products.csv', all_varchar=true, quote='"', escape='"')
        WHERE vulnerable = 'Y' AND vendor IS NOT NULL""").df()
    ap = ap[ap["cve_id"].isin(v["cve_id"])].merge(v[["cve_id", "attacked"]], on="cve_id")
    t = rate_table(ap, "vendor", overall, "vendor (affected_products, vulnerable=Y)")
    t["share_of_attacked"] = t["attacked"] / int(v["attacked"].sum())
    t["share_of_all"] = t["n"] / len(v)
    no_prod = v[~v["cve_id"].isin(ap["cve_id"])]
    return t, dict(n=len(no_prod), attacked=int(no_prod["attacked"].sum()))


# ---- vendor groups (analyst-assigned, coarse) --------------------------------------------------
GROUPS = {
    "Operating systems, browsers & platforms": ["Microsoft", "Apple", "Google", "Android", "Linux", "Mozilla", "Red Hat", "WebKitGTK",
                                                "WebRTC", "Canonical", "Debian", "Chromium"],
    "Chips, mobile & device firmware": ["Qualcomm", "Arm", "Samsung", "MediaTek", "Code Aurora", "Realtek", "Broadcom Wi-Fi", "Intel", "AMD"],
    "Network, security & storage appliances": ["Cisco", "Fortinet", "Palo Alto Networks", "SonicWall", "Citrix", "F5", "Juniper", "Zyxel",
                                               "D-Link", "TP-Link", "WatchGuard", "Sophos", "Ivanti", "Mitel", "Trend Micro", "QNAP",
                                               "Array Networks", "Check Point", "NETGEAR", "DrayTek", "Ubiquiti", "Tenda", "MikroTik",
                                               "Barracuda", "Barracuda Networks", "Aviatrix", "Versa", "Ruckus Wireless", "Sierra Wireless", "Grandstream",
                                               "TerraMaster", "ASUS", "Acronis"],
    "Enterprise & IT-management software": ["VMware", "Oracle", "SAP", "Adobe", "Atlassian", "Progress", "SolarWinds", "Veeam", "Zoho",
                                            "SysAid", "Qlik", "ConnectWise", "N-able", "Fortra", "Broadcom", "Commvault", "ServiceNow",
                                            "BeyondTrust", "PaperCut", "Hitachi Vantara", "Dassault Systèmes", "Cleo", "Advantive",
                                            "TeleMessage", "Synacor", "IBM", "TIBCO", "Kaseya", "Veritas", "Micro Focus", "Quest",
                                            "Sitecore", "NetApp", "Citrix Systems", "Pulse Secure", "Dell", "HP", "Hewlett Packard (HP)",
                                            "Nagios", "Zabbix", "Elastic", "VMware Tanzu", "Netwrix", "WSO2", "SugarCRM", "Teclib", "Novi Survey",
                                            "NextGen Healthcare", "Ignite Realtime", "Audinate"],
    "Web apps, CMS & open source": ["Apache", "Roundcube", "Craft CMS", "Kentico", "OSGeo", "MinIO", "Redis", "JetBrains", "CWP",
                                    "CyberPersons", "CrushFTP", "Jenkins", "GitLab", "Drupal", "WordPress", "Joomla!", "Rails", "PHP",
                                    "Laravel", "Grafana Labs", "Sonatype", "OpenSSL", "Exim", "Samba", "ImageMagick", "Sudo",
                                    "ThinkPHP", "vBulletin", "DotNetNuke (DNN)", "Webmin", "Gladinet", "Wing FTP Server", "ownCloud",
                                    "Cacti", "dotCMS", "ZK Framework", "Langflow", "XWiki", "Yiiframework", "Git", "PHP Group", "GNU",
                                    "Spreadsheet::ParseExcel", "Rejetto", "SimpleHelp", "Wazuh", "Erlang", "FreeType", "Meta Platforms"],
    "IoT, cameras & embedded": ["GeoVision", "PTZOptics", "Reolink", "Dahua", "Hikvision", "NUUO", "Digiever", "Unitronics", "Trimble",
                                "IGEL", "Nostromo", "ZKTeco", "SolarView", "AMI", "FXC", "Smartbedded"],
    "Desktop & file utilities": ["RARLAB", "7-Zip", "Kingsoft"],
}
OTHER_GROUP = "Other / unclassified"
VENDOR_TO_GROUP = {v.lower(): g for g, vs in GROUPS.items() for v in vs}


def vendor_group(vendor) -> str:
    return VENDOR_TO_GROUP.get(str(vendor).strip().lower(), OTHER_GROUP)


# ---- speed -----------------------------------------------------------------------------------
def speed_row(label: str, days: pd.Series) -> dict:
    d = days.dropna()
    q = d.quantile([0.25, 0.5, 0.75]) if len(d) else pd.Series([np.nan] * 3, index=[0.25, 0.5, 0.75])
    row = dict(group=label, n=len(d), q25=q[0.25], median=q[0.5], q75=q[0.75], n_before_publication=int((d < 0).sum()))
    for n in (30, 90, 365):
        row[f"share_within_{n}d"] = float((d <= n).mean()) if len(d) else np.nan
    return row


def exploit_flag_at_publish_month(v: pd.DataFrame, data_dir=DATA_DIR) -> pd.Series:
    """1/0 flag (any of the four exploit-code flags) at the end of the CVE's publish month, for CVEs published 2024-2025 only
    (exploit_signals files cover 2024-2025); NaN outside that range."""
    con = duckdb.connect()
    sig = con.execute(f"""SELECT cve_id, month,
          GREATEST(TRY_CAST(exploitdb AS INT), TRY_CAST(metasploit AS INT), TRY_CAST(nuclei AS INT), TRY_CAST(poc_github AS INT)) AS f
        FROM read_csv_auto(['{data_dir}/exploit_signals_2024.csv', '{data_dir}/exploit_signals_2025.csv'], all_varchar=true)""").df()
    sig["month"] = sig["month"].astype(str)
    m = v[v["published"] >= "2024-01-01"].assign(month=lambda d: d["published"].dt.strftime("%Y-%m"))
    j = m[["cve_id", "month"]].merge(sig, on=["cve_id", "month"], how="left")
    flag = j.set_index("cve_id")["f"].fillna(0).astype(int)  # no signal row = no flags
    return v["cve_id"].map(flag)


def speed_tables(v: pd.DataFrame, data_dir=DATA_DIR) -> pd.DataFrame:
    a = v[v["attacked"] == 1].copy()
    a["days"] = (a["date_added"] - a["published"]).dt.days
    a["flag"] = exploit_flag_at_publish_month(v, data_dir).loc[a.index]
    rows = []
    for cohort, sub in [("published 2022-01..2025-09", a), ("published 2022..2024 (365-day window fully observed)", a[a["published"] < "2025-01-01"])]:
        rows.append({**speed_row("all attacked", sub["days"]), "cohort": cohort})
        for k, lab in [("Known", "ransomware use: Known"), ("Unknown", "ransomware use: Unknown")]:
            rows.append({**speed_row(lab, sub.loc[sub["known_ransomware_use"] == k, "days"]), "cohort": cohort})
    sub = a[a["published"] >= "2024-01-01"]
    for val, lab in [(1, "had a public exploit flag at end of publish month"), (0, "no exploit flag at end of publish month")]:
        rows.append({**speed_row(lab, sub.loc[sub["flag"] == val, "days"]), "cohort": "published 2024-01..2025-09 only (exploit_signals cover 2024-2025)"})
    cols = ["cohort", "group", "n", "q25", "median", "q75", "n_before_publication", "share_within_30d", "share_within_90d", "share_within_365d"]
    return pd.DataFrame(rows)[cols], a


# ---- composition: invisible positives in the replicas -----------------------------------------
def invisible_composition(out_dir=OUT_DIR, data_dir=DATA_DIR):
    """Per replica: positives and how many are 'invisible' (no exploit flag and within-month EPSS rank below the cut a top-k EPSS
    list makes). Reuses the replica feature files; cross-checked against outputs/blindspot_positives.csv."""
    from src.common.scoring import k_for_pool
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "vendor"]).drop_duplicates("cve_id").set_index("cve_id")["vendor"]
    rows = []
    for y in (2024, 2025):
        f = pd.read_parquet(out_dir / f"features_replica_{y}.parquet", columns=["cve_id", "snapshot_month", "label", "any_exploit", "epss_rank_in_month"])
        k = k_for_pool(len(f))
        inv = (f["label"] == 1) & (f["any_exploit"] == 0) & (f["epss_rank_in_month"] < 1 - k / len(f))
        p = f[f["label"] == 1].assign(replica=y, invisible=inv[f["label"] == 1].astype(int))
        p["kev_vendor"] = p["cve_id"].map(kev)
        rows.append(p)
    pos = pd.concat(rows, ignore_index=True)
    pos["vendor_group"] = pos["kev_vendor"].map(vendor_group)
    bs = pd.read_csv(out_dir / "blindspot_positives.csv")
    assert set(pos.loc[pos["invisible"] == 1, "cve_id"]) == set(bs["cve_id"]), "invisible set differs from outputs/blindspot_positives.csv"
    return pos


def composition_tables(pos: pd.DataFrame):
    def row(label, d):
        n, k = len(d), int(d["invisible"].sum())
        lo, hi = wilson_interval(k, n)
        return dict(group=label, positives=n, invisible=k, share_invisible=k / n if n else np.nan, ci_low=lo, ci_high=hi)
    by_rep = pd.DataFrame([row(f"replica {y}", pos[pos["replica"] == y]) for y in (2024, 2025)] + [row("both replicas", pos)])
    by_vendor = pd.DataFrame([row(g, d) for g, d in pos.groupby("vendor_group")]).sort_values("positives", ascending=False).reset_index(drop=True)
    return by_rep, by_vendor


# ---- charts -----------------------------------------------------------------------------------
BLUE, ORANGE, AQUA, GREY, INK, MUTED, GRID = "#2a78d6", "#eb6834", "#1baf7a", "#9a9890", "#0b0b0b", "#52514e", "#e6e5e1"


def _style(ax, xlabel=None, ylabel=None):
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.grid(color=GRID, lw=0.6, axis="x")
    ax.set_axisbelow(True)
    if xlabel:
        ax.set_xlabel(xlabel, color=MUTED)
    if ylabel:
        ax.set_ylabel(ylabel, color=MUTED)
    ax.tick_params(colors=MUTED)


def _title(fig, text):
    fig.suptitle(text, x=0.01, ha="left", fontsize=12, fontweight="bold", color=INK, wrap=True)


def _dotplot(rows, overall, title, path, xlabel="share of CVEs attacked (KEV), with 95% Wilson interval", ref_label="all CVEs"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(9, 0.42 * len(rows) + 1.6))
    y = np.arange(len(rows))[::-1]
    for yi, r in zip(y, rows):
        ax.plot([r["ci_low"], r["ci_high"]], [yi, yi], color=r.get("color", BLUE), lw=2)
        ax.plot(r["rate"], yi, "o", color=r.get("color", BLUE), ms=7, mec="white", mew=1.2)
    ax.axvline(overall, color=GREY, ls="--", lw=1)
    ax.text(overall, len(rows) - 0.35, f" {ref_label} {overall:.2%}", color=MUTED, fontsize=8, va="bottom")
    ax.set_yticks(y)
    ax.set_yticklabels([r["label"] for r in rows], fontsize=8.5, color=INK)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=1))
    _style(ax, xlabel)
    _title(fig, title)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def _fmt_pct(x, d=1):
    return f"{x:.{d}%}"


def _md(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    return "\n".join(out + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def _table_md(t: pd.DataFrame, label_col: str, extra: list[str] = ()):
    heads = [label_col, "CVEs", "attacked", "attack rate", "lift", "95% interval", *extra]
    rows = [(r[label_col], f"{int(r.n):,}", int(r.attacked), _fmt_pct(r.rate, 2), f"{r.lift:.2f}x",
             f"{r.ci_low:.2%}-{r.ci_high:.2%}", *[r[e] for e in extra]) for _, r in t.iterrows()]
    return _md(heads, rows)


def main(data_dir=DATA_DIR, out_dir=OUT_DIR, fig_dir=None):
    fig_dir = fig_dir or REPO_ROOT / "docs" / "figures"
    v, con = load_scope(data_dir)
    n_all, n_att = len(v), int(v["attacked"].sum())
    overall = n_att / n_all

    # 1. attack-rate tables
    cvss_parts = [shown(rate_table(v, a, overall)) for a in CVSS_ATTRS]
    combo = shown(rate_table(v, "combo", overall, "network + no privileges + no user interaction"))
    cvss = pd.concat(cvss_parts + [combo], ignore_index=True)
    cwe = shown(cwe_table(v, overall, data_dir))
    assigner = shown(rate_table(v, "assigner", overall))
    vend_all, no_prod = vendor_product_table(v, overall, con, data_dir)
    vendors = shown(vend_all)
    year = shown(rate_table(v, "publish_year", overall))
    a = v[v["attacked"] == 1].copy()
    a["vendor_group"] = a["kev_vendor"].map(vendor_group)
    kev_groups = a.groupby("vendor_group").size().rename("attacked").reset_index().sort_values("attacked", ascending=False)
    kev_groups["share_of_attacked"] = kev_groups["attacked"] / n_att
    kev_vendors = a.groupby(["kev_vendor", "vendor_group"]).size().rename("attacked").reset_index().sort_values("attacked", ascending=False)
    kev_vendors["share_of_attacked"] = kev_vendors["attacked"] / n_att
    vmap = pd.DataFrame({"kev_vendor": sorted(set(a["kev_vendor"]))})
    vmap["vendor_group"] = vmap["kev_vendor"].map(vendor_group)

    # 2. speed
    speed, att = speed_tables(v, data_dir)
    # 3. composition
    pos = invisible_composition(out_dir, data_dir)
    by_rep, by_vendor = composition_tables(pos)

    for name, df in [("cvss", cvss), ("cwe", cwe), ("assigner", assigner), ("vendor_products", vendors), ("publish_year", year),
                     ("kev_vendor_groups", kev_groups), ("kev_vendors", kev_vendors), ("vendor_group_map", vmap), ("speed", speed),
                     ("invisible_by_replica", by_rep), ("invisible_by_vendor_group", by_vendor)]:
        df.round(6).to_csv(out_dir / f"why_attacked_{name}.csv", index=False)

    # ---- findings (numbers computed here; wording is association only)
    g = lambda t, c: t[t["category"] == c].iloc[0]  # noqa: E731
    cb, other = g(combo, COMBO), g(combo, "all other CVSS 3 CVEs")
    av = rate_table(v, "attack_vector", overall).set_index("category")
    sev = rate_table(v, "cvss3_severity", overall).set_index("category")
    top_cwe = cwe[(cwe["attacked"] >= 10) & ~cwe["cwe_id"].isin(["(missing)"])].head(4)
    top_vendors = vendors[vendors["attacked"] >= 10].head(4)
    ms = vend_all[vend_all["category"] == "microsoft"].iloc[0]
    spd = speed[(speed["cohort"] == "published 2022-01..2025-09") & (speed["group"] == "all attacked")].iloc[0]
    spd_full = speed[speed["group"] == "all attacked"].iloc[1]
    both = by_rep[by_rep["group"] == "both replicas"].iloc[0]
    rng_vendor = by_vendor[by_vendor["positives"] >= 10]
    crit = sev.loc["CRITICAL"]
    findings = [
        f"**Exposure:** network-reachable CVEs that need no privileges and no user interaction were attacked at {cb.rate:.2%} ({int(cb.attacked)} of {int(cb.n):,}) "
        f"versus {other.rate:.2%} ({int(other.attacked)} of {int(other.n):,}) for all other CVSS 3 CVEs, {cb.rate / other.rate:.1f}x as often with non-overlapping 95% intervals "
        f"({cb.ci_low:.2%}-{cb.ci_high:.2%} vs {other.ci_low:.2%}-{other.ci_high:.2%}); network attack vector alone barely separates "
        f"({av.loc['NETWORK', 'lift']:.2f}x the overall rate).",
        "**Weakness type:** " + "; ".join(f"{r.name} ({r.cwe_id}) {r.rate:.1%} ({int(r.attacked)} of {int(r.n):,}, {r.lift:.1f}x)" for r in top_cwe.itertuples()) +
        " were the CWE types with the highest attack rates among those with at least 10 attacked CVEs.",
        f"**Who ships the CVE:** products from a few vendors dominate: Microsoft products appear in {int(ms.attacked)} of the {n_att} attacked CVEs ({ms.share_of_attacked:.1%}) at "
        f"{ms.rate:.1%} of its {int(ms.n):,} CVEs ({ms.lift:.1f}x), and the highest vendor attack rates are "
        + ", ".join(f"{r.category} {r.rate:.1%} ({int(r.attacked)} of {int(r.n)})" for r in top_vendors.itertuples()) + ".",
        f"**Speed:** half of the {int(spd.n)} attacked CVEs reached KEV within {spd['median']:.0f} days of NVD publication (quartiles {spd.q25:.0f} and {spd.q75:.0f}); "
        f"{spd.share_within_30d:.0%} within 30 days, {spd.share_within_90d:.0%} within 90 and {spd_full.share_within_365d:.0%} within 365 days "
        f"(CVEs published 2022-2024, n={int(spd_full.n)}); {int(spd.n_before_publication)} were added before their NVD publication date.",
        f"**Invisibility:** {int(both.invisible)} of {int(both.positives)} attacked CVEs ({both.share_invisible:.0%}, 95% interval {both.ci_low:.0%}-{both.ci_high:.0%}) in the 2024 and 2025 "
        f"practice pools had no public exploit flag and a low within-month EPSS rank at the end of their publish month, and that share was "
        f"{rng_vendor['share_invisible'].min():.0%}-{rng_vendor['share_invisible'].max():.0%} across the vendor groups with at least 10 attacked CVEs.",
    ]

    # ---- charts
    rows = []
    for lab, t, c, col in [(f"{COMBO}", combo, COMBO, BLUE), ("all other CVSS 3 CVEs", combo, "all other CVSS 3 CVEs", GREY)]:
        r = g(t, c)
        rows.append(dict(label=f"{lab}  (n={int(r.n):,})", rate=r.rate, ci_low=r.ci_low, ci_high=r.ci_high, color=col))
    for attr, cats in [("privileges_required", ["NONE", "LOW", "HIGH"]), ("user_interaction", ["NONE", "REQUIRED"]),
                       ("attack_vector", ["NETWORK", "LOCAL"]), ("cvss3_severity", ["CRITICAL", "HIGH", "MEDIUM"])]:
        t = rate_table(v, attr, overall).set_index("category")
        for c in cats:
            r = t.loc[c]
            rows.append(dict(label=f"{attr}: {c}  (n={int(r.n):,})", rate=r.rate, ci_low=r.ci_low, ci_high=r.ci_high, color=ORANGE if attr == "cvss3_severity" else MUTED))
    _dotplot(rows, overall, f"Network + no privileges + no user interaction: attacked {cb.rate / other.rate:.1f}x as often as other CVSS 3 CVEs",
             fig_dir / "why_attacked_cvss.png")
    rows = [dict(label=f"{r.cwe_id} {r.name[:46]}  ({int(r.attacked)}/{int(r.n):,})", rate=r.rate, ci_low=r.ci_low, ci_high=r.ci_high)
            for r in cwe[(cwe["attacked"] >= 10) & (cwe["cwe_id"] != "(missing)")].head(10).itertuples()]
    _dotplot(rows, overall, f"{top_cwe.iloc[0].cwe_id}, {top_cwe.iloc[1].cwe_id} and {top_cwe.iloc[2].cwe_id}: weakness types attacked {top_cwe.iloc[2].lift:.0f}-{top_cwe.iloc[0].lift:.0f}x as often as average",
             fig_dir / "why_attacked_cwe.png")
    rows = [dict(label=f"{r.category}  ({int(r.attacked)}/{int(r.n):,})", rate=r.rate, ci_low=r.ci_low, ci_high=r.ci_high)
            for r in vendors[vendors["attacked"] >= 10].head(12).itertuples()]
    _dotplot(rows, overall, f"Products from {top_vendors.iloc[0].category}, {top_vendors.iloc[1].category} and {top_vendors.iloc[2].category} have the highest attack rates",
             fig_dir / "why_attacked_vendors.png")
    _speed_chart(att, spd, fig_dir / "why_attacked_speed.png")
    rows = [dict(label=f"{r.group}  ({int(r.invisible)}/{int(r.positives)})", rate=r.share_invisible, ci_low=r.ci_low, ci_high=r.ci_high,
                 color=BLUE if r.group == "both replicas" else MUTED)
            for r in pd.concat([by_rep.iloc[[2, 0, 1]], by_vendor[by_vendor["positives"] >= 10]]).itertuples()]
    _dotplot(rows, both.share_invisible, f"{both.share_invisible:.0%} of attacked CVEs in the 2024-25 practice pools were invisible to exploit flags and EPSS",
             fig_dir / "why_attacked_invisible.png", xlabel="share of attacked CVEs that were invisible, with 95% Wilson interval", ref_label="both replicas")

    write_report(out_dir, locals())
    print("\n".join(findings))
    return findings


def _speed_chart(att, spd, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(9, 4.6))
    xs = np.arange(0, 366)
    for lab, sub, col in [("all attacked", att, BLUE), ("ransomware use known", att[att["known_ransomware_use"] == "Known"], ORANGE),
                          ("ransomware use unknown", att[att["known_ransomware_use"] == "Unknown"], AQUA)]:
        d = sub["days"].clip(lower=0)
        ax.plot(xs, [(d <= x).mean() for x in xs], color=col, lw=2.2 if lab == "all attacked" else 1.6, label=f"{lab} (n={len(sub)})")
    ax.set_xlim(0, 365)
    ax.set_ylim(0, 1)
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    ax.grid(color=GRID, lw=0.6)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.set_xlabel("days from NVD publication to KEV (before publication counted as day 0)", color=MUTED)
    ax.set_ylabel("share of attacked CVEs added by then", color=MUTED)
    ax.tick_params(colors=MUTED)
    _title(fig, f"Half of attacked CVEs reached KEV within {spd['median']:.0f} days of publication; {spd.share_within_30d:.0%} within 30 days")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)


def write_report(out_dir, g):
    v, overall, n_all, n_att = g["v"], g["overall"], g["n_all"], g["n_att"]
    findings, no_prod = g["findings"], g["no_prod"]
    cvss_parts, combo, cwe, assigner, vendors, year = g["cvss_parts"], g["combo"], g["cwe"], g["assigner"], g["vendors"], g["year"]
    speed, by_rep, by_vendor, kev_groups, kev_vendors = g["speed"], g["by_rep"], g["by_vendor"], g["kev_groups"], g["kev_vendors"]
    crit = g["crit"]
    n_missing_cvss = int(v["attack_vector"].isna().sum())
    L = ["# Why are some vulnerabilities attacked? (descriptive analysis for the pitch)", "",
         "> **DESCRIPTIVE ONLY.** This analysis explains the past with today's NVD data. It is **not** used by any model, feature file or top-500 list, and nothing "
         "from it feeds into them. All statements are associations, never causes.", "",
         f"**Scope and definitions.** CVEs in `vulnerabilities.csv` published {SCOPE_START} to {SCOPE_END}: {n_all:,} CVEs. *Attacked* = the cve_id appears in "
         f"`known_exploited.csv` (CISA KEV, added on or before 2025-12-31; the file ends there): {n_att} CVEs, an overall rate of {overall:.2%} (about 1 in {1 / overall:.0f}). "
         "Because the CVEs are historical and the aim is to explain rather than predict, today's NVD fields (CVSS vector parts, `cwe_ids`, affected products) are used. "
         "These fields are not time-safe and must never be used as prediction features. Intervals are 95% Wilson intervals; *lift* = category attack rate / overall rate. "
         f"Tables list categories with at least {MIN_N} CVEs or at least {MIN_ATTACKED} attacked CVEs, sorted by lift.", "",
         "## The five strongest, best-supported findings", ""]
    L += [f"{i}. {f}" for i, f in enumerate(findings, 1)]
    L += ["", "## What a security team should do with this", "",
          "These are practical priorities consistent with the associations above, not proven causes. Put internet-reachable, unauthenticated flaws in products that sit at the edge or manage "
          "other systems (missing-authentication, authentication-bypass, deserialization and command-injection types) at the front of the queue, especially from vendors with a history of "
          "exploited bugs, and plan for days, not months: half of the attacked CVEs reached KEV within about a week of publication and about two thirds within 30 days. Do not rely on "
          f"a single signal: {crit.rate:.1%} of CRITICAL-severity CVEs were attacked, so about {1 - crit.rate:.0%} of them never were, and most attacked CVEs "
          f"({g['both'].share_invisible:.0%} in the 2024-25 practice pools) showed neither public exploit code nor a high EPSS rank at the end of their publish month. Combine exposure "
          "(is the product reachable?), weakness type, vendor history and the exploit signals, and re-check weekly.", "",
          "## Tables", "", "### CVSS 3 attributes and the exposure combination", ""]
    for part in cvss_parts + [combo]:
        L += [_table_md(part, "category"), ""]
        L[-2] = f"*{part.iloc[0]['attribute']}*\n\n" + L[-2]
    L += ["### Weakness types (CWE), top by lift; a CVE with several CWE ids is counted under each", "", _table_md(cwe.head(20).assign(category=lambda d: d["cwe_id"] + " " + d["name"].str[:60]), "category"), "",
          "### Vendors from affected_products.csv (vulnerable = Y), top by lift", "",
          _table_md(vendors.head(20).assign(**{"share of attacked": lambda d: d["share_of_attacked"].map(lambda x: f"{x:.1%}")}), "category", ["share of attacked"]), "",
          f"CVEs with no vulnerable product listed: {no_prod['n']:,}, of which {no_prod['attacked']} attacked (see limits).", "",
          "### Assigners, top by lift", "", _table_md(assigner.head(15), "category"), "",
          "### Publish year", "", _table_md(year.sort_values("category"), "category"), "",
          "### KEV vendor groups of the attacked CVEs (analyst-assigned groups, `why_attacked_vendor_group_map.csv`)", "",
          _md(["vendor group", "attacked CVEs", "share of attacked"], [(r.vendor_group, r.attacked, f"{r.share_of_attacked:.1%}") for r in kev_groups.itertuples()]), "",
          "Top KEV vendors: " + ", ".join(f"{r.kev_vendor} {r.attacked}" for r in kev_vendors.head(10).itertuples()) + ".", "",
          "### Speed: days from NVD publication to KEV", "",
          _md(["cohort", "group", "n", "q25", "median", "q75", "added before publication", "within 30d", "within 90d", "within 365d"],
              [(r.cohort, r.group, int(r.n), f"{r.q25:.0f}", f"{r.median:.1f}", f"{r.q75:.0f}", r.n_before_publication, _fmt_pct(r.share_within_30d, 0),
                _fmt_pct(r.share_within_90d, 0), _fmt_pct(r.share_within_365d, 0)) for r in speed.itertuples()]), "",
          "The exploit-flag split uses CVEs published 2024-01 to 2025-09 only, because the exploit_signals files cover 2024-2025; the flag is the state at the end of the publish month, "
          "which for a CVE attacked early can already reflect the attack (proof-of-concept code often appears after exploitation begins).", "",
          "### Invisible attacked CVEs in the 2024 and 2025 practice pools", "",
          _md(["group", "attacked CVEs", "invisible", "share invisible", "95% interval"],
              [(r.group, r.positives, r.invisible, _fmt_pct(r.share_invisible, 0), f"{r.ci_low:.0%}-{r.ci_high:.0%}") for r in pd.concat([by_rep, by_vendor]).itertuples()]), "",
          "'Invisible' = no public exploit flag and a within-month EPSS rank below the cut a top-k EPSS list would make (the same definition as `outputs/blindspot_positives.csv`, cross-checked). "
          "Groups with fewer than 10 attacked CVEs are too small to compare.", "",
          "## Limits", "",
          "- **Association, not causation.** Nothing here shows why attackers chose a CVE; categories overlap (a CVE can be network-reachable, unauthenticated, and from a popular vendor at once) and no adjustment was made.",
          "- **KEV is a lower bound on real attacks and is US-government focused.** A CVE missing from KEV may still have been attacked; products and vendors central to US federal systems are over-represented.",
          "- **NVD fields are today's versions.** Details can be added after an attack, and NIST reviews KEV entries first. The zero attacked among "
          f"{n_missing_cvss:,} CVEs with no CVSS 3 data and among {no_prod['n']:,} CVEs with no listed product is almost certainly this review order, not evidence that such CVEs are safe.",
          "- **Right-censoring.** CVEs published in 2025 had at most 12 months to reach KEV (the file ends 2025-12-31), so 2025 rates and long-delay shares are understated; the 365-day share is reported only for CVEs published through 2024.",
          "- **Small counts and many comparisons.** Many categories were examined; tiny categories (for example a vendor with 25 CVEs) have wide intervals and unstable lifts. A CVE with several CWE ids or vendors counts under each.",
          "- **Vendor groups are analyst-assigned and coarse**; vendors not recognised fall under 'Other / unclassified'. Vendors in the NVD product list use NVD naming (lower case, no spaces) and differ from the KEV `vendor` field.",
          "- **Too good to be true?** The zero-attacked rows for missing CVSS and missing products (above) and the very high rates for a few small vendors are artifacts of review order and small samples. Treat the lifts of the largest categories as the reliable ones."]
    (out_dir / "why_attacked_report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
