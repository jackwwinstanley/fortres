"""Before the Breach: team dashboard (issue #10 skeleton).

Run:  streamlit run app/dashboard.py

Reads whatever is in outputs/ and shows a placeholder when a file isn't there yet:
  top500_v*.csv (newest version), explanations.csv, runlog.csv, text_features.parquet,
  scoreboard_features.parquet, b_drift.json.
"""
import json
import re
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

OUT = Path(__file__).resolve().parents[1] / "outputs"

# One palette everywhere: our model = accent blue, baselines = neutral greys.
ACCENT = "#2563eb"
GREYS = ["#9aa5b1", "#7b8794", "#616e7c"]
WARN = "#d97706"
FLAG_LABELS = {
    "txt_rce": "remote code execution", "txt_unauth": "no login needed",
    "txt_auth_bypass": "authentication bypass", "txt_cmd_injection": "command injection",
    "txt_deserialization": "unsafe deserialization", "txt_path_traversal": "path traversal",
    "txt_sqli": "SQL injection", "txt_priv_esc": "privilege escalation",
    "txt_memory": "memory corruption", "txt_edge_device": "VPN / firewall / edge device",
    "txt_enterprise": "widely deployed enterprise product", "txt_browser": "web browser",
    "txt_wordpress": "WordPress plugin", "txt_xss": "cross-site scripting",
}
BASELINE_NAMES = {"baseline_cvss": "Highest CVSS", "baseline_epss": "Highest EPSS",
                  "baseline_exploit_epss": "Public exploit, then EPSS"}

st.set_page_config(page_title="Before the Breach", page_icon="🛡️", layout="wide")


@st.cache_data
def read(name: str):
    p = OUT / name
    if not p.exists():
        return None
    if p.suffix == ".parquet":
        return pd.read_parquet(p)
    if p.suffix == ".json":
        return json.loads(p.read_text())
    return pd.read_csv(p)


def latest_top500():
    files = sorted(OUT.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    return (files[-1].stem, pd.read_csv(files[-1])) if files else (None, None)


def style(fig: go.Figure, title: str, x_title: str = "", y_title: str = "") -> go.Figure:
    fig.update_layout(title=dict(text=title, x=0, xanchor="left", font=dict(size=17)),
                      xaxis_title=x_title, yaxis_title=y_title, bargap=0.35,
                      margin=dict(l=10, r=10, t=60, b=10), legend_title_text="",
                      legend=dict(orientation="h", yanchor="bottom", y=1.0, x=1, xanchor="right"))
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridwidth=0.5)
    return fig


def placeholder(what: str, how: str):
    st.info(f"**{what}**: coming soon. {how}", icon="⏳")


version, top = latest_top500()
runlog, tf, sb = read("runlog.csv"), read("text_features.parquet"), read("scoreboard_features.parquet")
explanations, drift = read("explanations.csv"), read("b_drift.json")

st.title("Before the Breach")
st.caption("Which of the 72,670 CVEs in the 2026 scoreboard will be added to CISA's Known Exploited "
           "Vulnerabilities list by 4 Nov 2026? We pick 500, using only what was known at the time.")

# Headline: best model vs best baseline on each practice year.
cols = st.columns(4)
if runlog is not None:
    rl = runlog.sort_values("timestamp").drop_duplicates(["version", "replica"], keep="last")
    for i, y in enumerate((2024, 2025)):
        r = rl[rl["replica"] == y]
        base = r[r["version"].str.startswith("baseline")]
        model = r[~r["version"].str.startswith("baseline")]
        best_base = int(base["hits"].max()) if len(base) else None
        if len(model):
            m = model.loc[model["hits"].idxmax()]
            cols[2 * i].metric(f"{y}: our hits", int(m["hits"]),
                               delta=None if best_base is None else f"{int(m['hits']) - best_base:+d} vs best baseline")
        else:
            cols[2 * i].metric(f"{y}: our hits", "–", help="No model run logged yet")
        cols[2 * i + 1].metric(f"{y}: best simple rule", "–" if best_base is None else best_base,
                               help=f"k = {int(r['k'].iloc[0]) if len(r) else '?'} picks")
else:
    placeholder("Practice results", "Person A logs runs to outputs/runlog.csv.")

tab_list, tab_base, tab_drift = st.tabs(["Top 500", "How we beat the baselines", "Is 2026 different?"])

with tab_list:
    if top is None:
        placeholder("The top 500 list", "Person A writes outputs/top500_vN.csv.")
    else:
        d = top.reset_index(names="rank")
        d["rank"] += 1
        if sb is not None:
            d = d.merge(sb[["cve_id", "epss", "exploitdb", "metasploit", "nuclei", "poc_github"]],
                        on="cve_id", how="left")
            d["public exploit"] = d[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1).map({1: "yes", 0: ""})
        if tf is not None:
            d = d.merge(tf, on="cve_id", how="left")
        if explanations is not None:
            d = d.merge(explanations, on="cve_id", how="left")
        else:
            flags = [c for c in FLAG_LABELS if c in d]
            d["reason"] = d[flags].apply(
                lambda r: ", ".join(FLAG_LABELS[c] for c in flags if r[c] == 1), axis=1) if flags else ""
            d["reason"] = "(draft) " + d["reason"].where(d["reason"] != "", "no text pattern matched")
        st.subheader(f"Our picks ({version}, {len(d)} CVEs)")
        q = st.text_input("Search", placeholder="CVE id or a word from the reason, e.g. VPN")
        if q:
            d = d[d["cve_id"].str.contains(q, case=False) | d["reason"].str.contains(q, case=False, na=False)]
        show = [c for c in ["rank", "cve_id", "reason", "epss", "public exploit", "kev_text_score"] if c in d]
        view = d[show].assign(cve_id="https://nvd.nist.gov/vuln/detail/" + d["cve_id"])
        st.dataframe(
            view, hide_index=True, use_container_width=True, height=520,
            column_config={
                "rank": st.column_config.NumberColumn("Rank", width="small"),
                "cve_id": st.column_config.LinkColumn(
                    "CVE", display_text=r"https://nvd.nist.gov/vuln/detail/(.*)", width="medium"),
                "reason": st.column_config.TextColumn("Why it's on the list", width="large"),
                "epss": st.column_config.ProgressColumn("EPSS", format="%.3f", min_value=0, max_value=1),
                "public exploit": st.column_config.TextColumn("Public exploit", width="small"),
                "kev_text_score": st.column_config.ProgressColumn(
                    "Sounds like past KEV", format="%.2f", min_value=0, max_value=1,
                    help="IBM Granite text score: how much the description resembles known-exploited ones"),
            })
        if explanations is None:
            st.caption("Reasons are draft tags from the description until Granite explanations (#13) land.")

with tab_base:
    if runlog is None:
        placeholder("Baseline comparison", "Person A logs runs to outputs/runlog.csv.")
    else:
        rl = runlog.sort_values("timestamp").drop_duplicates(["version", "replica"], keep="last")
        versions = list(dict.fromkeys(rl.sort_values("version")["version"]))
        base_v = [v for v in versions if v.startswith("baseline")]
        model_v = [v for v in versions if not v.startswith("baseline")]
        fig = go.Figure()
        for i, v in enumerate(base_v + model_v):
            r = rl[rl["version"] == v].sort_values("replica")
            is_model = v in model_v
            fig.add_bar(name=BASELINE_NAMES.get(v, v), x=r["replica"].astype(str), y=r["hits"],
                        marker_color=ACCENT if is_model else GREYS[i % len(GREYS)],
                        text=r["hits"], textposition="outside", cliponaxis=False)
        best = rl[rl["version"].isin(base_v)].groupby("replica")["hits"].max()
        title = ("Our model vs simple rules on past years" if model_v else
                 f"Best simple rule finds {best.get(2024, '?')} (2024) and {best.get(2025, '?')} (2025) "
                 "exploited CVEs: that's the bar to beat")
        fig.update_yaxes(range=[0, rl["hits"].max() * 1.2 + 1])
        st.plotly_chart(style(fig, title, "Practice year", "Exploited CVEs caught in the top k"),
                        use_container_width=True, theme="streamlit")
        pos = runlog.drop_duplicates("replica").set_index("replica")["notes"].str.extract(r"positives=(\d+)")[0]
        st.caption("k scales the 500 picks to each practice pool's size. Positives available: "
                   + ", ".join(f"{y}: {p}" for y, p in pos.items()) + ".")
        if not model_v:
            placeholder("Our model's bars", "They appear here once Person A logs a model run.")

with tab_drift:
    if drift is None:
        placeholder("Drift check", "Run `python -m src.b.drift`.")
    else:
        auc = drift["spot_the_year_auc"]
        shift = pd.DataFrame(drift["shift"]).head(10).iloc[::-1]
        c1, c2 = st.columns([1, 2])
        c1.metric("Spot-the-year score", f"AUC {auc:.2f}",
                  help="0.5 = indistinguishable, 1.0 = perfectly separable")
        c1.markdown(
            "The 2026 scoreboard is **clearly different** from the practice pools. The biggest change is "
            "EPSS: the typical 2026 score is several times higher, so a fixed EPSS threshold tuned on past "
            "years won't transfer. Ranking *within* the year is safer." if auc >= 0.75 else
            "The 2026 scoreboard looks broadly similar to the practice pools.")
        colors = [WARN if v > 0.25 else ACCENT if v > 0.1 else GREYS[0] for v in shift["psi_2025_vs_2026"]]
        fig = go.Figure(go.Bar(x=shift["psi_2025_vs_2026"], y=shift["feature"], orientation="h",
                               marker_color=colors, text=shift["psi_2025_vs_2026"].round(2),
                               textposition="outside", cliponaxis=False))
        fig.update_xaxes(range=[0, shift["psi_2025_vs_2026"].max() * 1.15])
        fig.add_vline(x=0.25, line_dash="dot", line_width=1, annotation_text="large shift",
                      annotation_position="top")
        top_f = shift.iloc[-1]
        c2.plotly_chart(style(fig, f"{top_f['feature']} moved the most between 2025 and 2026",
                              "Population stability index (higher = bigger change)"),
                        use_container_width=True, theme="streamlit")
        if sb is not None:
            ep = []
            for y, f in (("2024", "replica_2024.parquet"), ("2025", "replica_2025.parquet"), ("2026", None)):
                s = sb["epss"] if f is None else read(f)["epss"]
                ep.append((y, s.median() * 100, s.quantile(0.9) * 100))
            ep = pd.DataFrame(ep, columns=["year", "median", "90th percentile"])
            fig = go.Figure()
            fig.add_bar(name="Median CVE", x=ep["year"], y=ep["median"], marker_color=GREYS[0])
            fig.add_bar(name="90th percentile CVE", x=ep["year"], y=ep["90th percentile"], marker_color=ACCENT)
            st.plotly_chart(style(fig, "EPSS scores in the 2026 pool sit several times higher than in past years",
                                  "Pool", "EPSS (% chance of exploitation in 30 days)"),
                            use_container_width=True, theme="streamlit")

st.divider()
st.caption("Sheridan Datathon 2026 · IBM 'Before the Breach' track · Text features by IBM Granite "
           "(granite-embedding-30m-english). Only information available at each snapshot is used.")
