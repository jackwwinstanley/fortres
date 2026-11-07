"""Before the Breach: team dashboard.

Run:  streamlit run app/dashboard.py

Reads whatever is in outputs/ and shows a placeholder when a file isn't there yet:
  top500_final.csv or the newest top500_v*.csv, explanations.csv, runlog.csv (via src.b.runlog),
  text_features.parquet, scoreboard_features.parquet, b_drift.json, blindspot_positives.csv +
  v2_mechanism.csv (blind spots), leakage_results.csv (leakage experiment).
"""
import json
import re
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.b import runlog  # noqa: E402
from src.b.charts import blind_spot_counts  # noqa: E402
from src.b.style import ACCENT, ACCENT_LIGHT, GREYS, WARN  # noqa: E402

OUT = ROOT / "outputs"
FLAG_LABELS = {
    "txt_rce": "remote code execution", "txt_unauth": "no login needed",
    "txt_auth_bypass": "authentication bypass", "txt_cmd_injection": "command injection",
    "txt_deserialization": "unsafe deserialization", "txt_path_traversal": "path traversal",
    "txt_sqli": "SQL injection", "txt_priv_esc": "privilege escalation",
    "txt_memory": "memory corruption", "txt_edge_device": "VPN / firewall / edge device",
    "txt_enterprise": "widely deployed enterprise product", "txt_browser": "web browser",
    "txt_wordpress": "WordPress plugin", "txt_xss": "cross-site scripting",
}

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
    final = OUT / "top500_final.csv"
    if final.exists():
        return "top500_final", pd.read_csv(final)
    files = sorted(OUT.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    return (files[-1].stem, pd.read_csv(files[-1])) if files else (None, None)


def style(fig: go.Figure, title: str, x_title: str = "", y_title: str = "") -> go.Figure:
    fig.update_layout(title=dict(text=title, x=0, xanchor="left", font=dict(size=17)),
                      xaxis_title=x_title, yaxis_title=y_title, bargap=0.25, bargroupgap=0.05,
                      margin=dict(l=10, r=10, t=60, b=10), legend_title_text="",
                      legend=dict(orientation="h", yanchor="top", y=-0.15, x=0, xanchor="left"))
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridwidth=0.5)
    return fig


def bars(fig, name, x, y, color, lo=None, hi=None):
    err = None if lo is None else dict(type="data", array=list(hi - y), arrayminus=list(y - lo),
                                       thickness=1, width=4)
    inside = dict(textposition="inside", insidetextanchor="end", textfont=dict(color="white", size=13))
    fig.add_bar(name=name, x=x, y=y, marker_color=color, text=y, cliponaxis=False, error_y=err,
                **(inside if err else dict(textposition="outside")))


def placeholder(what: str, how: str):
    st.info(f"**{what}**: coming soon. {how}", icon="⏳")


version, top = latest_top500()
res = runlog.results()
best_model = runlog.latest_model(res)
tf, sb = read("text_features.parquet"), read("scoreboard_features.parquet")
explanations, drift, leak = read("explanations.csv"), read("b_drift.json"), read("leakage_results.csv")
blind = blind_spot_counts()

st.title("Before the Breach")
st.caption("Which of the 72,670 CVEs in the 2026 scoreboard will be added to CISA's Known Exploited "
           "Vulnerabilities list by 4 Nov 2026? We pick 500, using only what was known at the time, "
           "and tested the method on 2024 and 2025 first.")

# ---- headline -----------------------------------------------------------------------------------
c = st.columns(4)
if best_model:
    ours = res[res["version"] == best_model].set_index("test_year")["hits"]
    base = res[res["version"] == "baseline_exploit_epss"].set_index("test_year")["hits"]
    c[0].metric("Our catches, 2024+2025", int(ours.sum()),
                delta=f"{int(ours.sum() - base.sum()):+d} vs best simple rule")
    c[1].metric("Best simple rule", int(base.sum()), help="Public exploit code first, then highest EPSS. Exploited CVEs caught in the top k, both test years.")
else:
    placeholder("Practice results", "Person A logs model runs to outputs/runlog.csv.")
if blind is not None:
    b = blind[blind["group"] == "blind-spot"]
    c[2].metric("Blind spots", help="Exploited CVEs with no public exploit code and low EPSS", value=
                f"{int(b['exploited'].sum())} of {int(blind['exploited'].sum())}")
    c[3].metric("Blind spots caught", help="Best simple rule → our model", value=
                f"0 → {int(b[[c for c in blind.columns if c.startswith('Ours')][-1]].sum())}")

tabs = st.tabs(["Blind spots", "Top 500", "vs simple rules", "Is 2026 different?", "Leakage experiment"])

# ---- blind spots --------------------------------------------------------------------------------
with tabs[0]:
    if blind is None:
        placeholder("Blind-spot view", "Needs Person A's blindspot_positives.csv and v2_mechanism.csv.")
    else:
        st.markdown("Most exploited CVEs never had public exploit code and had a low EPSS score when they "
                    "were published, so rules built on those signals **cannot see them at all**. Our text "
                    "features (IBM Granite + description tags) are one of the few signals that reach any of them.")
        models = [c for c in blind.columns if c.startswith("Ours")]
        series = [("Public exploit, then EPSS", GREYS[1])] + [(c, ACCENT if c == models[-1] else ACCENT_LIGHT)
                                                              for c in models]
        cols = st.columns(2)
        for col, y in zip(cols, (2025, 2024)):
            g = blind[blind["year"] == y].set_index("group").loc[["flagged", "blind-spot"]]
            x = [f"Had exploit code ({g.loc['flagged', 'exploited']})",
                 f"Blind spot ({g.loc['blind-spot', 'exploited']})"]
            fig = go.Figure()
            for name, color in series:
                bars(fig, name, x, g[name].to_numpy(), color)
            fig.update_yaxes(range=[0, g[[s for s, _ in series]].to_numpy().max() * 1.3 + 1])
            col.plotly_chart(style(fig, f"Test on {y}", "", "Exploited CVEs caught"),
                             width="stretch", theme="streamlit")
        st.caption("Blind spot = no public exploit flag and EPSS rank below what a top-k EPSS list reaches "
                   "(Person A's definition). Small numbers: 27 and 48 exploited CVEs in the two test years.")

# ---- top 500 ------------------------------------------------------------------------------------
with tabs[1]:
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
        if explanations is not None and d["cve_id"].isin(explanations["cve_id"]).mean() > 0.95:
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
            view, hide_index=True, width="stretch", height=520,
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
        st.caption("Reasons are written by IBM Granite from facts our pipeline supplies; a checker rejects any "
                   "sentence that mentions a product, number or CVE not in those facts.")

# ---- vs simple rules ----------------------------------------------------------------------------
with tabs[2]:
    if res.empty:
        placeholder("Baseline comparison", "Person A logs runs to outputs/runlog.csv.")
    else:
        fig = go.Figure()
        shown = [v for v in ["baseline_cvss", "baseline_epss", "baseline_exploit_epss"] if v in set(res["version"])]
        shown += [best_model] if best_model else []
        for i, v in enumerate(shown):
            r = res[res["version"] == v].sort_values("test_year")
            color = ACCENT if v == best_model else GREYS[i % len(GREYS)]
            bars(fig, runlog.model_name(v), r["test_year"].astype(str), r["hits"].to_numpy(), color,
                 r["ci_lo"].to_numpy(), r["ci_hi"].to_numpy())
        fig.update_yaxes(range=[0, res["ci_hi"].max() * 1.15 + 1])
        title = ("Our model vs the best simple rule: a small gain overall, within the noise" if best_model
                 else "The bar to beat")
        st.plotly_chart(style(fig, title, "Test year (model trained on the other year)",
                              "Exploited CVEs caught in the top k"), width="stretch", theme="streamlit")
        st.caption("Error bars: 90% bootstrap range. k scales the 500 picks to each practice pool's size "
                   "(198 for 2024, 243 for 2025). With only 27 and 48 exploited CVEs, a gap of a few is within noise.")

# ---- drift --------------------------------------------------------------------------------------
with tabs[3]:
    if drift is None:
        placeholder("Drift check", "Run `python -m src.b.drift`.")
    else:
        auc = drift["spot_the_year_auc"]
        shift = pd.DataFrame(drift["shift"]).head(10).iloc[::-1]
        c1, c2 = st.columns([1, 2])
        c1.metric("Spot-the-year score", f"AUC {auc:.2f}", help="0.5 = indistinguishable, 1.0 = perfectly separable")
        c1.markdown(
            "The 2026 scoreboard is **clearly different** from the practice years. The biggest change is "
            "EPSS: the typical 2026 score is several times higher, so a fixed EPSS threshold tuned on past "
            "years won't transfer. Ranking *within* the year is safer." if auc >= 0.75 else
            "The 2026 scoreboard looks broadly similar to the practice years.")
        colors = [WARN if v > 0.25 else ACCENT if v > 0.1 else GREYS[0] for v in shift["psi_2025_vs_2026"]]
        fig = go.Figure(go.Bar(x=shift["psi_2025_vs_2026"], y=shift["feature"], orientation="h",
                               marker_color=colors, text=shift["psi_2025_vs_2026"].round(2),
                               textposition="outside", cliponaxis=False))
        fig.update_xaxes(range=[0, shift["psi_2025_vs_2026"].max() * 1.15])
        fig.add_vline(x=0.25, line_dash="dot", line_width=1, annotation_text="large shift", annotation_position="top")
        c2.plotly_chart(style(fig, f"{shift.iloc[-1]['feature']} moved the most between 2025 and 2026",
                              "Population stability index (higher = bigger change)"),
                        width="stretch", theme="streamlit")

# ---- leakage ------------------------------------------------------------------------------------
with tabs[4]:
    if leak is None:
        placeholder("Leakage experiment", "Run `python -m src.b.leakage`.")
    else:
        leak["replica"] = leak["replica"].astype(str)
        h = leak[leak["model"] == "honest"]["hits"].sum()
        lk = leak[leak["model"] == "leaky"]["hits"].sum()
        st.warning("**Leakage experiment, never submitted.** Same model, plus columns that NVD fills in "
                   "*after* a CVE gets attention (analysis status, reference and product counts, exploit links).",
                   icon="🧪")
        fig = go.Figure()
        for model, label, color in (("Exploit code, then EPSS", "Best simple rule", GREYS[1]),
                                    ("honest", "Our honest model", ACCENT),
                                    ("leaky", "Same model + banned columns", WARN)):
            g = leak[leak["model"] == model].set_index("replica").reindex(["2025", "2024"])
            bars(fig, label, ["Test on 2025", "Test on 2024"], g["hits"].to_numpy(), color,
                 g["ci_lo"].to_numpy(), g["ci_hi"].to_numpy())
        fig.update_yaxes(range=[0, leak["ci_hi"].max() * 1.15 + 1])
        st.plotly_chart(style(fig, f"After-the-fact columns would inflate our results: {lk:.0f} hits instead of {h:.0f}",
                              "", "Exploited CVEs caught in the top k"), width="stretch", theme="streamlit")
        st.markdown("Why: in today's NVD data **every** exploited CVE in both practice years is marked "
                    "*Analyzed*, against about half of the others, because NVD analyses attacked CVEs first. "
                    "At the moment of prediction that field wasn't filled in yet, so a model using it would "
                    "look great on paper and fail on 2026. We never use these columns.")

st.divider()
st.caption("Sheridan Datathon 2026 · IBM 'Before the Breach' track · Text features by IBM Granite "
           "(granite-embedding-30m-english), reasons by granite-3.3-2b-instruct. Only information available "
           "at each snapshot is used.")
