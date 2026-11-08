"""The "Rank a dataset" page: upload a CSV of 2026 CVEs, score it with the saved v6 models, and show a ranked, explained result."""
import io
import time
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from src.b import explain as ex
from src.b.export_story import KINDS
from src.b.score import MAX_ROWS, Scorer, UploadError, read_upload, vendors
from src.common.paths import OUT_DIR, SCOREBOARD_CSV

SAMPLES = Path(__file__).parent / "samples"
TOP = 500
BG, BLUE, GREEN, CORAL, INK, MUTED, LINE = "#080c12", "#4589ff", "#42be65", "#ff8389", "#f4f4f4", "#c6c6c6", "rgba(244,244,244,.14)"
CSS = f"""<style>
.fx-label {{ color: {MUTED}; font-size: 15px; margin-top: -8px; }}
.fx-card {{ border: 1px solid {LINE}; border-radius: 8px; padding: 18px 22px; }}
.fx-big {{ font-family: "IBM Plex Mono", ui-monospace, Menlo, monospace; font-size: 40px; font-weight: 500; line-height: 1.1; }}
.fx-cap {{ color: {MUTED}; font-size: 15px; margin-top: 6px; }}
.fx-time {{ color: {GREEN}; font-family: ui-monospace, Menlo, monospace; font-size: 16px; }}
.fx-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 14px; font-weight: 500; }}
.fx-ok {{ background: {GREEN}; color: {BG}; }} .fx-tpl {{ background: #393939; color: {INK}; }} .fx-fact {{ border: 1px solid {LINE}; color: {MUTED}; }}
</style>"""


@st.cache_resource(show_spinner="Loading the saved v6 models")
def scorer() -> Scorer:
    return Scorer()


@st.cache_resource(show_spinner="Preparing the facts")
def facts_table(_S: Scorer) -> pd.DataFrame:
    """One row per scoreboard CVE: the facts behind the explanation line."""
    sb, tx = _S.sb, _S.text
    f = pd.DataFrame({"cve_id": sb["cve_id"], "epss_pct": sb["epss_rank_in_month"].where(sb["epss"].notna()), "kev_text_pct": tx["kev_text_score"].rank(pct=True),
                      "nearest_kev_sim": tx["nearest_kev_sim"], "epss": sb["epss"]})
    src = list(ex.EXPLOIT_SRC)
    f["exploits"] = [[ex.EXPLOIT_SRC[c] for c, v in zip(src, row) if v == 1] for row in sb[src].to_numpy()]
    names = list(ex.FLAGS)
    f["tags"] = [[ex.TAGS[c] for c, v in zip(names, row) if v == 1] for row in tx[names].to_numpy()]
    def kind(row):
        d = dict(zip(names, row))
        return next((n for n, fl in KINDS if any(d.get(x) == 1 for x in fl)), "Other kind of flaw")
    f["kind"] = [kind(r) for r in tx[names].to_numpy()]
    f["vendor"] = vendors(f["cve_id"]).to_numpy()
    f["drivers"] = [[] for _ in range(len(f))]
    return f.set_index("cve_id")


@st.cache_resource
def explanations() -> pd.DataFrame:
    return pd.read_csv(OUT_DIR / "explanations.csv").set_index("cve_id")


def label_and_reason(cve: str, in_top: bool, known: bool, facts: pd.DataFrame, exp: pd.DataFrame) -> tuple[str, str]:
    if in_top and cve in exp.index:
        e = exp.loc[cve]
        return str(e["explanation"]), ("Checked by Granite Guardian" if e["guardian_verdict"] == "No" else "Template reason")
    if known:
        r = facts.loc[cve].to_dict() | {"cve_id": cve}
        return ex.facts_prose(r), "Facts only, not in the top 500"
    return f"{cve} is not in the 2026 scoreboard, so the Granite text score is not available.", "Facts only, not in the 2026 scoreboard"


def build_table(res: pd.DataFrame, S: Scorer, facts: pd.DataFrame, exp: pd.DataFrame, upload: pd.DataFrame) -> pd.DataFrame:
    top = set(S.top_ids(TOP))
    rows = []
    up = upload.set_index("cve_id")
    for r in res.itertuples():
        reason, label = label_and_reason(r.cve_id, r.cve_id in top, r.in_scoreboard, facts, exp)
        if r.in_scoreboard:
            f = facts.loc[r.cve_id]; kind, vendor, exploit = f["kind"], f["vendor"], bool(f["exploits"])
        else:
            kind, vendor = "Not available", ""
            exploit = any(str(up.loc[r.cve_id].get(c, "0")).strip() in ("1", "1.0", "True", "true") for c in ex.EXPLOIT_SRC)
        rows.append((r.rank_in_upload, r.rank_all_2026, r.cve_id, kind, vendor, round(r.epss_rank * 100, 1), "yes" if exploit else "no", reason, label, r.score, r.cve_id in top))
    return pd.DataFrame(rows, columns=["Rank here", "Rank in all 2026", "CVE", "What it lets an attacker do", "Vendor / reporter", "EPSS percentile in month", "Public exploit code", "Reason", "Reason type", "score", "in_top"])


def card(col, big, cap):
    col.markdown(f'<div class="fx-card"><div class="fx-big">{big}</div><div class="fx-cap">{cap}</div></div>', unsafe_allow_html=True)


def badge(label: str) -> str:
    cls = "fx-ok" if label.startswith("Checked") else "fx-tpl" if label.startswith("Template") else "fx-fact"
    return f'<span class="fx-badge {cls}">{label}</span>'


def signals_chart(cve: str, facts: pd.DataFrame, S: Scorer) -> go.Figure:
    i = S.index[cve]
    f = facts.loc[cve]
    names = ["EPSS percentile in month", "IBM Granite KEV-likeness (percentile)", "Similarity to past KEV entries", "Public exploit sources (of 4)"]
    vals = [float(f["epss_pct"] if pd.notna(f["epss_pct"]) else 0), float(f["kev_text_pct"]), float(f["nearest_kev_sim"]), len(f["exploits"]) / 4]
    fig = go.Figure(go.Bar(x=vals, y=names, orientation="h", marker_color=BLUE, text=[f"{v:.2f}" for v in vals], textposition="outside", cliponaxis=False))
    fig.update_layout(height=230, margin=dict(l=10, r=40, t=10, b=10), paper_bgcolor=BG, plot_bgcolor=BG, font=dict(color=INK, size=14), xaxis=dict(range=[0, 1.05], gridcolor=LINE), yaxis=dict(autorange="reversed"))
    return fig


def dist_chart(df: pd.DataFrame, n: int) -> go.Figure:
    cut = df["score"].nlargest(n).min()
    fig = go.Figure(go.Histogram(x=df["score"], nbinsx=60, marker_color="#2a3442"))
    fig.add_vline(x=cut, line_color=BLUE, line_width=3, annotation_text=f"top {n:,} cut-off", annotation_font_color=BLUE, annotation_position="top left")
    fig.update_layout(height=260, margin=dict(l=10, r=10, t=30, b=10), paper_bgcolor=BG, plot_bgcolor=BG, font=dict(color=INK, size=14), xaxis=dict(title="v6 score", gridcolor=LINE), yaxis=dict(title="CVEs", gridcolor=LINE), bargap=0.03)
    return fig


def render():
    st.markdown(CSS, unsafe_allow_html=True)
    st.title("Rank a dataset")
    st.markdown('<p class="fx-label">v6 model, trained on our 2024 and 2025 test pools, loaded from saved files. Granite text scores were computed in our earlier run.</p>', unsafe_allow_html=True)
    S, facts, exp = scorer(), facts_table(scorer()), explanations()
    a, b, c = st.columns([2, 1, 1])
    up = a.file_uploader(f"Upload a CSV of 2026 vulnerabilities (scoreboard columns, up to {MAX_ROWS:,} rows)", type=["csv"])
    source = None
    if b.button("Use the 2026 scoreboard", use_container_width=True):
        st.session_state["src"] = ("the 2026 scoreboard", SCOREBOARD_CSV)
    sample = c.selectbox("Sample slices", ["None", "One month of 2026 (May)", "2,000 random 2026 CVEs"])
    if sample != "None":
        st.session_state["src"] = (sample, SAMPLES / ("2026_one_month_2026-05.csv" if sample.startswith("One") else "2026_random_2000.csv"))
    if up is not None:
        source = (up.name, up)
    elif "src" in st.session_state:
        source = st.session_state["src"]
    if source:
        st.caption(f"Ready: {source[0]}")
    if st.button("Run", type="primary", disabled=source is None):
        bar = st.progress(0, text="Reading the file")
        try:
            raw = source[1]
            df = read_upload(io.BytesIO(raw.getvalue()) if hasattr(raw, "getvalue") else raw, set(S.ids))
        except UploadError as e:
            bar.empty()
            st.error(str(e))
            st.session_state.pop("res", None)
            return
        bar.progress(25, text=f"Ranking {len(df):,} CVEs")
        t = time.perf_counter()
        res = S.score(df)
        secs = time.perf_counter() - t
        bar.progress(60, text="Writing the reasons")
        tab = build_table(res, S, facts, exp, df)
        bar.progress(100, text="Done")
        bar.empty()
        st.session_state["res"] = dict(tab=tab, secs=secs, name=source[0], dropped=df.attrs.get("dropped_bad_ids", 0))
    if "res" not in st.session_state:
        return
    r = st.session_state["res"]
    tab = r["tab"]
    n_all = len(tab)
    st.markdown(f'<p class="fx-time">Scored {n_all:,} in {r["secs"]:.2f} s on this laptop</p>', unsafe_allow_html=True)
    if r["dropped"]:
        st.warning(f"{r['dropped']:,} rows without a valid CVE id were skipped.")
    n = st.number_input("Top N", min_value=1, max_value=n_all, value=min(TOP, n_all), step=50)
    head = tab.head(int(n))
    c1, c2, c3 = st.columns(3)
    card(c1, f"{n_all:,}", "rows scored")
    card(c2, f"{int(tab['in_top'].sum()):,}", "are in Fortres's 2026 top 500")
    card(c3, f"{int((head['Public exploit code'] == 'yes').sum()):,} of {len(head):,}", f"of your top {len(head):,} have public exploit code")
    st.plotly_chart(dist_chart(tab, int(n)), use_container_width=True)
    f1, f2, f3 = st.columns([2, 2, 1])
    q = f1.text_input("Search by CVE id", placeholder="CVE-2026-")
    vend = f2.multiselect("Vendor / reporter", sorted(v for v in tab["Vendor / reporter"].unique() if v))
    expl = f3.selectbox("Public exploit code", ["All", "yes", "no"])
    view = tab
    if q:
        view = view[view["CVE"].str.contains(q.strip(), case=False, regex=False)]
    if vend:
        view = view[view["Vendor / reporter"].isin(vend)]
    if expl != "All":
        view = view[view["Public exploit code"] == expl]
    show = view.drop(columns=["score", "in_top"]).head(5000)
    st.caption(f"Showing {len(show):,} of {len(view):,}. Click a row to see its signals.")
    ev = st.dataframe(show, use_container_width=True, hide_index=True, height=430, on_select="rerun", selection_mode="single-row",
                      column_config={"Reason": st.column_config.TextColumn(width="large"), "EPSS percentile in month": st.column_config.NumberColumn(format="%.1f")})
    picked = ev.selection.rows if ev and ev.selection else []
    if picked:
        row = show.iloc[picked[0]]
        st.subheader(row["CVE"])
        st.markdown(badge(row["Reason type"]), unsafe_allow_html=True)
        st.write(row["Reason"])
        if row["CVE"] in S.index.index:
            st.plotly_chart(signals_chart(row["CVE"], facts, S), use_container_width=True)
        else:
            st.info("This CVE is not in the 2026 scoreboard, so the Granite text score is not available.")
    d1, d2 = st.columns(2)
    d1.download_button(f"Download the top {len(head):,} (cve_id only)", head[["CVE"]].rename(columns={"CVE": "cve_id"}).to_csv(index=False), file_name=f"top{len(head)}.csv", mime="text/csv")
    d2.download_button("Download the full results", tab.drop(columns=["in_top"]).to_csv(index=False), file_name="fortres_results.csv", mime="text/csv")
