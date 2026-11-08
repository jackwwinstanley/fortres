"""The "Rank a dataset" page: upload a CSV of 2026 CVEs, score it with the saved v6 models, and show a ranked, explained result."""
import io
import time
from pathlib import Path

import pandas as pd
import altair as alt
import numpy as np
import streamlit as st

from app import style as ui
from src.b import explain as ex
from src.b.export_story import KINDS
from src.b.score import MAX_ROWS, Scorer, UploadError, read_upload, vendors  # noqa: F401
from src.common.paths import OUT_DIR, SCOREBOARD_CSV

SAMPLES = Path(__file__).parent / "samples"
TOP = 500
SAMPLE_FILES = {"One month of 2026 (May)": "2026_one_month_2026-05.csv", "2,000 random 2026 CVEs": "2026_random_2000.csv"}
MISSING_SAMPLE = "This sample isn't on this computer yet: run python scripts/make_app_samples.py first."
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


AXIS = dict(labelColor=ui.MUTED, titleColor=ui.MUTED, labelFont="IBM Plex Mono, ui-monospace, Menlo, monospace", titleFont="IBM Plex Sans, system-ui, sans-serif", titleFontWeight=400, domainColor=ui.LINE, tickColor=ui.LINE, grid=False)


def _theme(chart):
    return chart.configure(background=ui.BG).configure_view(strokeWidth=0).configure_axis(**AXIS)


def signals_chart(cve: str, facts: pd.DataFrame) -> alt.Chart:
    f = facts.loc[cve]
    d = pd.DataFrame({"signal": ["EPSS percentile in month", "IBM Granite KEV-likeness (percentile)", "Similarity to past KEV entries", "Public exploit sources (of 4)"],
                      "value": [float(f["epss_pct"] if pd.notna(f["epss_pct"]) else 0), float(f["kev_text_pct"]), float(f["nearest_kev_sim"]), len(f["exploits"]) / 4]})
    y = alt.Y("signal:N", sort=None, title=None, axis=alt.Axis(labelLimit=260, labelFont="IBM Plex Sans, system-ui, sans-serif", ticks=False, domain=False))
    bars = alt.Chart(d).mark_bar(color=ui.ACCENT, height=8).encode(x=alt.X("value:Q", scale=alt.Scale(domain=[0, 1.12]), axis=None), y=y, tooltip=[alt.Tooltip("signal:N", title="signal"), alt.Tooltip("value:Q", format=".2f", title="value")])
    text = bars.mark_text(align="left", dx=6, color=ui.TEXT, font="IBM Plex Mono, ui-monospace, Menlo, monospace").encode(text=alt.Text("value:Q", format=".2f"))
    return _theme(bars + text).properties(height=160)


def dist_chart(df: pd.DataFrame, n: int) -> alt.Chart:
    cut = float(df["score"].nlargest(n).min())
    counts, edges = np.histogram(df["score"].to_numpy(), bins=60, range=(0, 1))
    d = pd.DataFrame({"from": edges[:-1], "to": edges[1:], "CVEs": counts})
    x = alt.X("from:Q", bin="binned", title="v6 score", scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format=".1f", values=[i / 10 for i in range(11)]))
    bars = alt.Chart(d).mark_bar(color=ui.ACCENT, opacity=0.75).encode(x=x, x2="to:Q", y=alt.Y("CVEs:Q", title="CVEs", axis=alt.Axis(tickCount=4)), tooltip=[alt.Tooltip("from:Q", format=".2f", title="score from"), alt.Tooltip("CVEs:Q", format=",", title="CVEs")])
    rule = alt.Chart(pd.DataFrame({"x": [cut], "t": [f"top {n:,} cut-off"]})).mark_rule(color=ui.CORAL, strokeWidth=2).encode(x="x:Q")
    label = alt.Chart(pd.DataFrame({"x": [cut], "t": [f"top {n:,} cut-off"]})).mark_text(align="right", baseline="top", dx=-8, color=ui.CORAL, font="IBM Plex Mono, ui-monospace, Menlo, monospace", fontSize=13).encode(x="x:Q", y=alt.value(2), text="t:N")
    return _theme(bars + rule + label).properties(height=224)


def render():
    S, facts, exp = scorer(), facts_table(scorer()), explanations()
    drop, sources, go_col = st.columns([6, 3, 2], gap="medium", vertical_alignment="bottom")
    up = drop.file_uploader("Drop a CSV of 2026 vulnerabilities", type=["csv"])
    with sources, st.container(key="fx-sources"):
        board = st.button("Use the 2026 scoreboard", use_container_width=True)
        names = list(SAMPLE_FILES)
        s1 = st.button("One month of 2026", use_container_width=True)
        s2 = st.button("2,000 random CVEs", use_container_width=True)
    msg = None
    if board:
        st.session_state["src"] = ("the 2026 scoreboard", SCOREBOARD_CSV)
    for clicked, name in ((s1, names[0]), (s2, names[1])):
        if clicked:
            path = SAMPLES / SAMPLE_FILES[name]
            if path.exists():
                st.session_state["src"] = (name, path)
            else:
                msg = MISSING_SAMPLE
    source = (up.name, up) if up is not None else st.session_state.get("src")
    with go_col, st.container(key="fx-run"):
        run = st.button("Run", type="primary", disabled=source is None, use_container_width=True)
    if source:
        st.markdown(f'<p class="fx-ready">Ready: {ui.esc(source[0])}</p>', unsafe_allow_html=True)
    if msg:
        st.markdown(ui.panel(msg, error=True), unsafe_allow_html=True)
    if run:
        bar = st.progress(0)
        try:
            raw = source[1]
            df = read_upload(io.BytesIO(raw.getvalue()) if hasattr(raw, "getvalue") else raw, set(S.ids))
        except UploadError as e:
            bar.empty()
            st.markdown(ui.panel(str(e), error=True), unsafe_allow_html=True)
            st.session_state.pop("res", None)
            return
        bar.progress(25)
        t = time.perf_counter()
        res = S.score(df)
        secs = time.perf_counter() - t
        bar.progress(60)
        tab = build_table(res, S, facts, exp, df)
        bar.progress(100)
        bar.empty()
        st.session_state["res"] = dict(tab=tab, secs=secs, name=source[0], dropped=df.attrs.get("dropped_bad_ids", 0))
    if "res" not in st.session_state:
        if not msg:
            st.markdown("<div style='height:24px'></div>" + ui.panel("Choose a file or a sample, then press Run."), unsafe_allow_html=True)
        st.caption("v6 model, trained on our 2024 and 2025 test pools, loaded from saved files. Granite text scores were computed in our earlier run.")
        return
    r = st.session_state["res"]
    tab = r["tab"]
    n_all = len(tab)
    st.markdown(ui.banner(f"Scored {n_all:,} in {r['secs']:.2f} s on this laptop"), unsafe_allow_html=True)
    if r["dropped"]:
        st.markdown(ui.panel(f"{r['dropped']:,} rows without a valid CVE id were skipped.", error=True), unsafe_allow_html=True)
    n = int(st.session_state.get("fx_top_n", min(TOP, n_all)))
    n = min(n, n_all)
    head = tab.head(n)
    ex_n = int((head["Public exploit code"] == "yes").sum())
    st.markdown(ui.cards([(f"{n_all:,}", "rows scored", None), (f"{int(tab['in_top'].sum()):,}", "are in Fortres's 2026 top 500", None),
                          (f"{ex_n:,} of {len(head):,}", f"of your top {len(head):,} have public exploit code", ex_n / max(len(head), 1)), (f"{len(head):,}", "top N selected", None)]), unsafe_allow_html=True)
    st.altair_chart(dist_chart(tab, n), use_container_width=True, theme=None)
    f1, f2, f3, f4 = st.columns([3, 3, 2, 1.4], vertical_alignment="bottom")
    q = f1.text_input("Search by CVE id", placeholder="CVE-2026-")
    vend = f2.multiselect("Vendor / reporter", sorted(v for v in tab["Vendor / reporter"].unique() if v))
    expl = f3.segmented_control("Public exploit code", ["All", "yes", "no"], default="All") or "All"
    f4.number_input("Top N", min_value=1, max_value=n_all, value=min(TOP, n_all), step=50, key="fx_top_n")
    view = tab
    if q:
        view = view[view["CVE"].str.contains(q.strip(), case=False, regex=False)]
    if vend:
        view = view[view["Vendor / reporter"].isin(vend)]
    if expl != "All":
        view = view[view["Public exploit code"] == expl]
    st.markdown('<div class="fx-h">Ranked by Fortres</div>', unsafe_allow_html=True)
    if view.empty:
        st.markdown(ui.panel("No CVEs match these filters."), unsafe_allow_html=True)
    else:
        st.markdown(ui.table(view.head(25).to_dict("records")), unsafe_allow_html=True)
    show = view.drop(columns=["score", "in_top"]).head(5000).copy()
    show["Status"] = show["Reason type"].map(ui.short_label)
    show["Public exploit code"] = show["Public exploit code"].map({"yes": "Yes", "no": "No"})
    st.markdown(f'<div class="fx-h">All rows</div><div class="fx-sub">Showing {len(show):,} of {len(view):,}. Click a row to see its signals.</div>', unsafe_allow_html=True)
    left, right = st.columns([3, 2], gap="medium")
    cols = ["Rank here", "Rank in all 2026", "CVE", "Vendor / reporter", "EPSS percentile in month", "Public exploit code", "Status"]
    ev = left.dataframe(show, use_container_width=True, hide_index=True, height=480, on_select="rerun", selection_mode="single-row", row_height=40, column_order=cols,
                        column_config={"EPSS percentile in month": st.column_config.ProgressColumn("EPSS percentile", format="%.1f", min_value=0, max_value=100), "Public exploit code": st.column_config.TextColumn("Exploit code")})
    picked = ev.selection.rows if ev and ev.selection else []
    with right:
        if picked:
            row = show.iloc[picked[0]]
            st.markdown(ui.detail(row["CVE"], int(row["Rank in all 2026"]), len(S.ids), row["Reason type"], row["Reason"]), unsafe_allow_html=True)
            if row["CVE"] in S.index.index:
                st.altair_chart(signals_chart(row["CVE"], facts), use_container_width=True, theme=None)
            else:
                st.markdown(ui.panel("This CVE is not in the 2026 scoreboard, so the Granite text score is not available."), unsafe_allow_html=True)
        else:
            st.markdown(ui.panel("Select a row to see its reason and signals."), unsafe_allow_html=True)
    d1, d2, _ = st.columns([2, 2, 4])
    d1.download_button(f"Download the top {len(head):,} (cve_id only)", head[["CVE"]].rename(columns={"CVE": "cve_id"}).to_csv(index=False), file_name=f"top{len(head)}.csv", mime="text/csv")
    d2.download_button("Download the full results", tab.drop(columns=["in_top"]).to_csv(index=False), file_name="fortres_results.csv", mime="text/csv")
    st.caption("v6 model, trained on our 2024 and 2025 test pools, loaded from saved files. Granite text scores were computed in our earlier run.")
