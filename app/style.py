"""Fortres look for the Streamlit app: design tokens, CSS and small HTML helpers. Visual only; no values are computed here."""
import html
import json
from pathlib import Path

ASSETS = Path(__file__).parent / "assets"
FAVICON = ASSETS / "fortres.svg"
BG, PANEL, LINE, TEXT, MUTED, ACCENT, ACCENT2, GREEN, CORAL = "#080c12", "#0e141c", "#1c2632", "#e8edf3", "#8d9aaa", "#4589ff", "#a6c8ff", "#42be65", "#ff7b6b"
SANS = "'IBM Plex Sans', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif"
MONO = "'IBM Plex Mono', ui-monospace, Menlo, monospace"
EASE = "cubic-bezier(0.23, 1, 0.32, 1)"
MARK = ('<svg width="19" height="24" viewBox="400 180 610 790" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="44" stroke-linejoin="miter" stroke-miterlimit="8">'
        '<path d="M450 293L528 266L532 330L608 310L610 238L703 201L797 238L798 310L876 330L880 266L958 293L958 412L703 362L452 412Z"/>'
        '<path d="M487 450L703 398L919 450L884 492L884 742L703 840L522 742L522 492Z"/><path d="M507 606L425 655L425 798L703 948L982 798L982 655L900 606"/></g></svg>')

CSS = f"""<style id="fx-css">
/* chrome */
#MainMenu, footer, [data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"],
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], [data-testid="stAppDeployButton"] {{ display: none !important; }}
.stApp {{ background: {BG}; font-variant-numeric: tabular-nums; }}
.block-container {{ max-width: 1344px !important; padding: 24px 32px 48px !important; }}
h1, h2, h3, h4 {{ font-weight: 500 !important; letter-spacing: -0.01em; }}
hr {{ border-color: {LINE}; }}

/* top bar */
.fx-brand {{ display: flex; align-items: center; gap: 10px; color: {TEXT}; font-size: 20px; font-weight: 500; height: 40px; letter-spacing: -0.01em; }}
.fx-meta {{ color: {MUTED}; font-size: 13px; text-align: right; line-height: 40px; font-family: {MONO}; }}
.st-key-fx-tabs [data-testid="stButtonGroup"] button {{ border-radius: 999px; font-size: 14px; }}
.fx-rule {{ border: 0; border-top: 1px solid {LINE}; margin: 12px 0 24px; }}

/* buttons */
.stButton > button, .stDownloadButton > button {{ border-radius: 999px; border: 1px solid {LINE}; background: {PANEL}; color: {TEXT}; font-weight: 400; min-height: 40px;
  transition: transform 160ms {EASE}, background-color 160ms ease, border-color 160ms ease; }}
.stButton > button:active, .stDownloadButton > button:active {{ transform: scale(0.97); }}
@media (hover: hover) and (pointer: fine) {{
  .stButton > button:hover, .stDownloadButton > button:hover {{ border-color: {MUTED}; color: {TEXT}; background: {PANEL}; }}
}}
.st-key-fx-run .stButton > button {{ background: {TEXT}; color: {BG}; border-color: {TEXT}; font-weight: 500; font-size: 18px; height: 136px; border-radius: 20px; }}
.st-key-fx-run .stButton > button p {{ color: {BG}; font-size: 18px; font-weight: 500; }}
.st-key-fx-run .stButton > button:disabled {{ background: {PANEL}; border-color: {LINE}; }}
.st-key-fx-run .stButton > button:disabled p {{ color: {MUTED}; }}
@media (hover: hover) and (pointer: fine) {{
  .st-key-fx-run .stButton > button:hover:enabled {{ background: {ACCENT2}; border-color: {ACCENT2}; color: {BG}; }}
}}
.st-key-fx-sources {{ gap: 8px; }}
.st-key-fx-sources .stButton > button {{ min-height: 40px; width: 100%; font-size: 14px; }}

/* upload */
[data-testid="stFileUploader"] label p {{ font-size: 16px; color: {TEXT}; }}
[data-testid="stFileUploaderDropzone"] {{ background: {PANEL}; border: 1px dashed {MUTED}; border-radius: 6px; min-height: 104px; }}
.fx-ready {{ color: {MUTED}; font-size: 14px; font-family: {MONO}; margin: 4px 0 0; }}

/* run feedback */
[data-testid="stProgress"] > div > div {{ height: 2px; }}
.fx-banner {{ font-family: {MONO}; font-size: 18px; color: {GREEN}; margin: 24px 0 16px; }}

/* cards */
.fx-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
.fx-card {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 6px; padding: 24px; }}
.fx-num {{ font-family: {MONO}; font-size: 44px; line-height: 1.1; font-weight: 500; color: {TEXT}; }}
.fx-cap {{ color: {MUTED}; font-size: 14px; margin-top: 8px; line-height: 1.4; }}
.fx-track {{ height: 2px; background: {LINE}; margin-top: 16px; }}
.fx-fill {{ height: 2px; background: {ACCENT}; transform-origin: left; }}

/* section titles */
.fx-h {{ font-size: 18px; font-weight: 500; margin: 32px 0 12px; color: {TEXT}; }}
.fx-sub {{ color: {MUTED}; font-size: 14px; margin: -8px 0 12px; }}

/* inputs */
[data-testid="stTextInput"] input, [data-baseweb="select"] > div {{ background: {PANEL}; }}
[data-testid="stWidgetLabel"] p {{ color: {MUTED}; font-size: 14px; }}

/* hero table */
.fx-tablewrap {{ border: 1px solid {LINE}; border-radius: 6px; background: {PANEL}; max-height: 640px; overflow-y: auto; overflow-x: hidden; }}
table.fx-table {{ border-collapse: separate; border-spacing: 0; width: 100%; font-size: 14px; margin: 0; }}
.fx-table th, .fx-table td {{ border: 0 !important; }}
.fx-table th {{ position: sticky; top: 0; background: {PANEL}; color: {MUTED}; font-weight: 400; font-size: 13px; text-align: left; padding: 12px; box-shadow: inset 0 -1px 0 {LINE}; line-height: 1.3; z-index: 1; }}
.fx-table td {{ padding: 16px 12px; box-shadow: inset 0 -1px 0 {LINE}; vertical-align: top; color: {TEXT}; line-height: 1.45; }}
.fx-table tr:last-child td {{ box-shadow: none; }}
@media (hover: hover) and (pointer: fine) {{ .fx-table tbody tr {{ transition: background-color 120ms ease; }} .fx-table tbody tr:hover {{ background: {BG}; }} }}
.fx-table .m {{ font-family: {MONO}; white-space: nowrap; }}
.fx-table .d {{ color: {MUTED}; }}
.fx-table .r {{ font-size: 14px; color: {TEXT}; width: 42%; }}
.fx-epss {{ font-family: {MONO}; font-size: 14px; white-space: nowrap; }}
.fx-bar {{ width: 64px; height: 4px; background: {LINE}; border-radius: 2px; margin-top: 8px; }}
.fx-bar i {{ display: block; height: 4px; background: {ACCENT}; border-radius: 2px; transform-origin: left; }}

/* badges */
.fx-badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 13px; white-space: nowrap; border: 1px solid {LINE}; color: {MUTED}; }}
.fx-badge.ok {{ color: {GREEN}; border-color: {GREEN}; }}
.fx-badge.tpl {{ color: {ACCENT2}; border-color: {ACCENT}; }}

/* detail */
.fx-detail {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 6px; padding: 24px; }}
.fx-cve {{ font-family: {MONO}; font-size: 30px; font-weight: 500; color: {TEXT}; line-height: 1.1; }}
.fx-rank {{ font-family: {MONO}; color: {MUTED}; font-size: 15px; margin: 8px 0 16px; }}
.fx-quote {{ border-left: 2px solid {ACCENT}; padding: 0 0 0 16px; margin: 12px 0 0; color: {TEXT}; font-size: 16px; line-height: 1.5; }}

/* states */
.fx-panel {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 6px; padding: 24px; color: {MUTED}; font-size: 16px; }}
.fx-panel.err {{ border-color: {CORAL}; color: {CORAL}; }}
.fx-foot {{ color: {MUTED}; font-size: 13px; border-top: 1px solid {LINE}; margin-top: 48px; padding-top: 16px; }}
#vg-tooltip-element {{ font-family: {MONO} !important; background: {PANEL} !important; color: {TEXT} !important; border: 1px solid {LINE} !important; border-radius: 6px !important; box-shadow: none !important; }}
#vg-tooltip-element td.key {{ color: {MUTED} !important; }}
@media (prefers-reduced-motion: reduce) {{ .stButton > button, .stDownloadButton > button, .fx-table tbody tr {{ transition: none; }} .stButton > button:active, .stDownloadButton > button:active {{ transform: none; }} }}
@media (max-width: 1500px) {{ .fx-num {{ font-size: 36px; }} .fx-card {{ padding: 16px; }} }}
</style>"""


def esc(x) -> str:
    return html.escape(str(x))


def brand() -> str:
    return f'<div class="fx-brand">{MARK}<span>fortres</span></div>'


def meta(text: str) -> str:
    return f'<div class="fx-meta">{esc(text)}</div>'


def cards(items: list[tuple[str, str, float | None]]) -> str:
    """items: (big number, label, optional 0..1 share for the thin accent bar)."""
    out = []
    for big, cap, share in items:
        bar = "" if share is None else f'<div class="fx-track"><div class="fx-fill" style="transform:scaleX({max(0.0, min(1.0, share)):.4f})"></div></div>'
        out.append(f'<div class="fx-card"><div class="fx-num">{esc(big)}</div><div class="fx-cap">{esc(cap)}</div>{bar}</div>')
    return f'<div class="fx-grid">{"".join(out)}</div>'


def banner(text: str) -> str:
    return f'<p class="fx-banner">{esc(text)}</p>'


def panel(text: str, error: bool = False) -> str:
    return f'<div class="fx-panel{" err" if error else ""}">{esc(text)}</div>'


SHORT = {"Checked by Granite Guardian": "Guardian-checked", "Template reason": "Template"}


def short_label(label: str) -> str:
    return SHORT.get(label, "Facts only")


def badge(label: str) -> str:
    s = short_label(label)
    cls = "ok" if s == "Guardian-checked" else "tpl" if s == "Template" else ""
    return f'<span class="fx-badge {cls}">{esc(s)}</span>'


def table(rows: list[dict]) -> str:
    """The hero table: rows carry the same values as the full table."""
    body = []
    for r in rows:
        pct = float(r["EPSS percentile in month"])
        body.append(f'<tr><td class="m">{r["Rank here"]:,}</td><td class="m d">{r["Rank in all 2026"]:,}</td><td class="m">{esc(r["CVE"])}</td><td>{esc(r["What it lets an attacker do"])}</td>'
                    f'<td class="d">{esc(r["Vendor / reporter"])}</td><td><div class="fx-epss">{pct:.1f}</div><div class="fx-bar"><i style="transform:scaleX({pct / 100:.4f})"></i></div></td>'
                    f'<td>{"Yes" if r["Public exploit code"] == "yes" else "No"}</td><td class="r">{esc(r["Reason"])}</td><td>{badge(r["Reason type"])}</td></tr>')
    head = "".join(f"<th>{h}</th>" for h in ("Rank here", "Rank in all 2026", "CVE", "What it lets an attacker do", "Vendor / reporter", "EPSS percentile", "Exploit code", "Reason", "Status"))
    return f'<div class="fx-tablewrap"><table class="fx-table"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def detail(cve: str, rank: int, total: int, label: str, reason: str) -> str:
    return (f'<div class="fx-detail"><div class="fx-cve">{esc(cve)}</div><div class="fx-rank">{rank:,} of {total:,}</div>{badge(label)}'
            f'<blockquote class="fx-quote">{esc(reason)}</blockquote></div>')


def footer(out_dir: Path) -> str:
    base = "fortres · IBM Before the Breach · Granite and Granite Guardian run locally"
    p = out_dir / "watsonx_gov_summary.json"
    if p.exists():
        n = json.loads(p.read_text()).get("rows", {}).get("n")
        base += " · explanations scored on IBM watsonx.governance" if n == 500 else f" · a sample of {n} explanations scored on IBM watsonx.governance"
    return f'<div class="fx-foot">{esc(base)}</div>'
