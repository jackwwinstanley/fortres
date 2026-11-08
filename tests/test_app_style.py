"""The app's visual layer: the custom CSS is injected and both pages load without exceptions."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / "app" / "dashboard.py")
need = pytest.mark.skipif(not (ROOT / "models" / "v6" / "manifest.json").exists(), reason="saved models not present")


@need
def test_rank_page_loads_and_css_is_injected():
    at = AppTest.from_file(APP, default_timeout=120).run()
    assert len(at.exception) == 0
    assert any('id="fx-css"' in m.value for m in at.markdown)


@need
def test_overview_page_loads():
    at = AppTest.from_file(APP, default_timeout=120)
    at.session_state["fx_tab"] = "Overview"
    at.run()
    assert len(at.exception) == 0
    assert at.tabs


def test_style_uses_only_the_tokens():
    import re
    css = (ROOT / "app" / "style.py").read_text()
    allowed = {"#080c12", "#0e141c", "#1c2632", "#e8edf3", "#8d9aaa", "#4589ff", "#a6c8ff", "#42be65", "#ff7b6b"}
    assert {c.lower() for c in re.findall(r"#[0-9a-fA-F]{6}\\b", css)} <= allowed
    for bad in ("transition: all", "fonts.googleapis", "linear-gradient", "backdrop-filter"):
        assert bad not in css
