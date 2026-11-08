"""The story's site/data/* (e.g. the why-traits frequencies) is descriptive only and must never become a model input.
Only src/b/export_story.py (which writes it) may refer to it; no other module under src/ may read it."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {ROOT / "src" / "b" / "export_story.py"}
PATTERN = re.compile(r"""site[/\\]data|["']site["']\s*\)?\s*/\s*["']data["']|SITE_DATA|why_traits|story\.json""")


def test_only_export_story_touches_site_data():
    offenders = []
    for py in (ROOT / "src").rglob("*.py"):
        if py in ALLOWED:
            continue
        for i, line in enumerate(py.read_text().splitlines(), 1):
            if PATTERN.search(line):
                offenders.append(f"{py.relative_to(ROOT)}:{i}: {line.strip()}")
    assert not offenders, "site/data is descriptive only; these modules refer to it:\n" + "\n".join(offenders)


def test_pattern_catches_the_usual_spellings():
    for s in ['pd.read_csv("site/data/why_traits.csv")', 'REPO_ROOT / "site" / "data"', "SITE_DATA / 'x'", "load('story.json')"]:
        assert PATTERN.search(s), s
