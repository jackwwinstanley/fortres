"""Repo-relative path constants. Import these instead of hard-coding paths."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
OUT_DIR = REPO_ROOT / "outputs"
SCOREBOARD_CSV = DATA_DIR / "scoreboard_2026.csv"


def missing_data_message(path) -> str:
    """The one-line message for a missing competition-data file (data/ is not in the repository)."""
    try:
        rel = Path(path).resolve().relative_to(REPO_ROOT)
    except ValueError:
        rel = Path(path)
    return f"needs {rel.as_posix()} (competition data, not in the repo): put the datathon CSVs in ./data"


def require_data(*paths) -> None:
    """Exit with a clear message (status 2) instead of a traceback when a competition-data file is missing."""
    import sys
    for p in paths:
        if not Path(p).exists():
            print(missing_data_message(p), file=sys.stderr)
            sys.exit(2)
