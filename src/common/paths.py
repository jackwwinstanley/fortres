"""Repo-relative path constants. Import these instead of hard-coding paths."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
OUT_DIR = REPO_ROOT / "outputs"
SCOREBOARD_CSV = DATA_DIR / "scoreboard_2026.csv"
