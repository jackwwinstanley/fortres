"""Every target CVE (both replicas + the 2026 scoreboard) must have exactly one text_features row."""
import pandas as pd
import pytest

from src.b.phrases import strip_post_attack
from src.common.paths import OUT_DIR

TF = OUT_DIR / "text_features.parquet"
TARGETS = [OUT_DIR / f for f in ("replica_2024.parquet", "replica_2025.parquet", "scoreboard_features.parquet")]


@pytest.mark.skipif(not TF.exists() or not all(p.exists() for p in TARGETS),
                    reason="text_features.parquet or replica/scoreboard files not present")
def test_text_features_cover_every_target():
    tf = pd.read_parquet(TF, columns=["cve_id"])
    assert tf["cve_id"].is_unique
    have = set(tf["cve_id"])
    for p in TARGETS:
        ids = set(pd.read_parquet(p, columns=["cve_id"])["cve_id"])
        missing = ids - have
        assert not missing, f"{p.name}: {len(missing)} CVEs missing from text_features"


def test_strip_post_attack():
    s = "A flaw in X allows RCE. Google is aware that an exploit exists in the wild.  It has been exploited."
    out = strip_post_attack(s)
    assert "in the wild" not in out and "exploited" not in out
    assert "  " not in out
    assert strip_post_attack("Plain SQL injection in Y.") == "Plain SQL injection in Y."
