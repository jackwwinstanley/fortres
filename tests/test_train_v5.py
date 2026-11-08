import numpy as np
import pandas as pd
import pytest

from scripts.check_top500 import check
from src.common.paths import OUT_DIR, SCOREBOARD_CSV
from src.common.schema import SHARE_FEATURES
from src.models.train_v5 import FEATURES_V5, bootstrap_p


def test_bootstrap_p_detects_a_real_difference_and_not_a_null_one():
    rng = np.random.default_rng(0)
    real = rng.normal(22, 1.5, 30)
    null = rng.normal(19, 1.5, 30)
    d, (lo, hi), p = bootstrap_p(real, null, n=2000, seed=1)
    assert d == pytest.approx(real.mean() - null.mean()) and lo < d < hi and p < 0.01
    same = rng.normal(20, 1.5, 30)
    other = rng.normal(20, 1.5, 30)
    assert bootstrap_p(same, other, n=2000, seed=1)[2] > 0.05
    assert bootstrap_p(real, null, n=500, seed=3) == bootstrap_p(real, null, n=500, seed=3)    # reproducible


def test_share_columns_exist_in_feature_files_and_are_proper_shares():
    for name in ("replica_2024", "replica_2025", "scoreboard"):
        p = OUT_DIR / f"features_{name}.parquet"
        if not p.exists():
            pytest.skip("feature files not present")
        f = pd.read_parquet(p)
        assert set(SHARE_FEATURES) <= set(f.columns)
        assert f[SHARE_FEATURES].notna().all().all() and f[SHARE_FEATURES].ge(0).all().all() and f[SHARE_FEATURES].le(1).all().all()


@pytest.mark.skipif(not (OUT_DIR / "top500_v5.csv").exists(), reason="top500_v5.csv not produced yet")
@pytest.mark.skipif(not SCOREBOARD_CSV.exists(), reason="needs the untracked datathon data (data/scoreboard_2026.csv) to validate the IDs")
def test_top500_v5_format_and_contributions():
    assert check(OUT_DIR / "top500_v5.csv") == []
    ids = pd.read_csv(OUT_DIR / "top500_v5.csv")["cve_id"].tolist()
    contrib = pd.read_parquet(OUT_DIR / "v5_top500_contrib.parquet")
    assert list(contrib.columns) == ["cve_id", *FEATURES_V5] and contrib["cve_id"].tolist() == ids
