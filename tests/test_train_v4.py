import numpy as np
import pandas as pd
import pytest

from scripts.check_top500 import check
from src.common.paths import OUT_DIR
from src.common.schema import V4_FEATURES
from src.models.train_v4 import FEATURES_V4, bag, kev_events


def test_bag_rank_normalises_each_seed_then_averages():
    a = np.array([0.001, 0.002, 0.9])          # different scales per seed must not matter
    b = np.array([10.0, 20.0, 5.0])
    out = bag([a, b])
    assert out.tolist() == [(1 / 3 + 2 / 3) / 2, (2 / 3 + 1.0) / 2, (1.0 + 1 / 3) / 2]
    assert (bag([a, b]) == bag([a * 1000, b / 7])).all()      # invariant to monotone rescaling of any seed


def test_kev_events_group_positives_by_date_and_vendor():
    meta = pd.DataFrame({"cve_id": ["A", "B", "C", "D", "N1"], "label": [1, 1, 1, 1, 0]})
    kev = pd.DataFrame({"vendor": ["Ivanti", "Ivanti", "Ivanti", "Cisco"],
                        "date_added": ["2025-03-10", "2025-03-10", "2025-04-01", "2025-03-10"]},
                       index=pd.Index(["A", "B", "C", "D"], name="cve_id"))
    ev = kev_events(meta, kev)
    assert ev[0] == ev[1] and len({ev[0], ev[2], ev[3]}) == 3 and ev[4] == -1


@pytest.mark.skipif(not (OUT_DIR / "top500_v4.csv").exists(), reason="top500_v4.csv not produced yet")
def test_top500_v4_format_and_contributions():
    assert check(OUT_DIR / "top500_v4.csv") == []
    ids = pd.read_csv(OUT_DIR / "top500_v4.csv")["cve_id"].tolist()
    contrib = pd.read_parquet(OUT_DIR / "v4_top500_contrib.parquet")
    assert list(contrib.columns) == ["cve_id", *FEATURES_V4] and FEATURES_V4 == V4_FEATURES
    assert contrib["cve_id"].tolist() == ids
