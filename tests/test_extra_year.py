"""The 2023 back-test: a record dated after the snapshot-month end never counts (with a mutation check), and the committed
results are internally consistent."""
import numpy as np
import pandas as pd
import pytest

from src.b import extra_year as ey
from src.common.paths import OUT_DIR
from src.common.scoring import k_for_pool

POOL = pd.DataFrame({"cve_id": ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"], "snapshot_month": ["2023-03", "2023-03", "2023-04"]})
RECORDS = pd.DataFrame({"cve_id": ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0002", "CVE-2023-0003"],
                        "date": pd.to_datetime(["2023-03-31T23:59:59Z", "2023-04-01T00:00:00Z", "2023-05-01T00:00:00Z", "2023-04-30T12:00:00Z"], utc=True)})


def check(fn):
    assert fn(POOL, RECORDS).tolist() == [1, 0, 1]


def test_records_after_the_snapshot_month_end_do_not_count():
    check(ey.dated_flag)


def test_mutation_ignoring_the_date_is_caught():
    def leaky(pool, records):
        return pool["cve_id"].isin(set(records["cve_id"])).astype(int).to_numpy()
    with pytest.raises(AssertionError):
        check(leaky)


@pytest.mark.skipif(not (OUT_DIR / "extra_year_eval.csv").exists(), reason="no result yet")
def test_eval_table_is_consistent():
    e = pd.read_csv(OUT_DIR / "extra_year_eval.csv").set_index("method")
    v = e.loc["v6"]
    assert v["k"] == k_for_pool(int(v["pool"]))
    assert set(e.index) == {"v6", "v5", "simple rule", "EPSS alone", "severity (CVSS)", "random (expected)"}
    for m in ("v5", "simple rule", "EPSS alone", "severity (CVSS)"):
        assert e.loc[m, "v6_minus_this"] == v["hits"] - e.loc[m, "hits"]
    assert np.isclose(e.loc["random (expected)", "hits"], v["k"] * v["positives"] / v["pool"], atol=0.01)
