"""src/b/new_data.py: a Nuclei template dated after the end of the CVE's snapshot month must count as absent, and invalid or
bulk dates must count as missing. A mutation check proves the test can fail."""
import pandas as pd
import pytest

from src.b import new_data as nd

POOL = pd.DataFrame({"cve_id": ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003", "CVE-2025-0004"],
                     "snapshot_month": ["2025-03", "2025-03", "2025-03", "2025-03"]})
PUB = pd.Series(pd.to_datetime(["2025-03-01"] * 4, utc=True), index=POOL["cve_id"])
TPL = pd.DataFrame({
    "cve_id": ["CVE-2025-0001", "CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003", "CVE-2025-0004"],
    "first_date": pd.to_datetime(["2025-03-10T00:00:00Z", "2025-04-02T00:00:00Z", "2025-04-01T00:00:01Z", "1970-01-01T00:00:00Z", "2025-03-05T00:00:00Z"], utc=True),
    "bulk": [False, False, False, False, True],
    "date_invalid": [False, False, False, True, False],
})


def check_as_of(fn):
    f = fn(POOL, TPL, PUB).set_index("cve_id")
    # 0001: one template inside the month (counted), one after it (absent)
    assert f.loc["CVE-2025-0001", "nuclei_has_template_by_snapshot"] == 1
    assert f.loc["CVE-2025-0001", "nuclei_n_templates_by_snapshot"] == 1
    assert f.loc["CVE-2025-0001", "nuclei_days_published_to_first_template"] == pytest.approx(9.0)
    # 0002: dated one second after the month end -> absent
    assert f.loc["CVE-2025-0002"].tolist() == [0, -1.0, 0]
    # 0003: impossible date -> missing, never early; 0004: bulk-import date -> missing
    assert f.loc["CVE-2025-0003"].tolist() == [0, -1.0, 0]
    assert f.loc["CVE-2025-0004"].tolist() == [0, -1.0, 0]


def test_features_use_only_records_dated_by_the_snapshot_month_end():
    check_as_of(nd.features_for)


def test_mutation_without_the_date_filter_is_caught(monkeypatch):
    def leaky(pool, tpl, published):
        far = pool.assign(snapshot_month="2099-12")          # pretend every snapshot ends in 2099: later records leak in
        return nd.features_for(far, tpl.assign(bulk=False, date_invalid=False), published)
    with pytest.raises(AssertionError):
        check_as_of(leaky)


def test_no_banned_column_is_a_feature():
    from src.common.schema import is_banned
    assert not any(is_banned(c) for c in nd.NEW)
