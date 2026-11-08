"""The tables behind docs/findings.md: the arithmetic on small cases, and the committed tables against the published results."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import discovery_tables as dt  # noqa: E402

OUT = dt.OUT


@pytest.mark.parametrize("score,band", [(9.8, "Critical"), (9.0, "Critical"), (7.0, "High"), (6.9, "Medium"), (4.0, "Medium"),
                                        (3.9, "Low"), (0, "None or unscored"), (float("nan"), "None or unscored")])
def test_severity_bands(score, band):
    assert dt.severity(score) == band


def test_kev_severity_table_counts_by_year_and_ignores_other_years():
    kev = pd.DataFrame({"cve_id": list("abcd"), "date_added": ["2021-01-01", "2021-06-01", "2025-12-31", "2020-05-05"]})
    vul = pd.DataFrame({"cve_id": list("abcd"), "cvss3_score": [5.0, 9.5, 6.0, 5.0]})
    t = dt.kev_severity_table(kev, vul).set_index("year")
    assert t.loc[2021, "entries"] == 2 and t.loc[2021, "Medium"] == 1 and t.loc["total", "Medium"] == 2 and t.loc["total", "entries"] == 3


def test_depth_to_match():
    assert dt.depth_to_match([0, 1, 0, 1], 2) == 4
    assert dt.depth_to_match([1, 0], 2) is None


def test_events_group_by_date_and_vendor():
    p = pd.DataFrame({"cve_id": list("abc"), "replica": [2025, 2025, 2024], "date_added": ["d1", "d1", "d1"], "vendor": ["X", "X", "Y"]})
    t = dt.events_table(p)
    assert len(t) == 2 and t["n_cves"].sum() == 3


def test_epss_jump_factor():
    r = pd.DataFrame({"pool": ["2024", "2025", "2026", "2026"], "snapshot_month": ["2024-01", "2025-01", "2026-01", "2026-07"], "epss": [1.0, 1.0, 1.0, 6.0]})
    assert dt.epss_jump(r)[1] == 6.0


need = pytest.mark.skipif(not (OUT / "discovery_workload.csv").exists(), reason="discovery tables not present")


@need
def test_workload_table_matches_the_published_results_and_labels():
    w = pd.read_csv(OUT / "discovery_workload.csv")
    p = w[w["test_pool"] == "pooled"].set_index("method")
    assert p.loc["fortres (v6)", "hits_at_k"] == 27 and p.loc["fortres (v6)", "k"] == 441
    assert p.loc["usual rule (public code, then EPSS)", "hits_at_k"] == 19
    t = w[w["test_pool"] != "pooled"].groupby("method")["fixes_to_match"].sum()
    assert (t.reindex(p.index) == p["fixes_to_match"]).all()


@need
def test_events_table_covers_the_75_and_the_ivanti_event():
    e = pd.read_csv(OUT / "discovery_events.csv")
    assert e["n_cves"].sum() == 75
    assert "CVE-2024-13159;CVE-2024-13160;CVE-2024-13161" in set(e["cves"])


@need
def test_kev_severity_total_is_the_sum_of_the_years():
    t = pd.read_csv(OUT / "discovery_kev_severity.csv")
    years, total = t[t["year"] != "total"], t[t["year"] == "total"].iloc[0]
    assert np.all([years[c].sum() == total[c] for c in dt.SEVERITIES + ["entries"]])
