import pandas as pd
import pytest

from src.replicas import build_replica


@pytest.fixture
def synth(tmp_path):
    vuln = pd.DataFrame({
        "cve_id": ["A", "B", "C", "D", "E", "F", "G", "H"],
        "published": ["2024-02-10", "2024-03-05", "2024-03-06", "2024-04-01",
                      "2024-06-10", "2024-05-02", "2024-10-05", "2024-07-07"],
    })
    kev = pd.DataFrame({
        "cve_id": ["A", "B", "C", "E", "H"],
        "date_added": ["2024-02-20", "2024-05-01", "2024-12-01", "2024-01-15", "2024-11-04"],
    })
    sig = pd.DataFrame({
        "month": ["2024-02", "2024-03", "2024-04", "2024-03", "2024-06", "2024-05", "2024-07", "2024-10"],
        "cve_id": ["A", "B", "B", "C", "E", "F", "H", "G"],
        "epss": [0.5, 0.1, 0.9, 0.2, 0.3, 0.4, 0.6, 0.7],
        "in_kev": [0, 0, 0, 0, 0, 1, 0, 0],
        "exploitdb": [0, 1, 1, 0, 0, 0, 0, 0],
        "metasploit": 0, "nuclei": 0, "poc_github": 0,
    })
    paths = {}
    for name, df in [("vuln", vuln), ("kev", kev), ("sig", sig)]:
        paths[name] = tmp_path / f"{name}.csv"
        df.to_csv(paths[name], index=False)
    df, stats = build_replica(2024, paths["vuln"], paths["kev"], paths["sig"])
    return df.set_index("cve_id"), stats


def test_kev_before_snapshot_end_excluded(synth):
    df, stats = synth
    assert "A" not in df.index  # added 2024-02-20, snapshot month ends 2024-02-29


def test_added_after_month_end_before_cutoff_is_positive(synth):
    df, _ = synth
    assert df.loc["B", "label"] == 1
    assert df.loc["B", "epss"] == pytest.approx(0.1)  # joined on the snapshot month, not April's 0.9
    assert df.loc["H", "label"] == 1  # exactly Nov 4 counts


def test_added_after_cutoff_is_negative(synth):
    df, _ = synth
    assert df.loc["C", "label"] == 0


def test_no_signal_row_gives_null_epss_and_zero_flags(synth):
    df, _ = synth
    row = df.loc["D"]
    assert pd.isna(row["epss"])
    assert row[["exploitdb", "metasploit", "nuclei", "poc_github"]].sum() == 0
    assert row["label"] == 0


def test_kev_date_before_published_excluded(synth):
    df, stats = synth
    assert "E" not in df.index  # added 2024-01-15, published 2024-06-10
    assert stats["dropped_date_only"] >= 2  # A and E


def test_signal_kev_flag_excluded_and_pool_window(synth):
    df, stats = synth
    assert "F" not in df.index          # in_kev=1 in signals
    assert stats["dropped_signal_only"] == 1
    assert "G" not in df.index          # published after Sep 30
    assert set(df.index) == {"B", "C", "D", "H"}


def test_days_columns(synth):
    df, _ = synth
    assert df.loc["B", "days_to_snapshot"] == 26   # Mar 5 -> Mar 31
    assert df.loc["B", "days_to_cutoff"] == 218    # Mar 31 -> Nov 4 (2024)
