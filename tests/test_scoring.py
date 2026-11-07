import pandas as pd

from src.common.scoring import baselines, bootstrap_interval, hits_at_k, k_for_pool


def frame():
    return pd.DataFrame({
        "cve_id": [f"CVE-2026-{i:04d}" for i in range(10)],
        "epss": [0.9, 0.8, 0.7, 0.5, 0.5, 0.5, 0.1, 0.1, 0.0, 0.0],
        "exploitdb": [0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        "metasploit": 0, "nuclei": 0, "poc_github": 0,
        "cvss": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        "label": [1, 0, 0, 0, 1, 0, 0, 0, 0, 1],
    })


def test_k_rounding():
    assert k_for_pool(72670) == 500
    assert k_for_pool(36335) == 250
    assert k_for_pool(58755) == round(500 * 58755 / 72670)
    assert k_for_pool(1) == 1  # never zero


def test_tie_break_by_cve_id():
    df = frame()
    # three-way tie at 0.5 for ids 3,4,5; k=4 takes the top 3 plus lowest cve_id of the tie (id 3)
    assert hits_at_k(df, "epss", k=4) == 1  # label 1 only at id 0
    assert hits_at_k(df, "epss", k=5) == 2  # adds id 4 (label 1)
    # shuffling input rows must not change the result
    assert hits_at_k(df.sample(frac=1, random_state=1), "epss", k=5) == 2


def test_baselines():
    b = baselines(frame(), cvss_col="cvss", k=2)
    assert b["cvss"] == 1      # ids 9, 8 -> label 1 at 9
    assert b["epss"] == 1      # ids 0, 1
    assert b["exploit_epss"] == 1  # id 5 (exploit flag, label 0) then id 0 (label 1)
    assert "cvss" not in baselines(frame(), k=2)


def test_bootstrap_reproducible():
    df = frame()
    a = bootstrap_interval(df, "epss", k=3, n=200, seed=7)
    b = bootstrap_interval(df, "epss", k=3, n=200, seed=7)
    assert a == b and a[0] <= a[1]
