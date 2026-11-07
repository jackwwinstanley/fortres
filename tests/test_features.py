import numpy as np
import pandas as pd
import pytest

from src.features.build import (assigner_features, build_features, signal_features,
                                vendor_features, vendor_lexicon)

CUT = "2023-12-31"


def vuln():
    return pd.DataFrame({
        "cve_id": ["O1", "O2", "O3", "P1", "P2", "P3"],
        "published": ["2022-01-01", "2022-06-01", "2023-05-01", "2024-02-01", "2024-02-02", "2024-03-01"],
        "assigner": ["a@x", "a@x", "b@x", "a@x", "new@x", "b@x"],
        "description": ["old", "old", "old", "Flaw in Cisco IOS", "CiscoWorks and Acme issue", "Acme's gadget"],
    })


def kev(extra=None):
    rows = [("O1", "Cisco", "2023-06-01"), ("O3", "Acme Inc.", "2023-12-31")]
    rows += extra or []
    return pd.DataFrame(rows, columns=["cve_id", "vendor", "date_added"])


def pool():
    return pd.DataFrame({"cve_id": ["P1", "P2", "P3"], "snapshot_month": ["2024-02", "2024-02", "2024-03"],
                         "epss": [0.5, 0.1, np.nan]})


def test_kev_after_cutoff_does_not_change_history_features():
    base = build_features(pool().assign(published="x", exploitdb=0, metasploit=0, nuclei=0, poc_github=0,
                                        days_to_snapshot=1, days_to_cutoff=1), vuln(), kev(), CUT)[0]
    later = kev([("O2", "Cisco", "2024-01-01"), ("O1", "Acme", "2025-05-05")])
    changed = build_features(pool().assign(published="x", exploitdb=0, metasploit=0, nuclei=0, poc_github=0,
                                           days_to_snapshot=1, days_to_cutoff=1), vuln(), later, CUT)[0]
    pd.testing.assert_frame_equal(base, changed)


def test_unseen_assigner_gets_global_rate():
    f = assigner_features(pool(), vuln(), kev(), CUT)
    global_rate = 2 / 3  # 2 KEV rows (<= cutoff) / 3 CVEs published <= cutoff
    p2 = f.iloc[1]
    assert p2["assigner_prior_cves"] == 0 and p2["assigner_kev_count"] == 0
    assert p2["assigner_kev_rate_smooth"] == pytest.approx(global_rate)
    # seen assigner a@x: 2 prior CVEs, 1 KEV -> (1 + 20*g)/(2+20)
    assert f.iloc[0]["assigner_kev_rate_smooth"] == pytest.approx((1 + 20 * global_rate) / 22)


def test_rank_in_month_within_month_only():
    df = pd.DataFrame({"snapshot_month": ["m1", "m1", "m2", "m2", "m2"], "epss": [0.1, 0.9, 0.5, 0.2, np.nan],
                       "exploitdb": 0, "metasploit": 0, "nuclei": 0, "poc_github": 0,
                       "days_to_snapshot": 1, "days_to_cutoff": 1})
    r = signal_features(df)["epss_rank_in_month"].tolist()
    assert r[:2] == [0.5, 1.0]            # m1 ranks ignore m2 values
    assert r[2:4] == [1.0, 0.5] and r[4] == 0.0   # missing -> 0
    assert signal_features(df)["epss_missing"].tolist() == [0, 0, 0, 0, 1]


def test_vendor_matching_is_whole_word():
    lex, dropped = vendor_lexicon(kev(), CUT)
    assert set(lex["vendor"]) == {"cisco", "acme"}  # "Acme Inc." -> "acme"
    f = vendor_features(vuln().set_index("cve_id")["description"], lex)
    assert f.loc["P1", "n_vendors_mentioned"] == 1          # "Cisco IOS"
    assert f.loc["P2", "n_vendors_mentioned"] == 1          # "CiscoWorks" must NOT match cisco; Acme does
    assert f.loc["P3", "n_vendors_mentioned"] == 1          # "Acme's" matches acme
    assert f.loc["P2", "vendor_kev_count_max"] == pytest.approx(np.log1p(1))


def test_short_and_ambiguous_vendors_dropped():
    k = kev([("P1", "SAP", "2023-01-01"), ("P2", "Linux", "2023-01-01")])
    lex, dropped = vendor_lexicon(k, CUT)
    assert "sap" not in set(lex["vendor"]) and "linux" not in set(lex["vendor"])
    assert {"sap", "linux"} <= set(dropped["vendor"])


def test_build_is_deterministic():
    p = pool().assign(published="x", exploitdb=0, metasploit=0, nuclei=0, poc_github=0, days_to_snapshot=1,
                      days_to_cutoff=1)
    a = build_features(p, vuln(), kev(), CUT)[0]
    b = build_features(p, vuln(), kev(), CUT)[0]
    pd.testing.assert_frame_equal(a, b)


def test_share_features_guard_zero_denominators_and_are_scale_free():
    from src.features.build import assigner_features, vendor_features, vendor_lexicon
    # no KEV at all before the cutoff: every share must be 0 (not NaN or inf)
    empty_kev = pd.DataFrame({"cve_id": [], "vendor": [], "date_added": []})
    a = assigner_features(pool(), vuln(), empty_kev, CUT)
    assert a[["assigner_kev_share", "assigner_kev_12m_share"]].eq(0.0).all().all() and a["assigner_cve_share"].between(0, 1).all()
    lex, _ = vendor_lexicon(empty_kev, CUT)
    v = vendor_features(vuln().set_index("cve_id")["description"], lex, 0, 0)
    assert v[["vendor_kev_share_max", "vendor_kev_12m_share_max"]].eq(0.0).all().all()
    # normal case: a@x has 1 of the 2 KEV entries added by the cutoff; CVEs published by the cutoff: 3 (O1, O2, O3)
    f = assigner_features(pool(), vuln(), kev(), CUT)
    assert f.iloc[0]["assigner_kev_share"] == pytest.approx(1 / 2)
    assert f.iloc[0]["assigner_cve_share"] == pytest.approx(2 / 3)
    assert f.iloc[1]["assigner_cve_share"] == 0.0           # unseen assigner
    lex, _ = vendor_lexicon(kev(), CUT)
    vf = vendor_features(vuln().set_index("cve_id")["description"], lex, 2, 1)
    assert vf.loc["P1", "vendor_kev_share_max"] == pytest.approx(1 / 2)          # "Cisco IOS": cisco has 1 of 2 KEV entries
