import pandas as pd

from src.b import runlog


def test_results_parses_both_formats(tmp_path):
    p = tmp_path / "runlog.csv"
    pd.DataFrame([
        dict(timestamp="t1", version="baseline_epss", replica="2024", k=198, hits=3, baseline_exploit_epss_hits=6,
             notes="pool=1 boot90=[1,7]"),
        dict(timestamp="t1", version="v2_lgbm", replica="train2024_test2025", k=243, hits=15,
             baseline_exploit_epss_hits=13, notes="boot90=[9-21]"),
        dict(timestamp="t1", version="v2_lgbm", replica="train2025_test2024", k=198, hits=8,
             baseline_exploit_epss_hits=6, notes="boot90=[4-13]"),
        dict(timestamp="t1", version="v2_lgbm", replica="lomo2024", k=198, hits=9,
             baseline_exploit_epss_hits=6, notes="optimistic"),
    ]).to_csv(p, index=False)
    r = runlog.results(p)
    assert set(r["test_year"]) == {2024, 2025}
    assert len(r) == 3  # lomo row skipped
    v2 = r[r["version"] == "v2_lgbm"].set_index("test_year")
    assert v2.loc[2025, "ci_lo"] == 9 and v2.loc[2025, "ci_hi"] == 21
    assert runlog.latest_model(r) == "v2_lgbm"
    assert runlog.model_name("baseline_epss") == "Highest EPSS"


def test_leakage_columns_are_all_banned():
    from src.b.leakage import HONEST
    from src.common.schema import check_feature_list
    assert check_feature_list(HONEST) == []
    assert not any(c.startswith("leak_") for c in HONEST)
