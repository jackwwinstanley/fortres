import numpy as np
import pandas as pd
import pytest

from src.common.paths import OUT_DIR
from src.common.schema import (ALLOWED_FEATURES, PSI_REPLACED, SHARE_FEATURES, TEXT_FEATURES, V1_FEATURES, V2_FEATURES, V4_FEATURES,
                               V5_FEATURES, V5_TRANSFORMS)
from src.features import drift_fix as dfx


def test_psi_identical_is_zero_and_shift_is_large():
    rng = np.random.default_rng(0)
    a = rng.normal(size=5000)
    assert dfx.psi_binned(a, rng.normal(size=5000)) < 0.02
    assert dfx.psi_binned(a, rng.normal(loc=1.5, size=5000)) > dfx.PSI_LARGE


def test_psi_zero_inflated_and_binary_columns_are_not_collapsed():
    rng = np.random.default_rng(1)
    a = np.where(rng.random(5000) < 0.8, 0.0, rng.random(5000) * 5)
    b = np.where(rng.random(5000) < 0.3, 0.0, rng.random(5000) * 5)   # far fewer zeros
    assert dfx.psi_binned(a, b) > dfx.PSI_LARGE
    flags_a, flags_b = (rng.random(5000) < 0.02).astype(float), (rng.random(5000) < 0.2).astype(float)
    assert dfx.psi_binned(flags_a, flags_b) > dfx.PSI_LARGE


def test_to_v4_drops_raw_epss_and_ranks_within_the_pool():
    X = pd.DataFrame({"epss": [0.1, 0.2, 0.3, 0.4], "days_to_cutoff": [10, 20, 20, 40], "n_flags": [0, 1, 0, 2]})
    out = dfx.to_v4(X, ["days_to_cutoff"])
    assert "epss" not in out and "days_to_cutoff" not in out
    assert out["days_to_cutoff_pctrank"].tolist() == [0.25, 0.625, 0.625, 1.0]   # average ties, percentile of the pool
    assert out["n_flags"].tolist() == [0, 1, 0, 2]                                # untouched
    # a second pool is ranked on its own, not against the first
    other = dfx.to_v4(pd.DataFrame({"epss": [0.5], "days_to_cutoff": [999], "n_flags": [0]}), ["days_to_cutoff"])
    assert other["days_to_cutoff_pctrank"].tolist() == [1.0]


def test_schema_v4_legacy_definition():
    assert "epss" not in V4_FEATURES
    assert V4_FEATURES == dfx.v4_feature_names(PSI_REPLACED)
    assert set(V1_FEATURES) <= set(V2_FEATURES) and "epss" in V1_FEATURES      # legacy sets stay reproducible
    assert not set(PSI_REPLACED) & set(V4_FEATURES)
    assert all(dfx.rank_name(f) in V4_FEATURES for f in PSI_REPLACED)


def test_schema_v5_definition():
    assert ALLOWED_FEATURES == V5_FEATURES and "epss" not in V5_FEATURES
    assert "epss_rank_in_month" in V5_FEATURES and "epss_missing" in V5_FEATURES
    assert set(V5_TRANSFORMS) == set(dfx.SENSITIVE)
    assert set(TEXT_FEATURES) <= set(V5_FEATURES) and len(V5_FEATURES) == len(set(V5_FEATURES)) == 33
    for f, col in V5_TRANSFORMS.items():
        assert col in V5_FEATURES and (col == f or col == dfx.rank_name(f) or col == dfx.SHARE_OF.get(f))
        assert col == f or f not in V5_FEATURES      # a replaced raw feature is gone
    assert set(dfx.SHARE_OF.values()) == set(SHARE_FEATURES)


def test_select_transforms_picks_lowest_psi_ties_to_raw():
    rng = np.random.default_rng(0)
    n = 4000
    def pool(shift):
        return pd.DataFrame({f: rng.normal(size=n) + (shift if f == "assigner_kev_count" else 0.0) for f in dfx.SENSITIVE} |
                            {s_: rng.normal(size=n) for s_ in SHARE_FEATURES})
    chosen, table = dfx.select_transforms([pool(0.0), pool(0.0)], pool(2.0))
    assert set(chosen) == set(dfx.SENSITIVE)
    # identical distributions everywhere except assigner_kev_count raw: its rank or share must win, never raw
    assert chosen["assigner_kev_count"] != "assigner_kev_count"
    # features with no shift: all candidates ~0, ties/near-ties resolved to raw only if not strictly better by tol, so the table is complete
    assert len(table) == sum(len(dfx.candidate_columns(f)) for f in dfx.SENSITIVE)
    # exact tie goes to raw
    same = pd.DataFrame({c: np.arange(100.0) for f in dfx.SENSITIVE for _, c in dfx.candidate_columns(f)})
    chosen_tie, _ = dfx.select_transforms([same], same)
    assert all(chosen_tie[f] == f for f in dfx.SENSITIVE)


@pytest.mark.skipif(not all((OUT_DIR / f).exists() for f in ["features_replica_2024.parquet", "features_replica_2025.parquet",
                                                             "features_scoreboard.parquet", "text_features.parquet"]),
                    reason="feature files not present")
def test_recomputed_psi_still_selects_the_recorded_replacements():
    text = pd.read_parquet(OUT_DIR / "text_features.parquet").set_index("cve_id")

    def x2(name):
        f = pd.read_parquet(OUT_DIR / name)
        t = text.reindex(f["cve_id"])[TEXT_FEATURES].reset_index(drop=True)
        return pd.concat([f[V1_FEATURES].reset_index(drop=True), t], axis=1)

    rep = pd.concat([x2("features_replica_2024.parquet"), x2("features_replica_2025.parquet")], ignore_index=True)
    table = dfx.psi_table(rep, x2("features_scoreboard.parquet"))
    assert dfx.replaced_features(table) == PSI_REPLACED          # step 3d decision (legacy)
    raw_epss = table.set_index("feature").loc["epss"]
    assert raw_epss["psi"] > dfx.PSI_LARGE   # the drift evidence for removing raw epss


@pytest.mark.skipif(not all((OUT_DIR / f).exists() for f in ["features_replica_2024.parquet", "features_replica_2025.parquet", "features_scoreboard.parquet"]),
                    reason="feature files not present")
def test_recomputed_psi_still_selects_the_recorded_v5_transformations():
    cols = V1_FEATURES + SHARE_FEATURES
    f24, f25, sb = (pd.read_parquet(OUT_DIR / f"features_{n}.parquet")[cols] for n in ("replica_2024", "replica_2025", "scoreboard"))
    chosen, _ = dfx.select_transforms([f24, f25], sb)
    assert chosen == V5_TRANSFORMS
