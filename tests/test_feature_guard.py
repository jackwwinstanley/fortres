import pytest

from src.common.schema import ALLOWED_FEATURES, V2_FEATURES, V4_FEATURES, check_feature_list, is_banned
from src.models.train_v1 import FEATURES
from src.models.train_v2 import FEATURES_V2


def test_legacy_v1_features_are_allowed_under_the_legacy_list():
    assert check_feature_list(FEATURES, allowed=V2_FEATURES) == []
    assert set(FEATURES) <= set(V2_FEATURES)


def test_current_features_exclude_raw_epss_and_pass_the_guard():
    from src.models.train_v5 import FEATURES_V5
    assert "epss" not in ALLOWED_FEATURES and "epss" not in FEATURES_V5
    assert check_feature_list(FEATURES_V5) == []
    assert set(FEATURES_V5) == set(ALLOWED_FEATURES)
    assert check_feature_list(["epss"])            # raw epss is no longer allowed for a current model


def test_legacy_v4_features_pass_under_their_own_list():
    from src.models.train_v4 import FEATURES_V4
    assert check_feature_list(FEATURES_V4, allowed=V4_FEATURES) == []
    assert check_feature_list(FEATURES_V4)         # but they are not the current allowed set


@pytest.mark.parametrize("bad", ["nvd_status", "n_affected_cpes", "n_references", "cvss3_score", "cvss_missing",
                                 "cwe_ids", "affected_products_n", "reference_links", "kev_date_added",
                                 "kev_after_snapshot", "description", "in_kev"])
def test_guard_catches_banned_names(bad):
    assert is_banned(bad)
    assert check_feature_list(FEATURES + [bad])  # non-empty problem list


def test_v2_legacy_features_are_allowed_under_the_legacy_list():
    assert check_feature_list(FEATURES_V2, allowed=V2_FEATURES) == []
    assert set(FEATURES) < set(FEATURES_V2)
    assert {"kev_text_score", "nearest_kev_sim"} <= set(FEATURES_V2)


def test_history_kev_features_are_the_only_allowed_kev_names():
    kev_named = [f for f in ALLOWED_FEATURES if "kev" in f]
    assert {"assigner_kev_share", "assigner_kev_12m_share"} <= set(kev_named)
    assert kev_named and all(not is_banned(f) for f in kev_named)
