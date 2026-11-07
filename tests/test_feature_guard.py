import pytest

from src.common.schema import ALLOWED_FEATURES, check_feature_list, is_banned
from src.models.train_v1 import FEATURES


def test_model_features_are_allowed_and_not_banned():
    assert check_feature_list(FEATURES) == []
    assert set(FEATURES) <= set(ALLOWED_FEATURES)


@pytest.mark.parametrize("bad", ["nvd_status", "n_affected_cpes", "n_references", "cvss3_score", "cvss_missing",
                                 "cwe_ids", "affected_products_n", "reference_links", "kev_text_score",
                                 "kev_date_added", "description"])
def test_guard_catches_banned_names(bad):
    assert is_banned(bad)
    assert check_feature_list(FEATURES + [bad])  # non-empty problem list


def test_history_kev_features_are_the_only_allowed_kev_names():
    kev_named = [f for f in ALLOWED_FEATURES if "kev" in f]
    assert kev_named and all(not is_banned(f) for f in kev_named)
