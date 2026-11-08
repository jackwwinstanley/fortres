"""Which model is the primary (headline) model, and its file names. Import this instead of hard-coding v5/v6 names.

v6 = the b/rank candidate I (regularised v5 settings on the frozen v5 features), chosen from seven declared variants by a
rule fixed before any result (outputs/rank_report.md, outputs/v6_report.md). v5 is kept as history ("previous").
"""
from src.common.paths import OUT_DIR

PRIMARY = "v6"
PREVIOUS = "v5"

_FILES = {
    "v6": dict(top500="top500_v6.csv", contrib="v6_top500_contrib.parquet", blindspots="v6_blindspots.csv",
               leakage="v6_leakage_results.csv", report="v6_report.md"),
    "v5": dict(top500="top500_v5.csv", contrib="v5_top500_contrib.parquet", blindspots="v5_blindspots.csv",
               leakage="leakage_results.csv", report="v5_report.md"),
}

# Practice-year (directional) settings of each model, keyed by training year. v6: chosen in b/rank by leave-one-month-out
# CV inside the training year only (outputs/rank_eval.csv, candidate I, "selected"). v5: None = v5's rule
# (train_v1.select_lgbm on the training replica).
_DIRECTION_PARAMS = {
    "v6": {2024: {"num_leaves": 2, "min_child_samples": 200, "n_estimators": 150, "reg_lambda": 30, "scale_pos_weight": 10, "colsample_bytree": 0.4},
           2025: {"num_leaves": 3, "min_child_samples": 200, "n_estimators": 150, "reg_lambda": 30, "scale_pos_weight": 10, "colsample_bytree": 0.6}},
    "v5": None,
}


def name(model: str = PRIMARY) -> str:
    return model


def files(model: str = PRIMARY, out_dir=OUT_DIR) -> dict:
    """{'top500', 'contrib', 'blindspots', 'leakage', 'report'} -> Path for `model` (default: the primary model)."""
    return {k: out_dir / v for k, v in _FILES[model].items()}


def file(kind: str, model: str = PRIMARY, out_dir=OUT_DIR):
    return files(model, out_dir)[kind]


def direction_params(train_year: int, X, y, groups, feats, model: str = PRIMARY) -> dict:
    """The model's settings for a practice direction trained on `train_year` (never chosen on a test year)."""
    fixed = _DIRECTION_PARAMS[model]
    if fixed is not None:
        return dict(fixed[int(train_year)])
    from src.models import train_v1 as v1
    return v1.select_lgbm(X[feats], y, groups, feats, f"v5 train {train_year}")[0]


def lgbm(params: dict, feats: list, seed: int):
    """LightGBM classifier with the project's fixed settings and monotone constraints; a value in `params` overrides
    a fixed default (v6 sets colsample_bytree)."""
    import lightgbm as lgb
    from src.common.schema import MONOTONE_UP
    from src.models import train_v1 as v1
    mono = [1 if f in MONOTONE_UP else 0 for f in feats]
    return lgb.LGBMClassifier(monotone_constraints=mono, **{**v1.FIXED, "random_state": int(seed), **params})
