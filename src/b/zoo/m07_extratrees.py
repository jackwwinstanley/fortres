"""m07 ExtraTrees on the v5 features (median-imputed). Fixed settings (not tuned): 300 trees, min_samples_leaf 30,
max_features 0.5, class_weight balanced_subsample. One forest per seed, 20-seed rank-averaged bag."""
from sklearn.ensemble import ExtraTreesClassifier

from src.b.zoo import harness as H
from src.b.zoo.util import memo, numeric

P = dict(n_estimators=300, min_samples_leaf=30, max_features=0.5, class_weight="balanced_subsample")


@memo("m07")
def score(train, apply, seed, env):
    a, b = numeric(train, apply, scale=False)
    m = ExtraTreesClassifier(**P, random_state=int(seed), n_jobs=2).fit(a, train.y)
    return m.predict_proba(b)[:, 1]


if __name__ == "__main__":
    H.run_method("m07_extratrees", score_fn=score, deterministic=False, params=P)
