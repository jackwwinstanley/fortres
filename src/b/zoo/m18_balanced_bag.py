"""m18 balanced bagging: each seed = one bag with ALL training positives + a random sample of 20 x as many negatives
(sampled with that seed), LightGBM with I's settings for that training year but scale_pos_weight = 1. 20-seed bag."""
import numpy as np

from src.b.zoo import harness as H
from src.b.zoo.util import memo

RATIO = 20


@memo("m18")
def score(train, apply, seed, env):
    rng = np.random.default_rng(int(seed))
    pos = np.flatnonzero(train.y == 1)
    neg = rng.choice(np.flatnonzero(train.y == 0), size=min(RATIO * len(pos), int((train.y == 0).sum())), replace=False)
    idx = np.sort(np.r_[pos, neg])
    p = {**env["I_params"], "scale_pos_weight": 1}
    return H.lgb_fit_predict(p, train.X.iloc[idx].reset_index(drop=True), train.y[idx], apply.X, seed)


if __name__ == "__main__":
    H.run_method("m18_balanced_bag", score_fn=score, deterministic=False, params={"neg_per_pos": RATIO})
