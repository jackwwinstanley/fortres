"""m19 adversarial pruning (label-blind). Discriminator = LightGBM (200 trees, 15 leaves, seed 0) separating the TRAINING-year
pool (0) from the 2026 scoreboard pool (1) on the v5 features; no KEV label is used. The 3 features with the highest
discriminator gain (fixed number, chosen now) are dropped.
Standalone: I's settings on the remaining v5 features (20-seed bag). Feature variant: the discriminator's out-of-sample
'2026-likeness' probability added to I. Blend: standalone blended 50/50 with I."""
import json

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.b.zoo import harness as H
from src.b.zoo.util import memo

N_DROP = 3
_D = {}


def discriminator(train):
    k = (train.name, len(train), str(train.cve_id[0]))
    if k not in _D:
        pools, _, _ = H.load()
        sb = pools["sb"]
        X = pd.concat([train.X, sb.X], ignore_index=True)
        z = np.r_[np.zeros(len(train)), np.ones(len(sb))]
        m = lgb.LGBMClassifier(n_estimators=200, num_leaves=15, learning_rate=0.05, subsample=0.8, subsample_freq=1, random_state=0,
                               n_jobs=2, verbose=-1, importance_type="gain").fit(X, z)
        imp = pd.Series(m.feature_importances_, index=X.columns).sort_values(ascending=False)
        _D[k] = (m, list(imp.index[:N_DROP]), imp)
        H.log("m19 drop", train.name, list(imp.index[:N_DROP]))
    return _D[k]


@memo("m19")
def score(train, apply, seed, env):
    _, drop, _ = discriminator(train)
    keep = [c for c in train.X.columns if c not in drop]
    return H.lgb_fit_predict(env["I_params"], train.X[keep], train.y, apply.X[keep], seed)


def feature(train, apply, seed, env):
    m, _, _ = discriminator(train)
    return pd.DataFrame({"p_2026_like": m.predict_proba(apply.X)[:, 1]})


if __name__ == "__main__":
    pools, _, _ = H.load()
    drops = {y: discriminator(pools[y])[1] for y in (2024, 2025)}
    H.run_method("m19_adversarial", score_fn=score, feature_fn=feature, deterministic=False, params={"n_drop": N_DROP},
                 notes="dropped by training year: " + json.dumps({str(k): v for k, v in drops.items()}))
