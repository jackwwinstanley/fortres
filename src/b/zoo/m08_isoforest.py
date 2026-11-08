"""m08 IsolationForest anomaly score on the v5 features (label-blind; fit on the training year only).
Standalone: anomaly score (higher = more unusual), 20-seed bag. Feature: anomaly score from one forest (first seed of the set)."""
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.b.zoo import harness as H
from src.b.zoo.util import memo, numeric


@memo("m08")
def score(train, apply, seed, env):
    a, b = numeric(train, apply, scale=False)
    return -IsolationForest(n_estimators=200, random_state=int(seed), n_jobs=2).fit(a).score_samples(b)


def feature(train, apply, seed, env):
    return pd.DataFrame({"iso_anomaly": score(train, apply, seed, env)})


if __name__ == "__main__":
    import sys
    if "--variants" not in " ".join(sys.argv):
        # standalone is stochastic (bagged); feature and blend use the same entry point
        pass
    H.run_method("m08_isoforest", score_fn=score, feature_fn=feature, deterministic=False, coverage_fn=feature)
