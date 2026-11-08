"""m06 rank by I's bag mean minus 1 x bag sd: per-seed I scores (same seed set) -> percentile rank per seed -> mean - sd."""
import numpy as np
import pandas as pd

from src.b.zoo import harness as H


def score(train, apply, seed, env):
    P = np.array([pd.Series(s).rank(pct=True).to_numpy() for s in env["I_seed_scores"]])
    assert P.shape[1] == len(apply)
    return P.mean(0) - P.std(0)


if __name__ == "__main__":
    H.run_method("m06_mean_minus_sd", score_fn=score, deterministic=True)
