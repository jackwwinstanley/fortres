"""m03 Cox proportional hazards on time-to-KEV with censoring (training year only).
Time origin = end of the snapshot month. Event = KEV date_added inside the label window (time = days to it); everyone else is
censored at days_to_cutoff (to Nov 4). Covariates = v5 features, median-imputed and standardised on the training year.
Breslow ties, L2 penalty 0.01 (fixed, not tuned). Score = linear predictor. Deterministic."""
import numpy as np
from scipy.optimize import minimize

from src.b.zoo import harness as H
from src.b.zoo.util import memo, numeric

LAM = 0.01


def fit_cox(X, t, e, lam=LAM):
    o = np.argsort(-t, kind="stable")
    X, t, e = X[o], t[o], e[o]
    # last index of each block of equal time (descending order): risk set = all rows with time >= t
    last = np.r_[np.flatnonzero(np.diff(t) != 0), len(t) - 1]
    grp = np.searchsorted(last, np.arange(len(t)))
    n = len(t)

    def f(b):
        eta = X @ b
        w = np.exp(eta - eta.max())
        R = np.cumsum(w)[last][grp]
        S1 = np.cumsum(w[:, None] * X, axis=0)[last][grp]
        ll = np.sum(e * (eta - eta.max() - np.log(R)))
        g = np.sum(e[:, None] * (X - S1 / R[:, None]), axis=0)
        return -ll / n + lam * b @ b, -g / n + 2 * lam * b

    r = minimize(f, np.zeros(X.shape[1]), jac=True, method="L-BFGS-B", options={"maxiter": 500})
    return r.x


@memo("m03")
def score(train, apply, seed, env):
    a, b = numeric(train, apply)
    e = train.y.astype(float)
    t = np.where(e == 1, train.days_to_kev, train.days_to_cutoff)
    t = np.nan_to_num(t, nan=np.nanmax(train.days_to_cutoff))
    beta = fit_cox(a, t.astype(float), e)
    return b @ beta


if __name__ == "__main__":
    H.run_method("m03_cox", score_fn=score, deterministic=True, params={"l2": LAM})
