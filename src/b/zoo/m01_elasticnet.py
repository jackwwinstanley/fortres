"""m01 elastic-net logistic regression on the v5 features (median-imputed, standardised on the training year).
C x l1_ratio chosen by leave-one-snapshot-month-out CV AP inside the training year only. Deterministic (saga, random_state=0)."""
import itertools
import warnings

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from src.b.zoo import harness as H
from src.b.zoo.util import memo, numeric

warnings.filterwarnings("ignore")
GRID = list(itertools.product([0.01, 0.1, 1.0], [0.2, 0.5, 0.8]))
_SEL = {}


def _fit(Xa, ya, Xb, C, l1):
    m = LogisticRegression(penalty="elasticnet", solver="saga", C=C, l1_ratio=l1, class_weight="balanced", max_iter=300, tol=1e-3, random_state=0)
    return m.fit(Xa, ya).decision_function(Xb)


def select(train):
    k = (train.name, len(train))
    if k not in _SEL:
        best = None
        for C, l1 in GRID:
            oof = np.zeros(len(train))
            for mth in sorted(set(train.months)):
                te = train.months == mth
                a, b = numeric(train.subset(~te), train.subset(te))
                oof[te] = _fit(a, train.y[~te], b, C, l1)
            ap = average_precision_score(train.y, oof)
            H.log("m01 cv", train.name, C, l1, round(ap, 4))
            if best is None or ap > best[0]:
                best = (ap, C, l1)
        _SEL[k] = best
    return _SEL[k]


@memo("m01")
def score(train, apply, seed, env):
    _, C, l1 = select(train)
    a, b = numeric(train, apply)
    return _fit(a, train.y, b, C, l1)


if __name__ == "__main__":
    H.run_method("m01_elasticnet", score_fn=score, deterministic=True, params={"grid_C_l1": GRID})
