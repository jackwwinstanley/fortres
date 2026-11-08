"""Small helpers shared by zoo methods (not part of the frozen harness; methods still score only through harness.evaluate)."""
import numpy as np
import pandas as pd

_MEMO = {}


def key(train, apply, seed, tag=""):
    return (tag, train.name, len(train), str(train.cve_id[0]), str(train.cve_id[-1]), apply.name, len(apply),
            str(apply.cve_id[0]), str(apply.cve_id[-1]), int(seed))


def memo(tag):
    """Cache a fit_predict_fn's output in-process (standalone and blend_I reuse the same scores)."""
    def deco(fn):
        def inner(train, apply, seed, env):
            k = key(train, apply, seed, tag)
            if k not in _MEMO:
                _MEMO[k] = fn(train, apply, seed, env)
            return _MEMO[k]
        return inner
    return deco


def numeric(train, apply, cols=None, scale=True):
    """Median-impute (train medians) and optionally standardise (train mean/sd) the v5 features."""
    cols = list(train.X.columns) if cols is None else cols
    a, b = train.X[cols].astype(float), apply.X[cols].astype(float)
    med = a.median().fillna(0)
    a, b = a.fillna(med), b.fillna(med)
    if scale:
        mu, sd = a.mean(), a.std().replace(0, 1).fillna(1)
        a, b = (a - mu) / sd, (b - mu) / sd
    return a.to_numpy(), b.to_numpy()
