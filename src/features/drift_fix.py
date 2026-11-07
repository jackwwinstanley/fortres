"""Step 3d: robustness of the feature set to the 2026 shift.

Decisions (made on drift evidence, not on test hits):
  1. raw `epss` is removed (its scale moved ~4x in 2026); `epss_rank_in_month` and `epss_missing` stay.
  2. PSI (population stability index) of every v2 feature, pooled 2024+2025 replicas vs the 2026 scoreboard,
     10 quantile bins from the replicas. Any scale-type feature (counts or raw scores, not binary flags and not an
     existing percentile rank) with PSI > 0.25 is replaced by its within-pool percentile rank (pool = each replica,
     or the scoreboard, computed separately).
PSI here is spike-aware: a value holding >= 10% of the replica rows (typically 0) gets its own bin and the rest is cut
into quantile bins. src.b.drift.psi collapses zero-inflated columns into one bin and treats integer columns as
categories, which makes counts such as days_to_cutoff look unstable for the wrong reason; the formula is the same.
"""
import numpy as np
import pandas as pd

from src.common.schema import PSI_REPLACED, RAW_REMOVED, TEXT_FEATURES, V2_FEATURES, V4_FEATURES  # noqa: F401

PSI_LARGE = 0.25
BINARY = {"epss_missing", "exploitdb", "metasploit", "nuclei", "poc_github", "any_exploit"} | \
    {c for c in TEXT_FEATURES if c.startswith("txt_")}
RANK_TYPE = {"epss_rank_in_month"}  # already a within-month percentile rank
REMOVED = list(RAW_REMOVED)
SCALE_CANDIDATES = [f for f in V2_FEATURES if f not in BINARY | RANK_TYPE | set(REMOVED)]
SPIKE_SHARE = 0.10


def psi_binned(a, b, bins: int = 10) -> float:
    """PSI of b relative to a (a = replicas, b = scoreboard); NaNs ignored. Columns with <= 3 distinct values in a
    (binary flags) use one bin per value."""
    a, b = pd.Series(a, dtype="float64").dropna(), pd.Series(b, dtype="float64").dropna()
    if a.nunique() <= 3:
        cats = sorted(set(a) | set(b))
        pa = np.array([(a == c).mean() for c in cats])
        pb = np.array([(b == c).mean() for c in cats])
    else:
        vc = a.value_counts(normalize=True)
        spike = vc.index[0] if vc.iloc[0] >= SPIKE_SHARE else None
        rest = a[a != spike] if spike is not None else a
        edges = np.unique(np.quantile(rest, np.linspace(0, 1, bins + 1))).astype(float)
        edges = np.array([-np.inf, np.inf]) if len(edges) < 2 else np.r_[-np.inf, edges[1:-1], np.inf]

        def shares(x):
            if spike is None:
                return np.histogram(x, edges)[0] / max(len(x), 1)
            is_spike = (x == spike).to_numpy()
            return np.append(np.histogram(x[~is_spike], edges)[0], is_spike.sum()) / max(len(x), 1)

        pa, pb = shares(a), shares(b)
    pa, pb = np.clip(pa, 1e-4, None), np.clip(pb, 1e-4, None)
    return float(np.sum((pb - pa) * np.log(pb / pa)))


def psi_table(rep: pd.DataFrame, sb: pd.DataFrame, features=None) -> pd.DataFrame:
    rows = []
    for f in features or V2_FEATURES:
        kind = "binary" if f in BINARY else "rank" if f in RANK_TYPE else "removed" if f in REMOVED else "scale"
        p = psi_binned(rep[f], sb[f])
        rows.append((f, kind, p, rep[f].isna().mean(), sb[f].isna().mean()))
    return pd.DataFrame(rows, columns=["feature", "kind", "psi", "missing_replicas", "missing_scoreboard"])


def replaced_features(table: pd.DataFrame) -> list[str]:
    """Scale-type features whose PSI exceeds the threshold, in V2 order."""
    big = set(table.loc[(table["kind"] == "scale") & (table["psi"] > PSI_LARGE), "feature"])
    return [f for f in SCALE_CANDIDATES if f in big]


def rank_name(f: str) -> str:
    return f + "_pctrank"


def to_v4(X: pd.DataFrame, replaced) -> pd.DataFrame:
    """Drop raw epss and swap each replaced feature for its within-pool percentile rank. X is ONE pool
    (a replica or the scoreboard); call it separately per pool."""
    out = X.drop(columns=[c for c in REMOVED if c in X]).copy()
    for f in replaced:
        out[rank_name(f)] = X[f].rank(pct=True, method="average").to_numpy()
    return out.drop(columns=list(replaced))


def v4_feature_names(replaced) -> list[str]:
    """V2 order, minus raw epss, with replaced features renamed to *_pctrank."""
    return [rank_name(f) if f in replaced else f for f in V2_FEATURES if f not in REMOVED]
