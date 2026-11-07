"""Scoring helpers shared by both people. Rule: k = round(500 * pool / 72670);
hits = labelled positives in the top k by score; ties broken by cve_id."""
import numpy as np
import pandas as pd

TOTAL_SCOREBOARD = 72670
TOP_N = 500


def k_for_pool(pool_size: int, total: int = TOTAL_SCOREBOARD, top: int = TOP_N) -> int:
    return max(1, round(top * pool_size / total))


def _ranked(df: pd.DataFrame, score_cols, ascending=False) -> pd.DataFrame:
    """Sort by score(s) descending, then cve_id ascending (deterministic)."""
    cols = [score_cols] if isinstance(score_cols, str) else list(score_cols)
    asc = [ascending] * len(cols) + [True]
    return df.sort_values(cols + ["cve_id"], ascending=asc, kind="mergesort", na_position="last")


def hits_at_k(df, score_col, label_col="label", k=None) -> int:
    k = k_for_pool(len(df)) if k is None else k
    return int(_ranked(df, score_col).head(k)[label_col].sum())


def baselines(df, label_col="label", cvss_col=None, k=None) -> dict:
    """Hits for CVSS-desc (only if cvss_col given), EPSS-desc, any-exploit-flag then EPSS."""
    k = k_for_pool(len(df)) if k is None else k
    out = {}
    if cvss_col is not None:
        out["cvss"] = hits_at_k(df, cvss_col, label_col, k)
    out["epss"] = hits_at_k(df, "epss", label_col, k)
    d = df.assign(any_exploit=df[["exploitdb", "metasploit", "nuclei", "poc_github"]].max(axis=1))
    out["exploit_epss"] = int(_ranked(d, ["any_exploit", "epss"]).head(k)[label_col].sum())
    return out


def bootstrap_interval(df, score_col, k, n=1000, seed=0, label_col="label"):
    """90% bootstrap interval (5th, 95th pct) of hits@k, resampling CVEs with replacement.
    k is rescaled to each resample's size (same here, since resamples keep len(df))."""
    rng = np.random.default_rng(seed)
    ranked = _ranked(df, score_col).reset_index(drop=True)
    labels = ranked[label_col].to_numpy()
    size = len(ranked)
    stats = np.empty(n)
    for i in range(n):
        idx = np.sort(rng.integers(0, size, size))  # keeps rank order
        stats[i] = labels[idx][:k].sum()
    return float(np.percentile(stats, 5)), float(np.percentile(stats, 95))
