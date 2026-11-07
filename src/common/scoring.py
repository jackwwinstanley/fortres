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


def rank_order(df, score_cols, ascending=False) -> pd.DataFrame:
    """Rows in ranked order (score cols desc, then cve_id asc); public wrapper of the tie-break rule."""
    return _ranked(df, score_cols, ascending)


def expected_hits_at_k(df, score_cols, k, label_col="label") -> dict:
    """Tie-aware hits. Rows with identical values in ALL score_cols form a tie group.
    expected = positives in groups fully inside the top k
               + (positives in the straddling group) * (slots remaining) / (group size).
    arbitrary = hits when ties are broken by cve_id (the deterministic scorer rule).
    tie_size = size of the group straddling the cutoff (1 if the cut falls between groups)."""
    cols = [score_cols] if isinstance(score_cols, str) else list(score_cols)
    r = _ranked(df, cols).reset_index(drop=True)
    vals = r[cols]
    prev = vals.shift()
    differs = ((vals != prev) & ~(vals.isna() & prev.isna())).any(axis=1)
    differs.iloc[0] = True
    gid = differs.cumsum()
    g = r.groupby(gid, sort=True).agg(size=(label_col, "size"), pos=(label_col, "sum"))
    end = g["size"].cumsum()
    start = end - g["size"]
    inside = end <= k
    straddle = (start < k) & (end > k)
    expected = float(g.loc[inside, "pos"].sum())
    tie_size, slots = 1, 0
    if straddle.any():
        row = g[straddle].iloc[0]
        slots = int(k - start[straddle].iloc[0])
        tie_size = int(row["size"])
        expected += float(row["pos"]) * slots / tie_size
    return {"arbitrary": int(r.head(k)[label_col].sum()), "expected": expected,
            "tie_size": tie_size, "slots_in_tie": slots}


def paired_bootstrap_hits(labels, rank_positions, k, n=1000, seed=0):
    """Paired bootstrap of hits@k for several rankings of the SAME rows.
    labels: array of 0/1 per row. rank_positions: list of arrays, position of each row in a
    ranking (0 = best). Each resample draws rows with replacement (same draw for every ranking),
    orders them by each ranking and counts positives in the first k. Returns array (n, n_rankings)."""
    labels = np.asarray(labels)
    rng = np.random.default_rng(seed)
    size = len(labels)
    out = np.empty((n, len(rank_positions)))
    for i in range(n):
        idx = rng.integers(0, size, size)
        lab = labels[idx]
        for j, pos in enumerate(rank_positions):
            order = np.argsort(pos[idx], kind="stable")
            out[i, j] = lab[order][:k].sum()
    return out
