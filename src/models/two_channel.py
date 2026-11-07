"""Two-channel allocation (no fitting).  Run after train_v2:  python -m src.models.two_channel

Channel A = exploit-then-EPSS baseline order (any_exploit desc, epss desc, cve_id).
Channel B = mean of the within-pool percentile ranks of kev_text_score, assigner_kev_rate_smooth,
            vendor_kev_count_max and nearest_kev_sim (ties by cve_id).
Allocation: top s from A, then fill the remaining k - s slots from B (skipping CVEs already chosen).
Headline numbers choose s on one replica and report the other; the pooled-best s is slightly optimistic.
Final rule (decided before running): the 2026 list uses the allocation fraction with the highest pooled hits
over both replicas; ties go to the LARGER s (closest to the baseline). LOW POWER: 27 + 48 positives.
"""
import json

import numpy as np
import pandas as pd

from src.baselines import add_scores
from src.common.paths import DATA_DIR, OUT_DIR
from src.common.scoring import expected_hits_at_k, k_for_pool, paired_bootstrap_hits, rank_order
from src.models import train_v1 as v1
from src.models.train_v2 import LABEL, load_with_text

FRACS = [1.0, 0.9, 0.8, 0.7, 0.6, 0.5]
B_SCORES = ["kev_text_score", "assigner_kev_rate_smooth", "vendor_kev_count_max", "nearest_kev_sim"]
BASE = "Exploit code, then EPSS"
N_FINAL, N_POOL_SB = 500, 72670


def channel_a_ids(df) -> list:
    return rank_order(df, ["exploit_epss"])["cve_id"].tolist()


def channel_b_score(df) -> pd.Series:
    """Mean of within-pool percentile ranks (average ties) of the four prior scores."""
    return pd.concat([df[c].rank(pct=True, method="average") for c in B_SCORES], axis=1).mean(axis=1)


def channel_b_ids(df) -> list:
    return rank_order(df.assign(b_mean=channel_b_score(df)), ["b_mean"])["cve_id"].tolist()


def allocate(a_ids, b_ids, k, s) -> list:
    """Top s of channel A, then channel B until k unique ids; B never re-adds an A pick."""
    chosen = list(a_ids[:s])
    seen = set(chosen)
    for i in b_ids:
        if len(chosen) >= k:
            break
        if i not in seen:
            chosen.append(i)
            seen.add(i)
    return chosen


def build_final_list(df, k=N_FINAL, frac=1.0) -> list:
    """Final list for a pool df (needs exploit_epss and the four B score columns): exactly k unique ids."""
    out = allocate(channel_a_ids(df), channel_b_ids(df), k, round(frac * k))
    assert len(out) == k and len(set(out)) == k
    return out


def pos_from_order(ids, order_ids, n_index):
    """Rank position of every row given a chosen prefix `ids` followed by the rest in `order_ids`."""
    pos = np.empty(len(n_index), dtype=np.int64)
    seq = list(ids) + [i for i in order_ids if i not in set(ids)]
    pos[n_index.loc[seq].to_numpy()] = np.arange(len(seq))
    return pos


def best_frac(hits_by_frac: dict) -> float:
    m = max(hits_by_frac.values())
    return max(f for f, h in hits_by_frac.items() if h == m)  # ties -> larger s


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, sb, sb2 = load_with_text(out_dir, data_dir)
    preds = pd.read_parquet(out_dir / ".cache" / "test_preds.parquet")
    frames, ks = {}, {}
    for y in (2024, 2025):
        df = data[y]["meta"].copy()
        p = preds[preds["test_year"] == y].set_index("cve_id").reindex(df["cve_id"])
        for v in ["logreg_v1", "lgbm_v1", "logreg_v2", "lgbm_v2"]:
            df[f"s_{v}"] = p[v].to_numpy()
        frames[y], ks[y] = df, k_for_pool(len(df))

    # ---- allocation table: every fraction on both replicas
    chosen, hits = {}, {y: {} for y in frames}
    for y, df in frames.items():
        a, b = channel_a_ids(df), channel_b_ids(df)
        lab = df.set_index("cve_id")["label"]
        for f in FRACS:
            ids = allocate(a, b, ks[y], round(f * ks[y]))
            chosen[(y, f)] = ids
            hits[y][f] = int(lab.loc[ids].sum())
    pooled_hits = {f: hits[2024][f] + hits[2025][f] for f in FRACS}
    f24, f25 = best_frac(hits[2024]), best_frac(hits[2025])
    f_pool = best_frac(pooled_hits)
    cross = {2025: (f24, hits[2025][f24]), 2024: (f25, hits[2024][f25])}  # s chosen on the OTHER replica

    # ---- pooled comparison with paired bootstrap, all rankings together
    Bs, exp_tab = {}, {}
    names = None
    for y, df in frames.items():
        df = df.assign(b_mean=channel_b_score(df))
        idx = pd.Series(np.arange(len(df)), index=df["cve_id"])
        a_order = channel_a_ids(df)
        rk = dict(v1.BASELINES)
        rk.update({LABEL[v]: [f"s_{v}", "epss_rank_in_month"] for v in ["logreg_v1", "lgbm_v1", "logreg_v2", "lgbm_v2"]})
        rk.update({f"B alone: {c}": [c] for c in B_SCORES})
        rk["B alone: mean of 4 percentile ranks"] = ["b_mean"]
        pos, e = [], {}
        for name, cols in rk.items():
            pos.append(v1.rank_pos(df, cols))
            e[name] = expected_hits_at_k(df, cols, ks[y])
        for name, f in [("Two-channel, s chosen on the other replica", cross[y][0]),
                        (f"Two-channel, best pooled s ({f_pool:.0%} of k; optimistic)", f_pool)]:
            ids = chosen[(y, f)]
            pos.append(pos_from_order(ids, a_order, idx))
            hit = int(df.set_index("cve_id")["label"].loc[ids].sum())
            e[name] = dict(arbitrary=hit, expected=float(hit), tie_size=1, slots_in_tie=0)
        names = list(e)
        Bs[y] = paired_bootstrap_hits(df["label"].to_numpy(), pos, ks[y], n=v1.N_BOOT, seed=0)
        exp_tab[y] = e
    bi = names.index(BASE)
    rows = []
    for j, n in enumerate(names):
        arb = sum(exp_tab[y][n]["arbitrary"] for y in frames)
        exp = sum(exp_tab[y][n]["expected"] for y in frames)
        d = sum(Bs[y][:, j] - Bs[y][:, bi] for y in frames)
        lo, hi = np.percentile(d, [5, 95])
        rows.append((n, exp_tab[2025][n]["arbitrary"], exp_tab[2024][n]["arbitrary"], arb, f"{exp:.1f}",
                     "" if n == BASE else f"{arb - sum(exp_tab[y][BASE]['arbitrary'] for y in frames):+d} [{lo:+.0f}, {hi:+.0f}]"))
    base_pooled_exp = sum(exp_tab[y][BASE]["expected"] for y in frames)

    # ---- final 2026 list
    sbm = add_scores(sb2.assign(cve_id=sb["cve_id"].to_numpy(), label=0))  # exploit_epss from scoreboard epss and flags
    for c in B_SCORES:
        assert c in sbm
    final_ids = build_final_list(sbm, N_FINAL, f_pool)
    pd.DataFrame({"cve_id": final_ids}).to_csv(out_dir / "top500_v2.csv", index=False)
    a_only = set(channel_a_ids(sbm)[:N_FINAL])
    overlap_baseline = len(a_only & set(final_ids))

    best_alloc_hits = pooled_hits[f_pool]
    beat = best_alloc_hits > base_pooled_exp
    L = ["### Two-channel allocation (no fitting)", "",
         "> **LOW POWER** (75 positives). Channel A = exploit-then-EPSS order. Channel B = mean of within-pool percentile "
         "ranks of kev_text_score, assigner_kev_rate_smooth, vendor_kev_count_max, nearest_kev_sim. Allocation: top s of A, "
         "then B fills the remaining k - s, skipping CVEs already chosen. Hits are counted in arbitrary tie order (ties by cve_id).", ""]
    L += ["Hits for every allocation on both replicas (s as a share of k; 100% = the baseline):", "",
          v1.md(["s", "2024 (k=%d)" % ks[2024], "2025 (k=%d)" % ks[2025], "pooled"],
                [(f"{f:.0%} ({round(f * ks[2024])} / {round(f * ks[2025])})", hits[2024][f], hits[2025][f], pooled_hits[f]) for f in FRACS]), ""]
    L += ["Headline (s chosen on one replica, reported on the other; ties go to the larger s):", "",
          v1.md(["choose s on", "chosen s", "report on", "hits there", "baseline hits there"],
                [(2024, f"{f24:.0%}", 2025, hits[2025][f24], hits[2025][1.0]),
                 (2025, f"{f25:.0%}", 2024, hits[2024][f25], hits[2024][1.0]),
                 ("pooled", "", "", hits[2025][f24] + hits[2024][f25], hits[2025][1.0] + hits[2024][1.0])]), ""]
    L += [f"Pooled-best s = **{f_pool:.0%}** of k (optimistic, chosen on the same data it is scored on). "
          "Final rule, decided before running: the 2026 list uses the allocation with the highest pooled hits across both "
          "replicas; ties go to the larger s.", ""]
    L += ["Everything side by side, pooled over both replicas (test replica 2025 and 2024). Models are trained on the other "
          "replica. Interval = 90% paired bootstrap of the pooled difference vs the best baseline (1000 resamples within "
          "each replica, seed 0; for the allocations the ranking is held fixed in the resample):", "",
          v1.md(["ranking", "hits 2025", "hits 2024", "pooled hits", "pooled expected", f"diff vs {BASE}"], rows), ""]
    L += [f"Final list `outputs/top500_v2.csv`: allocation s = {round(f_pool * N_FINAL)} from Channel A "
          f"+ {N_FINAL - round(f_pool * N_FINAL)} from Channel B on the 2026 scoreboard; {overlap_baseline} of 500 overlap "
          "with the baseline top 500.", ""]
    if not beat:
        L += [f"**Nothing beat the baseline.** The best allocation's pooled hits ({best_alloc_hits}) do not exceed the baseline's "
              f"pooled expected hits ({base_pooled_exp:.1f}); per the pre-set rule the list uses the larger s on ties.", ""]
    (out_dir / ".cache" / "v2_two_channel.md").write_text("\n".join(L) + "\n")
    json.dump({"hits": {str(y): {str(f): h for f, h in hits[y].items()} for y in hits}, "f_pool": f_pool,
               "f24": f24, "f25": f25, "rows": [list(map(str, r)) for r in rows], "beat": bool(beat),
               "base_pooled_expected": base_pooled_exp, "overlap_with_baseline": overlap_baseline},
              open(out_dir / ".cache" / "v2_two_channel.json", "w"))
    print("\n".join(L))


if __name__ == "__main__":
    main()
