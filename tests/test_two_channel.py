import numpy as np
import pandas as pd

from src.models.two_channel import B_SCORES, allocate, best_frac, build_final_list, channel_b_score


def pool(n=60, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({"cve_id": [f"CVE-2026-{i:05d}" for i in range(n)],
                       "exploit_epss": rng.random(n).round(2) + rng.integers(0, 2, n) * 2,
                       **{c: rng.random(n).round(2) for c in B_SCORES}})
    return df


def test_allocate_exact_k_unique_and_b_never_readds_a():
    a = [f"id{i}" for i in range(10)]
    b = ["id2", "id9", "x1", "id0", "x2", "x3", "x4"]
    out = allocate(a, b, k=6, s=3)
    assert out == ["id0", "id1", "id2", "id9", "x1", "x2"]  # id2 and id0 (A picks) are skipped in B
    assert len(out) == len(set(out)) == 6
    assert allocate(a, b, k=5, s=5) == a[:5]            # s = k -> pure channel A


def test_build_final_list_exact_deterministic_unique():
    df = pool()
    for frac in (1.0, 0.8, 0.5):
        out = build_final_list(df, k=20, frac=frac)
        assert len(out) == 20 and len(set(out)) == 20
        assert out == build_final_list(df.sample(frac=1, random_state=3), k=20, frac=frac)  # row order is irrelevant
    full = build_final_list(df, k=20, frac=0.5)
    top_a = df.sort_values(["exploit_epss", "cve_id"], ascending=[False, True])["cve_id"].head(10).tolist()
    assert full[:10] == top_a and not set(full[10:]) & set(top_a)


def test_channel_b_score_range_and_ties():
    df = pool()
    s = channel_b_score(df)
    assert s.between(0, 1).all()


def test_best_frac_ties_go_to_larger_s():
    assert best_frac({1.0: 5, 0.9: 7, 0.8: 7, 0.5: 3}) == 0.9
    assert best_frac({1.0: 5, 0.9: 5}) == 1.0
