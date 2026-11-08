from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from scripts.check_top500 import check
from src.common.paths import OUT_DIR, SCOREBOARD_CSV
from src.common.scoring import expected_hits_at_k
from src.models.stress_v2 import shuffle_text_within_month, smd, topk_hits, within_month_permutation
from src.models.train_v2 import FEATURES_V2

TEXT = ["kev_text_score", "txt_rce"]


def frame(n=40, seed=0):
    rng = np.random.default_rng(seed)
    months = np.repeat(["2024-01", "2024-02", "2024-03", "2024-04"], n // 4)
    return pd.DataFrame({"epss": rng.random(n), "kev_text_score": rng.random(n),
                         "txt_rce": rng.integers(0, 2, n).astype("int8"), "month": months}), months


def test_placebo_permutation_stays_within_month():
    _, months = frame()
    perm = within_month_permutation(months, np.random.default_rng(3))
    assert sorted(perm) == list(range(len(months)))          # a true permutation
    assert (months[perm] == months).all()                    # every row swaps only inside its own month


def test_placebo_shuffles_text_jointly_and_leaves_other_columns():
    X, months = frame()
    S = shuffle_text_within_month(X, months, TEXT, np.random.default_rng(5))
    assert (S["epss"] == X["epss"]).all() and (S["month"] == X["month"]).all()
    assert S["txt_rce"].dtype == X["txt_rce"].dtype
    for m in np.unique(months):                              # same multiset of (text row) tuples within each month
        a = sorted(map(tuple, X.loc[months == m, TEXT].to_numpy()))
        b = sorted(map(tuple, S.loc[months == m, TEXT].to_numpy()))
        assert a == b
    assert not S[TEXT].equals(X[TEXT])                       # actually shuffled
    again = shuffle_text_within_month(X, months, TEXT, np.random.default_rng(5))
    pd.testing.assert_frame_equal(S, again)                  # deterministic for a fixed seed


def test_topk_hits_matches_scorer_rule():
    rng = np.random.default_rng(1)
    n = 300
    df = pd.DataFrame({"cve_id": [f"CVE-2026-{i:05d}" for i in rng.permutation(n)], "s": rng.integers(0, 20, n) / 20,
                       "epss_rank_in_month": rng.integers(0, 5, n) / 5, "label": (rng.random(n) < 0.1).astype(int)})
    code = np.argsort(np.argsort(df["cve_id"].to_numpy()))
    want = expected_hits_at_k(df, ["s", "epss_rank_in_month"], 40)["arbitrary"]
    assert topk_hits(df["label"], df["s"], df["epss_rank_in_month"], code, 40) == want


def test_smd():
    a, b = pd.Series([0.0, 1.0, 2.0]), pd.Series([1.0, 2.0, 3.0])
    assert smd(a, b) == pytest.approx(1.0)
    assert smd(pd.Series([1.0, 1.0]), pd.Series([1.0, 1.0])) == 0.0


@pytest.mark.skipif(not (OUT_DIR / "top500_v3.csv").exists(), reason="top500_v3.csv not produced yet")
@pytest.mark.skipif(not SCOREBOARD_CSV.exists(), reason="needs the untracked datathon data (data/scoreboard_2026.csv) to validate the IDs")
def test_top500_v3_format_and_contributions():
    assert check(OUT_DIR / "top500_v3.csv") == []
    ids = pd.read_csv(OUT_DIR / "top500_v3.csv")["cve_id"].tolist()
    contrib = pd.read_parquet(OUT_DIR / "v3_top500_contrib.parquet")
    assert list(contrib.columns) == ["cve_id", *FEATURES_V2]
    assert contrib["cve_id"].tolist() == ids
