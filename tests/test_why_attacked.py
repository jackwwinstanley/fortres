import math

import numpy as np
import pandas as pd
import pytest

from src.analysis.why_attacked import filter_min_count, rate_table, wilson_interval


def test_wilson_known_values():
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = wilson_interval(5, 10)
    assert (lo, hi) == (pytest.approx(0.2366, abs=1e-3), pytest.approx(0.7634, abs=1e-3))
    lo, hi = wilson_interval(10, 10)
    assert lo == pytest.approx(0.7225, abs=1e-3) and hi == 1.0
    lo, hi = wilson_interval(577, 129208)
    assert lo < 577 / 129208 < hi


def test_wilson_edge_cases_and_monotonic_width():
    assert all(math.isnan(x) for x in wilson_interval(0, 0))
    w = lambda n: np.subtract(*wilson_interval(n // 10, n)[::-1])  # noqa: E731
    assert w(100) > w(1000) > w(10000)       # more data, narrower interval


def test_min_count_filter_boundaries():
    t = pd.DataFrame({"category": list("abcdefg"), "n": [200, 199, 50, 5000, 199, 9, 10], "attacked": [0, 9, 10, 0, 10, 9, 10]})
    kept = set(filter_min_count(t)["category"])
    # a: n=200 kept; b: 199 and 9 dropped; c: 10 attacked kept; d: big n kept; e: 10 attacked kept; f: dropped; g: 10 attacked kept
    assert kept == {"a", "c", "d", "e", "g"}


def test_rate_table_lift_missing_and_ci():
    df = pd.DataFrame({"x": ["a"] * 6 + ["b"] * 4 + [None] * 2, "attacked": [1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0]})
    overall = df["attacked"].mean()      # 3 / 12 = 0.25
    t = rate_table(df, "x", overall).set_index("category")
    assert set(t.index) == {"a", "b", "(missing)"}
    assert t.loc["a", "n"] == 6 and t.loc["a", "attacked"] == 1
    assert t.loc["b", "rate"] == 0.5 and t.loc["b", "lift"] == pytest.approx(2.0)
    assert t.loc["(missing)", "rate"] == 0.0 and t.loc["a", "ci_low"] < t.loc["a", "rate"] < t.loc["a", "ci_high"]
