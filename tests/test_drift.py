import numpy as np
import pandas as pd

from src.b.drift import psi


def test_psi_identical_is_zero():
    x = np.random.default_rng(0).random(5000)
    assert psi(x, x) < 1e-9


def test_psi_detects_shift():
    rng = np.random.default_rng(0)
    a, b = rng.normal(0, 1, 5000), rng.normal(1.5, 1, 5000)
    assert psi(a, b) > 0.25


def test_psi_categorical():
    a = pd.Series(["x"] * 90 + ["y"] * 10)
    assert psi(a, a) < 1e-9
    assert psi(a, pd.Series(["x"] * 10 + ["y"] * 90)) > 0.25
