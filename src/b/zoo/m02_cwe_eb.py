"""m02 empirical-Bayes CWE shrinkage. Fit on the training year only: per CWE, posterior KEV rate (k + a*p0) / (n + a), with p0 the
training-year base rate and a the beta-binomial prior strength from the method of moments over CWEs with n >= 20.
A CVE's score = max posterior over its CWE ids; no CWE (or NVD-CWE-noinfo/Other only) -> p0 (missingness is NOT a category).
Check only (not a feature): CWE missingness by nvd_status per pool -> outputs/zoo/m02_cwe_missingness_check.csv."""
import numpy as np
import pandas as pd

from src.b.zoo import harness as H

NOINFO = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def _cw(lst):
    return [c for c in lst if c not in NOINFO]


def table(train):
    rows = {}
    for cws, y in zip(train.cwe, train.y):
        for c in set(_cw(cws)):
            n, k = rows.get(c, (0, 0))
            rows[c] = (n + 1, k + int(y))
    p0 = float(train.y.mean())
    t = pd.DataFrame(rows, index=["n", "k"]).T
    big = t[t["n"] >= 20]
    r = big["k"] / big["n"]
    m, v = float(np.average(r, weights=big["n"])), float(np.average((r - np.average(r, weights=big["n"])) ** 2, weights=big["n"]))
    a = m * (1 - m) / v - 1 if v > 0 and m * (1 - m) / v - 1 > 0 else 100.0
    t["post"] = (t["k"] + a * p0) / (t["n"] + a)
    return t["post"].to_dict(), p0, a


def score(train, apply, seed, env):
    post, p0, a = table(train)
    return np.array([max([post.get(c, p0) for c in _cw(cws)], default=p0) for cws in apply.cwe])


def feature(train, apply, seed, env):
    return pd.DataFrame({"cwe_eb_rate": score(train, apply, seed, env)})


def check():
    pools, _, _ = H.load()
    rows = []
    for k in (2024, 2025, "sb"):
        p = pools[k]
        miss = np.array([len(_cw(c)) == 0 for c in p.cwe])
        st = H.nvd_status_check_only(p.cve_id)
        for s in sorted(set(st)):
            m = st == s
            rows.append({"pool": p.name, "nvd_status": s, "n": int(m.sum()), "cwe_missing_share": round(float(miss[m].mean()), 4),
                         "positives": None if p.y is None else int(p.y[m].sum())})
    H.ZOO.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(H.ZOO / "m02_cwe_missingness_check.csv", index=False)


if __name__ == "__main__":
    check()
    H.run_method("m02_cwe_eb", score_fn=score, feature_fn=feature, deterministic=True, coverage_fn=feature)
