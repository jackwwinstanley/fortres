"""m11 exploit / proof-of-concept tokens in the DESCRIPTION text only (never reference URLs). Patterns fixed now.
Standalone score = number of distinct patterns matched. Features = that count and any-match. Label-free, deterministic."""
import re

import numpy as np
import pandas as pd

from src.b.zoo import harness as H

PATTERNS = [r"\bproof[- ]of[- ]concept\b", r"\bpoc\b", r"\bexploit(?:s|ed|ing|ation|able)?\b", r"\bin the wild\b",
            r"\bactively exploited\b", r"\bpublic(?:ly)? (?:available |released |disclosed )?exploit", r"\bexploit code\b",
            r"\bweaponi[sz]ed\b", r"\bmetasploit\b", r"\bexploit[- ]?db\b", r"\bzero[- ]day\b|\b0[- ]day\b",
            r"\bhas been (?:disclosed|made public|released) to the public\b", r"\bthe exploit has been\b", r"\bmay be used\b.*\battack\b"]
RX = [re.compile(p, re.I) for p in PATTERNS]


def counts(apply):
    return np.array([sum(bool(r.search(d or "")) for r in RX) for d in apply.desc], float)


def score(train, apply, seed, env):
    return counts(apply)


def feature(train, apply, seed, env):
    c = counts(apply)
    return pd.DataFrame({"rx_count": c, "rx_any": (c > 0).astype(float)})


if __name__ == "__main__":
    H.run_method("m11_regex", score_fn=score, feature_fn=feature, deterministic=True, coverage_fn=feature, params={"patterns": PATTERNS})
