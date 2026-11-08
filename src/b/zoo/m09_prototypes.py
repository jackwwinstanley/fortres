"""m09 cosine similarity of each description's Granite embedding to 25 fixed attack-mechanism prototype phrases
(src/b/zoo/m09_prototypes.txt, committed before any result). Phrases embedded with the same model as the descriptions
(ibm-granite/granite-embedding-30m-english, local cache); no LLM call over descriptions. Label-free, deterministic.
Standalone score = max similarity. Features = max similarity, mean of the top 3."""
import os
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

from src.b.zoo import harness as H

os.environ.setdefault("HF_HUB_OFFLINE", "1")
PHRASES = [l.strip() for l in (Path(__file__).parent / "m09_prototypes.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]


CACHE_NPY = H.CACHE / "m09_protos.npy"
_EMBED = """
import sys, numpy as np
from sentence_transformers import SentenceTransformer
ph = [l.strip() for l in open(sys.argv[1]).read().splitlines() if l.strip() and not l.startswith("#")]
m = SentenceTransformer("ibm-granite/granite-embedding-30m-english", device="cpu", model_kwargs={"dtype": "float32"})
np.save(sys.argv[2], m.encode(ph, normalize_embeddings=True, convert_to_numpy=True).astype("float32"))
"""


@lru_cache(None)
def protos():
    """Phrase embeddings are made in a SEPARATE process (torch and LightGBM's OpenMP segfault together in one process)."""
    import subprocess
    import sys
    H.CACHE.mkdir(parents=True, exist_ok=True)
    if not CACHE_NPY.exists():
        subprocess.run([sys.executable, "-c", _EMBED, str(Path(__file__).parent / "m09_prototypes.txt"), str(CACHE_NPY)], check=True)
    P = np.load(CACHE_NPY)
    assert P.shape == (len(PHRASES), 384)
    return P


def sims(apply):
    return apply.emb() @ protos().T


def score(train, apply, seed, env):
    return sims(apply).max(1)


def feature(train, apply, seed, env):
    s = np.sort(sims(apply), axis=1)
    return pd.DataFrame({"proto_max": s[:, -1], "proto_top3": s[:, -3:].mean(1)})


if __name__ == "__main__":
    H.run_method("m09_prototypes", score_fn=score, feature_fn=feature, deterministic=True, coverage_fn=feature, params={"n_phrases": len(PHRASES)})
