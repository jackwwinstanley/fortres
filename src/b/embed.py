"""Person B, step 2: embed every description with IBM Granite.

Run:  python -m src.b.embed                # real model
      python -m src.b.embed --limit 500    # quick timing test first
      python -m src.b.embed --fake         # random vectors, for testing the pipeline only

Model: ibm-granite/granite-embedding-30m-english (384 dims, small enough for a laptop CPU).
Writes chunks outputs/emb_small_part{N}.npy (50K rows each) so a crash only loses the current
chunk; re-running skips finished chunks. Then merges into outputs/emb_small.npy (float32,
L2-normalised) + outputs/emb_ids.csv (cve_id, same row order). Both are gitignored.
"""
import argparse
import time

import numpy as np
import pandas as pd

from src.common.paths import OUT_DIR

MODEL = "ibm-granite/granite-embedding-30m-english"
CHUNK = 50_000


def _encoder(fake: bool):
    if fake:
        rng = np.random.default_rng(0)

        def enc(texts):
            v = rng.standard_normal((len(texts), 384)).astype("float32")
            return v / np.linalg.norm(v, axis=1, keepdims=True)
        return enc
    from sentence_transformers import SentenceTransformer
    import torch
    device = "cuda" if torch.cuda.is_available() else ("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"loading {MODEL} on {device}")
    m = SentenceTransformer(MODEL, device=device)

    def enc(texts):
        return m.encode(texts, batch_size=64, normalize_embeddings=True,
                        show_progress_bar=True, convert_to_numpy=True).astype("float32")
    return enc


def main(limit=None, fake=False):
    texts = pd.read_parquet(OUT_DIR / "b_texts.parquet", columns=["cve_id", "description"])
    if limit:
        texts = texts.head(limit)
    enc = _encoder(fake)
    n_chunks = (len(texts) + CHUNK - 1) // CHUNK
    t0 = time.time()
    for i in range(n_chunks):
        part = OUT_DIR / f"emb_small_part{i}.npy"
        if part.exists() and not limit:
            print(f"chunk {i} exists, skipping")
            continue
        sl = texts.iloc[i * CHUNK:(i + 1) * CHUNK]
        np.save(part, enc(sl["description"].tolist()))
        print(f"chunk {i + 1}/{n_chunks} done, {time.time() - t0:,.0f}s elapsed")
    parts = [np.load(OUT_DIR / f"emb_small_part{i}.npy") for i in range(n_chunks)]
    emb = np.vstack(parts)
    assert emb.shape[0] == len(texts), (emb.shape, len(texts))
    if limit:
        print(f"timing test: {len(texts)} rows in {time.time() - t0:.1f}s -> "
              f"~{(time.time() - t0) / len(texts) * 180_000 / 60:.0f} min for 180K rows")
        for i in range(n_chunks):
            (OUT_DIR / f"emb_small_part{i}.npy").unlink()
        return
    np.save(OUT_DIR / "emb_small.npy", emb)
    texts[["cve_id"]].to_csv(OUT_DIR / "emb_ids.csv", index=False)
    print(f"wrote emb_small.npy {emb.shape} and emb_ids.csv")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    ap.add_argument("--fake", action="store_true")
    a = ap.parse_args()
    main(a.limit, a.fake)
