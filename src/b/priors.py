"""Person B, issue #12 follow-up: time-safe "track record" priors for every CVE in the pools.

Run:  python -m src.b.priors          -> outputs/b_priors.parquet (cve_id, pool, product_kev_count_max,
                                         product_kev_12m_max, knn_kev_rate)

For pool year Y the history cutoff is Dec 31 of Y-1 (CONTRACT.md, issue #5), the same as every other KEV-based feature.

product_kev_count_max / product_kev_12m_max
    KEV *product* names with date_added <= cutoff (e.g. "FortiOS", "Exchange Server", "PAN-OS") are matched as whole
    words in the description (post-attack phrases stripped). Names found in > 0.5% of earlier history descriptions are
    dropped as generic words. Value = log1p of the largest KEV count among the products
    mentioned (all-time / last 12 months before the cutoff). Mirrors Person A's vendor features one level down.
knn_kev_rate
    Among the K=50 most similar earlier CVEs (cosine on the Granite embeddings; candidates = the embedded history sample
    + KEV entries published before 2024-01-01, the same set for every pool), the share on KEV by the pool's cutoff. The candidate set over-samples
    KEV (all KEV entries, a 40K sample of the rest), so the level is inflated; only the ranking within a pool matters.

Why not the Granite chat labels (src.b.extract)? That set was partly chosen BY LABEL (every exploited replica CVE was added
for the descriptive blind-spot profile), so whether a CVE has a label would leak the answer. These priors cover every CVE.
"""
import re

import numpy as np
import pandas as pd

from src.b.phrases import strip_post_attack
from src.common.paths import DATA_DIR, OUT_DIR
from src.features.build import normalize, vendor_features

K = 50
GENERIC_SHARE = 0.005   # a product name in > 0.5% of history descriptions is a common word, not a product
CAND_END = pd.Timestamp("2024-01-01")
CHUNK = 2000
PRODUCT_STOP = {"multiple products", "multiple chipsets", "multiple devices", "mobile devices", "multiple", "products",
                "devices", "server", "software", "application", "firmware", "router", "routers", "kernel", "windows"}
MIN_LEN = 5
POOLS = {2024: "replica_2024.parquet", 2025: "replica_2025.parquet", 2026: "scoreboard_features.parquet"}


def product_names(product: str) -> list[str]:
    """'iOS, iPadOS, and macOS' -> ['ios', 'ipados', 'macos']; generic or too-short names are dropped."""
    p = re.sub(r"\(.*?\)", " ", str(product))
    parts = re.split(r",|\band\b|/", p)
    out = []
    for x in parts:
        n = normalize(pd.Series([x]))[0]
        if len(n) >= MIN_LEN and n not in PRODUCT_STOP:
            out.append(n)
    return out


def product_lexicon(kev: pd.DataFrame, cutoff, history_desc: pd.Series | None = None) -> pd.DataFrame:
    """KEV products known by the cutoff -> DataFrame[vendor (= product phrase, to reuse vendor_features), kev_count, kev_12m].
    Generic names ('platform', 'project', 'framework', ...) are dropped data-first: any name found in more than
    GENERIC_SHARE of the history descriptions (all published before the cutoff) is too common to identify a product."""
    cutoff = pd.Timestamp(cutoff)
    k = kev.assign(date_added=pd.to_datetime(kev["date_added"]))
    k = k[k["date_added"] <= cutoff]
    rows = [(n, d) for prod, d in zip(k["product"], k["date_added"]) for n in product_names(prod)]
    t = pd.DataFrame(rows, columns=["vendor", "date_added"])
    lex = t.groupby("vendor").agg(kev_count=("date_added", "size"),
                                  kev_12m=("date_added", lambda s: int((s > cutoff - pd.DateOffset(months=12)).sum()))).reset_index()
    if history_desc is not None and len(history_desc):
        h = " " + normalize(history_desc) + " "
        share = lex["vendor"].map(lambda n: h.str.contains(f" {n} ", regex=False).mean())
        lex = lex[share <= GENERIC_SHARE].reset_index(drop=True)
    return lex


def product_features(desc: pd.Series, kev: pd.DataFrame, cutoff, history_desc=None) -> pd.DataFrame:
    f = vendor_features(desc.map(strip_post_attack), product_lexicon(kev, cutoff, history_desc))
    return f.rename(columns={"n_vendors_mentioned": "n_products_mentioned", "vendor_kev_count_max": "product_kev_count_max",
                             "vendor_kev_12m_max": "product_kev_12m_max"})


def knn_kev_rate(target_ids, year: int, emb, row, texts, k=K) -> np.ndarray:
    """Share of the k nearest earlier CVEs (history sample + KEV, published < year-01-01) on KEV by Dec 31 of year-1."""
    # same candidate CVEs for every pool (published before CAND_END), so the neighbourhoods don't drift between years;
    # only the KEV labels move forward with each pool's cutoff
    cut_pub, cut_kev = min(pd.Timestamp(f"{year}-01-01"), CAND_END), pd.Timestamp(f"{year - 1}-12-31")
    cand = texts[texts["role"].isin(["history", "kev"]) & (texts["published"] < cut_pub)]
    y = (cand["kev_date_added"].notna() & (cand["kev_date_added"] <= cut_kev)).to_numpy(dtype=float)
    Cm = emb[row.loc[cand["cve_id"]].to_numpy()]
    T = emb[row.loc[target_ids].to_numpy()]
    out = np.empty(len(T))
    for s in range(0, len(T), CHUNK):
        S = T[s:s + CHUNK] @ Cm.T
        kk = min(k, S.shape[1])
        idx = np.argpartition(-S, kk - 1, axis=1)[:, :kk]
        out[s:s + CHUNK] = y[idx].mean(axis=1)
    return out


def build(out_dir=OUT_DIR, data_dir=DATA_DIR) -> pd.DataFrame:
    texts = pd.read_parquet(out_dir / "b_texts.parquet")
    texts["published"] = pd.to_datetime(texts["published"])
    texts["kev_date_added"] = pd.to_datetime(texts["kev_date_added"])
    emb = np.load(out_dir / "emb_small.npy")
    row = pd.Series(np.arange(len(emb)), index=pd.read_csv(out_dir / "emb_ids.csv")["cve_id"])
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "product", "date_added"])
    desc = texts.set_index("cve_id")["description"]
    parts = []
    for y, f in POOLS.items():
        ids = pd.read_parquet(out_dir / f, columns=["cve_id"])["cve_id"]
        d = pd.DataFrame({"cve_id": ids.to_numpy(), "pool": y})
        hist = texts[(texts["role"] == "history") & (texts["published"] < pd.Timestamp(f"{y}-01-01"))]["description"]
        pf = product_features(desc.reindex(ids).fillna("").reset_index(drop=True), kev, f"{y - 1}-12-31", hist)
        d = pd.concat([d, pf[["product_kev_count_max", "product_kev_12m_max"]]], axis=1)
        d["knn_kev_rate"] = knn_kev_rate(ids, y, emb, row, texts)
        parts.append(d)
        print(f"{y}: {len(d):,} CVEs, {(pf['n_products_mentioned'] > 0).mean():.1%} mention a past-KEV product, "
              f"knn_kev_rate median {d['knn_kev_rate'].median():.3f}")
    out = pd.concat(parts, ignore_index=True)
    out.to_parquet(out_dir / "b_priors.parquet", index=False)
    return out


if __name__ == "__main__":
    build()
