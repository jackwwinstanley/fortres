"""Build the v1 allowed-column feature tables.  Run:  python -m src.features.build

Time-safety (see CONTRACT.md): every KEV-based history feature uses a FIXED cutoff of
December 31 of the year before the pool year (2024 -> 2023-12-31, 2025 -> 2024-12-31,
2026 scoreboard -> 2025-12-31). Nothing from KEV after the cutoff, and no 2026 KEV info, is used.
Description text is read only to find vendor mentions and is never saved.
"""
import re

import duckdb
import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import ALLOWED_FEATURES

SMOOTH = 20  # pseudo-count for the smoothed assigner KEV rate
GENERIC_WORDS = {"inc", "corp", "corporation", "ltd", "llc", "co", "company", "gmbh", "plc",
                 "limited", "the", "group", "package"}
AMBIGUOUS_VENDORS = {"linux", "git", "perl", "progress", "quest", "elastic", "rails", "versa",
                     "checkbox", "pear", "plex", "cleo", "sudo"}
MIN_VENDOR_LEN = 4


def normalize(s: pd.Series) -> pd.Series:
    """lowercase, non-alphanumerics -> single space (used for BOTH vendors and descriptions)."""
    return s.fillna("").str.lower().str.replace(r"[^a-z0-9]+", " ", regex=True).str.strip()


def clean_vendor(v: str) -> str:
    v = re.sub(r"\(.*?\)", " ", str(v))
    toks = [t for t in normalize(pd.Series([v]))[0].split() if t not in GENERIC_WORDS]
    return " ".join(toks)


# ---- signals / timing -------------------------------------------------------------------------
def signal_features(df: pd.DataFrame) -> pd.DataFrame:
    """epss_rank_in_month: percentile rank of epss within the same snapshot_month of THIS pool
    (missing = 0); this normalises across the March 2025 EPSS model change."""
    out = pd.DataFrame(index=df.index)
    out["epss"] = df["epss"].astype("float64")
    out["epss_missing"] = df["epss"].isna().astype("int8")
    out["epss_rank_in_month"] = (
        df.groupby("snapshot_month")["epss"].rank(pct=True, method="average").fillna(0.0))
    flags = ["exploitdb", "metasploit", "nuclei", "poc_github"]
    for f in flags:
        out[f] = df[f].astype("int8")
    out["n_flags"] = df[flags].sum(axis=1).astype("int8")
    out["any_exploit"] = df[flags].max(axis=1).astype("int8")
    out["days_to_snapshot"] = df["days_to_snapshot"].astype("int32")
    out["days_to_cutoff"] = df["days_to_cutoff"].astype("int32")
    return out


# ---- assigner history -------------------------------------------------------------------------
def assigner_features(pool: pd.DataFrame, vuln: pd.DataFrame, kev: pd.DataFrame, cutoff) -> pd.DataFrame:
    """pool needs cve_id; vuln: cve_id, published, assigner; kev: cve_id, date_added.
    All counts are as of `cutoff` (inclusive)."""
    cutoff = pd.Timestamp(cutoff)
    v = vuln.assign(assigner=vuln["assigner"].fillna("unknown"), published=pd.to_datetime(vuln["published"]))
    prior = v[v["published"] <= cutoff].groupby("assigner").size().rename("prior")
    k = kev.assign(date_added=pd.to_datetime(kev["date_added"])).merge(v[["cve_id", "assigner"]], on="cve_id")
    k = k[k["date_added"] <= cutoff]
    kev_n = k.groupby("assigner").size().rename("kev")
    kev_12 = k[k["date_added"] > cutoff - pd.DateOffset(months=12)].groupby("assigner").size().rename("kev12")
    global_rate = len(k) / max(1, int((v["published"] <= cutoff).sum()))
    a = v.set_index("cve_id")["assigner"].reindex(pool["cve_id"]).fillna("unknown").to_numpy()
    t = pd.DataFrame({"assigner": a}).join(prior, on="assigner").join(kev_n, on="assigner").join(kev_12, on="assigner")
    t = t.fillna({"prior": 0, "kev": 0, "kev12": 0})
    out = pd.DataFrame(index=pool.index)
    out["assigner_prior_cves"] = np.log1p(t["prior"].to_numpy())
    out["assigner_kev_count"] = np.log1p(t["kev"].to_numpy())
    out["assigner_kev_12m"] = np.log1p(t["kev12"].to_numpy())
    out["assigner_kev_rate_smooth"] = (t["kev"].to_numpy() + SMOOTH * global_rate) / (t["prior"].to_numpy() + SMOOTH)
    return out


# ---- vendor history ---------------------------------------------------------------------------
def vendor_lexicon(kev: pd.DataFrame, cutoff):
    """Return (lexicon DataFrame[vendor, kev_count, kev_12m], dropped DataFrame[vendor, reason])."""
    cutoff = pd.Timestamp(cutoff)
    k = kev.assign(date_added=pd.to_datetime(kev["date_added"]))
    k = k[k["date_added"] <= cutoff].assign(v=lambda d: d["vendor"].map(clean_vendor))
    g = k.groupby("v").agg(kev_count=("cve_id", "size"),
                           kev_12m=("date_added", lambda s: int((s > cutoff - pd.DateOffset(months=12)).sum())))
    dropped = []
    keep = []
    for v, row in g.iterrows():
        if len(v) < MIN_VENDOR_LEN:
            dropped.append((v, f"shorter than {MIN_VENDOR_LEN} characters"))
        elif v in AMBIGUOUS_VENDORS:
            dropped.append((v, "ambiguous word (stoplist)"))
        else:
            keep.append(v)
    lex = g.loc[keep].reset_index().rename(columns={"v": "vendor"})
    return lex, pd.DataFrame(dropped, columns=["vendor", "reason"])


def vendor_features(descriptions: pd.Series, lex: pd.DataFrame) -> pd.DataFrame:
    """Whole-word (token-bounded) vendor mentions. 'cisco' matches 'Cisco IOS' and "Cisco's",
    but not 'ciscoworks'. Vectorised with one compiled alternation (longest vendor first)."""
    out = pd.DataFrame(index=descriptions.index)
    if lex.empty:
        out["n_vendors_mentioned"] = 0
        out["vendor_kev_count_max"] = 0.0
        out["vendor_kev_12m_max"] = 0.0
        return out
    names = sorted(lex["vendor"], key=len, reverse=True)
    pat = re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(n) for n in names) + r")(?![a-z0-9])")
    found = normalize(descriptions).str.findall(pat)
    cnt = dict(zip(lex["vendor"], np.log1p(lex["kev_count"])))
    c12 = dict(zip(lex["vendor"], np.log1p(lex["kev_12m"])))
    out["n_vendors_mentioned"] = found.map(lambda m: len(set(m)))
    out["vendor_kev_count_max"] = found.map(lambda m: max((cnt[x] for x in m), default=0.0))
    out["vendor_kev_12m_max"] = found.map(lambda m: max((c12[x] for x in m), default=0.0))
    return out


def build_features(pool: pd.DataFrame, vuln: pd.DataFrame, kev: pd.DataFrame, cutoff):
    """pool: contract columns of a replica/scoreboard file. Returns (features DataFrame, dropped vendors)."""
    sig = signal_features(pool)
    asg = assigner_features(pool, vuln, kev, cutoff)
    lex, dropped = vendor_lexicon(kev, cutoff)
    desc = vuln.set_index("cve_id")["description"].reindex(pool["cve_id"]).set_axis(pool.index)
    ven = vendor_features(desc, lex)
    keep = [c for c in ["cve_id", "snapshot_month", "published", "label"] if c in pool]
    out = pd.concat([pool[keep], sig, asg, ven], axis=1)
    return out[keep + ALLOWED_FEATURES], dropped


def main(data_dir=DATA_DIR, out_dir=OUT_DIR):
    con = duckdb.connect()
    vuln = con.execute(f"SELECT cve_id, CAST(published AS DATE) AS published, assigner, description "
                       f"FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)").df()
    kev = con.execute(f"SELECT cve_id, vendor, CAST(date_added AS DATE) AS date_added "
                      f"FROM read_csv_auto('{data_dir}/known_exploited.csv', all_varchar=true)").df()
    jobs = [("replica_2024", "features_replica_2024", "2023-12-31"),
            ("replica_2025", "features_replica_2025", "2024-12-31"),
            ("scoreboard_features", "features_scoreboard", "2025-12-31")]
    drops = []
    for src, dst, cutoff in jobs:
        pool = pd.read_parquet(out_dir / f"{src}.parquet")
        feats, dropped = build_features(pool, vuln, kev, cutoff)
        feats.to_parquet(out_dir / f"{dst}.parquet", index=False)
        drops.append(dropped.assign(cutoff=cutoff))
        print(f"{dst}: {len(feats):,} rows, history cutoff {cutoff}, "
              f"{int((feats['n_vendors_mentioned'] > 0).sum()):,} rows mention a KEV vendor")
    d = pd.concat(drops).drop_duplicates(["vendor", "reason"])
    d.to_csv(out_dir / "vendor_lexicon_dropped.csv", index=False)
    print(f"vendors dropped from lexicon ({len(d)}): " + ", ".join(sorted(set(d['vendor']))))


if __name__ == "__main__":
    main()
