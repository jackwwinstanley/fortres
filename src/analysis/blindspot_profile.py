"""Blind-spot profile: DESCRIPTIVE ONLY, NOT USED FOR MODEL DESIGN.
Positives (both replicas) that are invisible to exploit flags and EPSS: no public exploit flag AND within-month EPSS
rank below the cut a top-k EPSS list would make. The KEV vendor and the days to KEV are post-snapshot facts and are
never features. Run after train_v2:  python -m src.analysis.blindspot_profile
"""
import duckdb
import pandas as pd

from src.analysis.depth_curves import blind_mask
from src.common.paths import DATA_DIR, OUT_DIR
from src.common.scoring import k_for_pool
from src.models.train_v1 import md
from src.models.train_v2 import load_with_text


def build(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, _, _ = load_with_text(out_dir, data_dir)
    con = duckdb.connect()
    vuln = con.execute(f"SELECT cve_id, assigner FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true)").df()
    kev = con.execute(f"SELECT cve_id, vendor AS kev_vendor, CAST(date_added AS DATE) AS date_added "
                      f"FROM read_csv_auto('{data_dir}/known_exploited.csv', all_varchar=true)").df()
    parts = []
    for y in (2024, 2025):
        m = data[y]["meta"]
        k = k_for_pool(len(m))
        sel = m[(m["label"] == 1) & blind_mask(m, k)].assign(replica=y)
        parts.append(sel)
    d = pd.concat(parts).merge(vuln, on="cve_id", how="left").merge(kev, on="cve_id", how="left")
    eom = pd.to_datetime(d["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0)
    d["days_to_kev"] = (pd.to_datetime(d["date_added"]) - eom).dt.days
    cols = ["cve_id", "replica", "kev_vendor", "assigner", "days_to_kev", "kev_text_score", "assigner_kev_rate_smooth",
            "vendor_kev_count_max", "nearest_kev_sim"]
    out = d[cols].sort_values(["replica", "cve_id"]).reset_index(drop=True)
    out.round({"kev_text_score": 4, "assigner_kev_rate_smooth": 5, "vendor_kev_count_max": 3, "nearest_kev_sim": 4}).to_csv(
        out_dir / "blindspot_positives.csv", index=False)
    return out, d


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    out, d = build(out_dir, data_dir)
    L = ["### Blind-spot profile (descriptive, not used for model design)", "",
         f"{len(out)} positives across both replicas have no public exploit flag and a within-month EPSS rank below the "
         "top-k EPSS cut. Vendor and days-to-KEV are post-snapshot facts shown for description only.", ""]
    L += ["Top KEV vendors:", "", md(["KEV vendor", "positives"], list(out["kev_vendor"].value_counts().head(8).items())), ""]
    L += ["Top assigners:", "", md(["assigner", "positives"], list(out["assigner"].value_counts().head(8).items())), ""]
    q = out["days_to_kev"].quantile([0.25, 0.5, 0.75])
    L += [f"Days from the end of the snapshot month to KEV `date_added`: median {q[0.5]:.0f}, IQR {q[0.25]:.0f} to {q[0.75]:.0f} "
          f"(min {out['days_to_kev'].min()}, max {out['days_to_kev'].max()}).", ""]
    share = d.groupby(["replica", "snapshot_month"]).size().rename("n").reset_index()
    share["share"] = share["n"] / share.groupby("replica")["n"].transform("sum")
    L += ["Share by snapshot month:", "",
          md(["replica", "month", "positives", "share of replica's blind-spot positives"],
             [(r.replica, r.snapshot_month, r.n, f"{r.share:.0%}") for r in share.itertuples()]), ""]
    sc = out[["kev_text_score", "assigner_kev_rate_smooth", "vendor_kev_count_max", "nearest_kev_sim"]]
    L += ["Median prior scores of these positives vs the whole pool (descriptive):", ""]
    data, _, _ = load_with_text(out_dir, data_dir)
    pool = pd.concat([data[2024]["meta"], data[2025]["meta"]])
    L += [md(["score", "blind-spot positives (median)", "all CVEs (median)"],
             [(c, f"{sc[c].median():.4f}", f"{pool[c].median():.4f}") for c in sc.columns]), ""]
    (out_dir / ".cache" / "v2_blindspot.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
