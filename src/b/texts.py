"""Person B, step 1: collect the descriptions we need to embed.

Run:  python -m src.b.texts

Writes outputs/b_texts.parquet with one row per CVE:
  cve_id, published (date), description, kev_date_added (date or null), role
role is one of: kev, replica_2024, replica_2025, scoreboard, history
  kev          every CVE on the KEV list (needed for nearest-KEV similarity)
  replica_Y    every CVE in Person A's replica pools (targets)
  scoreboard   the 72,670 2026 CVEs (targets)
  history      a random sample of older non-KEV CVEs (published 2018-01-01..2023-12-31),
               used only as negatives when training the text classifier

Only `description` and `published` come from vulnerabilities.csv. No banned columns are read.
Post-attack phrases ("exploited in the wild", ...; see src/b/phrases.py) are removed from every
description here, BEFORE embedding, so they can't leak the label into any text feature.
The output is gitignored (it holds full descriptions); it is an intermediate file, not a contract file.
"""
import argparse

import duckdb
import pandas as pd

from src.b.phrases import strip_post_attack
from src.common.paths import DATA_DIR, OUT_DIR, SCOREBOARD_CSV

N_HISTORY = 40_000
SEED = 0


def main(n_history: int = N_HISTORY) -> pd.DataFrame:
    con = duckdb.connect()
    vuln = con.execute(f"""
        SELECT cve_id, CAST(published AS DATE) AS published, description
        FROM read_csv_auto('{DATA_DIR / "vulnerabilities.csv"}', quote='"', escape='"')
    """).df()
    kev = con.execute(f"""
        SELECT cve_id, CAST(date_added AS DATE) AS kev_date_added
        FROM read_csv_auto('{DATA_DIR / "known_exploited.csv"}')
    """).df()
    sb = pd.read_csv(SCOREBOARD_CSV, usecols=["cve_id"])
    vuln["published"] = pd.to_datetime(vuln["published"])
    kev["kev_date_added"] = pd.to_datetime(kev["kev_date_added"])

    roles = []
    roles.append(kev[["cve_id"]].assign(role="kev"))
    for y in (2024, 2025):
        p = OUT_DIR / f"replica_{y}.parquet"
        if not p.exists():
            raise SystemExit(f"Missing {p}. Pull Person A's replica files first.")
        ids = pd.read_parquet(p, columns=["cve_id"]).drop_duplicates()
        roles.append(ids.assign(role=f"replica_{y}"))
    roles.append(sb.assign(role="scoreboard"))

    taken = set(pd.concat(roles)["cve_id"])
    hist = vuln[(vuln["published"] >= pd.Timestamp("2018-01-01"))
                & (vuln["published"] <= pd.Timestamp("2023-12-31"))
                & ~vuln["cve_id"].isin(taken)]
    hist = hist.sample(n=min(n_history, len(hist)), random_state=SEED)
    roles.append(hist[["cve_id"]].assign(role="history"))

    # A CVE can be both 'kev' and a target; keep the target role so each id appears once.
    order = {"scoreboard": 0, "replica_2025": 1, "replica_2024": 2, "kev": 3, "history": 4}
    r = pd.concat(roles, ignore_index=True)
    r["o"] = r["role"].map(order)
    r = r.sort_values(["o", "cve_id"]).drop_duplicates("cve_id").drop(columns="o")

    out = (r.merge(vuln, on="cve_id", how="left")
             .merge(kev, on="cve_id", how="left"))
    missing = out["description"].isna().sum()
    out["description"] = out["description"].fillna("").astype(str)
    stripped = out["description"].map(strip_post_attack)
    changed = stripped != out["description"]
    out["description"] = stripped
    print("descriptions with post-attack phrases removed, by role:")
    print(changed.groupby(out["role"]).sum().to_string())
    out = out.sort_values("cve_id").reset_index(drop=True)
    OUT_DIR.mkdir(exist_ok=True)
    out.to_parquet(OUT_DIR / "b_texts.parquet", index=False)
    print(out["role"].value_counts().to_string())
    print(f"total {len(out):,} rows, {missing:,} with no description")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-history", type=int, default=N_HISTORY)
    main(ap.parse_args().n_history)
