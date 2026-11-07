"""Person B, step 3: build outputs/text_features.parquet (contract file).

Run:  python -m src.b.text_features

Columns: cve_id, kev_text_score, nearest_kev_sim, txt_* (int8 regex flags). One row per target
CVE (replica_2024, replica_2025 and the 2026 scoreboard), unique cve_id.

TIME-SAFETY (see CONTRACT.md):
  kev_text_score   For target year Y, a logistic regression on Granite embeddings is trained
                   only on CVEs published before Y-01-01, labelled 1 if KEV date_added
                   <= (Y-1)-12-31. One model per Y in {2024, 2025, 2026}.
  nearest_kev_sim  For target year Y, the max cosine similarity between its description and KEV
                   entries with date_added <= (Y-1)-12-31 (the shared cutoff from issue #5:
                   2023-12-31 for replica 2024, 2024-12-31 for replica 2025, 2025-12-31 for the
                   2026 scoreboard), excluding the target CVEs themselves.
  txt_* flags      Regexes on the description only.
  Post-attack phrases ("exploited in the wild", ...) are stripped from the text in texts.py
  BEFORE embedding; this script asserts none are left.
Every cve_id in replica_2024, replica_2025 and scoreboard_features must get a row (asserted).
Limit: descriptions are the current NVD text and can be edited after publication.
"""
import re

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from src.b.phrases import POST_ATTACK
from src.common.paths import OUT_DIR

FLAGS = {
    "txt_rce": r"remote code execution|execute arbitrary (code|commands)|arbitrary code execution",
    "txt_unauth": r"unauthenticated|without authentication|no authentication|remote attacker without",
    "txt_auth_bypass": r"authentication bypass|bypass (the )?authentication|bypass authorization",
    "txt_cmd_injection": r"command injection|os command|inject (arbitrary )?commands",
    "txt_deserialization": r"deserializ",
    "txt_path_traversal": r"path traversal|directory traversal|\.\./",
    "txt_sqli": r"sql injection",
    "txt_priv_esc": r"privilege escalation|escalate privileges|elevation of privilege",
    "txt_memory": r"use[- ]after[- ]free|buffer overflow|out[- ]of[- ]bounds write|heap overflow|type confusion",
    "txt_edge_device": r"\bvpn\b|firewall|gateway|router|load balancer|ssl[- ]vpn|remote access",
    "txt_enterprise": r"exchange server|sharepoint|confluence|vcenter|esxi|netscaler|citrix|fortios|fortigate|"
                      r"pan-os|ivanti|sonicwall|big-ip|moveit|jenkins|weblogic|windows",
    "txt_browser": r"chrome|chromium|firefox|safari|webkit|edge browser|v8\b",
    "txt_wordpress": r"wordpress|wp plugin|plugin for wordpress",
    "txt_xss": r"cross[- ]site scripting|\bxss\b",
}


def _targets() -> pd.DataFrame:
    parts = []
    for y in (2024, 2025):
        d = pd.read_parquet(OUT_DIR / f"replica_{y}.parquet", columns=["cve_id", "snapshot_month"])
        parts.append(d.drop_duplicates("cve_id").assign(year=y))
    sb = pd.read_parquet(OUT_DIR / "scoreboard_features.parquet", columns=["cve_id", "snapshot_month"])
    parts.append(sb.assign(year=2026))
    t = pd.concat(parts, ignore_index=True)
    assert t["cve_id"].is_unique, "a CVE appears in two target sets"
    return t


def main():
    texts = pd.read_parquet(OUT_DIR / "b_texts.parquet")
    emb = np.load(OUT_DIR / "emb_small.npy")
    ids = pd.read_csv(OUT_DIR / "emb_ids.csv")["cve_id"]
    assert len(ids) == emb.shape[0]
    row = pd.Series(np.arange(len(ids)), index=ids)
    texts = texts.set_index("cve_id").loc[ids].reset_index()
    texts["published"] = pd.to_datetime(texts["published"])
    texts["kev_date_added"] = pd.to_datetime(texts["kev_date_added"])

    tg = _targets()
    tg = tg[tg["cve_id"].isin(row.index)].copy()
    tg["i"] = row.loc[tg["cve_id"]].to_numpy()
    tg["kev_text_score"] = np.nan
    tg["nearest_kev_sim"] = np.nan

    for y in (2024, 2025, 2026):
        cut_pub = pd.Timestamp(f"{y}-01-01")
        cut_kev = pd.Timestamp(f"{y - 1}-12-31")
        tr = texts[(texts["published"] < cut_pub)
                   & ~(texts["cve_id"].isin(tg.loc[tg["year"] == y, "cve_id"]))]
        ytr = (tr["kev_date_added"].notna() & (tr["kev_date_added"] <= cut_kev)).astype(int)
        Xtr = emb[row.loc[tr["cve_id"]].to_numpy()]
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000)
        clf.fit(Xtr, ytr)
        m = tg["year"] == y
        tg.loc[m, "kev_text_score"] = clf.predict_proba(emb[tg.loc[m, "i"].to_numpy()])[:, 1]
        print(f"{y}: trained on {len(tr):,} CVEs published < {cut_pub.date()}, "
              f"{ytr.sum():,} KEV-positive as of {cut_kev.date()}")

    kev = texts[texts["kev_date_added"].notna()]
    for y, g in tg.groupby("year"):
        cut_kev = pd.Timestamp(f"{y - 1}-12-31")
        k = kev[(kev["kev_date_added"] <= cut_kev) & ~kev["cve_id"].isin(g["cve_id"])]
        K = emb[row.loc[k["cve_id"]].to_numpy()]
        X = emb[g["i"].to_numpy()]
        tg.loc[g.index, "nearest_kev_sim"] = (X @ K.T).max(axis=1) if len(K) else 0.0
        print(f"{y}: nearest_kev_sim against {len(k):,} KEV entries added <= {cut_kev.date()}")

    desc = texts.set_index("cve_id").loc[tg["cve_id"], "description"].str.lower().to_numpy()
    for name, pat in FLAGS.items():
        rx = re.compile(pat, re.I)
        tg[name] = np.fromiter((bool(rx.search(d)) for d in desc), dtype=bool, count=len(desc)).astype("int8")
    n_banned = sum(bool(POST_ATTACK.search(d)) for d in desc)
    print(f"{n_banned:,} target descriptions still contain post-attack phrases (expected 0)")

    out = tg[["cve_id", "kev_text_score", "nearest_kev_sim", *FLAGS]].copy()
    missing = set(_targets()["cve_id"]) - set(out["cve_id"])
    assert not missing, f"{len(missing):,} target CVEs have no text features, e.g. {sorted(missing)[:5]}"
    out["kev_text_score"] = out["kev_text_score"].astype("float64")
    out["nearest_kev_sim"] = out["nearest_kev_sim"].astype("float64")
    out = out.sort_values("cve_id").reset_index(drop=True)
    out.to_parquet(OUT_DIR / "text_features.parquet", index=False)
    print(f"wrote text_features.parquet: {len(out):,} rows")
    return out


if __name__ == "__main__":
    main()
