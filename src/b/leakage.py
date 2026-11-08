"""Person B, issue #8: LEAKAGE EXPERIMENT. Never used for the submission.

Run:  python -m src.b.leakage

Question: how much better would a model LOOK if it used columns that are only filled in after the
fact (CONTRACT.md "BANNED")? Same data, features, parameter rule and 20-seed rank-averaged bag as Person A's
v5 headline model (src/models/train_v5.py); the only difference is the extra banned columns:
  nvd_status (one-hot), n_affected_cpes, n_references, blank-vs-filled CVSS 3 / CVSS 4 / CWE
  indicators, NVD-sourced CVSS 3 score (cvss3_source == nvd@nist.gov), and reference-link features
  from references.csv (refs tagged "Exploit", refs to exploit hosting sites).
All of these come from today's NVD record, which is updated AFTER exploitation (NVD analyses KEV
CVEs first; exploit links get added), so they partly encode the answer.

Directions: train 2024 -> test 2025 (forward in time) and train 2025 -> test 2024. Hits use Person A's
tie-aware scorer and paired bootstrap. Writes outputs/leakage_results.csv, outputs/b_leakage_report.md.
"""
import duckdb
import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR
from src.common.schema import ALLOWED_FEATURES, SHARE_FEATURES, is_banned
from src.features import drift_fix as dfx
from src.models import stress_v2 as st
from src.models import train_v1 as v1
from src.models.train_v2 import load_with_text
from src.models.train_v4 import BAG_SEEDS, bag

HONEST = list(ALLOWED_FEATURES)  # Person A's v5 set: no raw EPSS, PSI-chosen raw/rank/share transforms
EXPLOIT_HOSTS = r"exploit-db\.com|packetstormsecurity|github\.com|gist\.github|seclists\.org|rapid7\.com"


def banned_columns(ids: pd.Series, data_dir=DATA_DIR) -> pd.DataFrame:
    con = duckdb.connect()
    con.register("ids", pd.DataFrame({"cve_id": ids.unique()}))
    v = con.execute(f"""
        SELECT v.cve_id, nvd_status, TRY_CAST(n_affected_cpes AS DOUBLE) AS n_affected_cpes,
               TRY_CAST(n_references AS DOUBLE) AS n_references,
               TRY_CAST(cvss3_score AS DOUBLE) AS cvss3_score, cvss3_source,
               TRY_CAST(cvss4_score AS DOUBLE) AS cvss4_score, cwe_ids
        FROM read_csv_auto('{data_dir}/vulnerabilities.csv', all_varchar=true) v JOIN ids USING (cve_id)
    """).df()
    r = con.execute(f"""
        SELECT r.cve_id,
               SUM(CASE WHEN tags ILIKE '%exploit%' THEN 1 ELSE 0 END) AS refs_tagged_exploit,
               SUM(CASE WHEN regexp_matches(lower(url), '{EXPLOIT_HOSTS}') THEN 1 ELSE 0 END) AS refs_exploit_host
        FROM read_csv_auto('{data_dir}/references.csv', all_varchar=true, quote='"', escape='"', strict_mode=false, null_padding=true) r JOIN ids USING (cve_id)
        GROUP BY r.cve_id
    """).df()
    d = v.merge(r, on="cve_id", how="left")
    out = pd.DataFrame({"cve_id": d["cve_id"]})
    for s in ["Analyzed", "Awaiting Analysis", "Modified", "Undergoing Analysis", "Received", "Deferred"]:
        out[f"leak_nvd_status_{s.lower().replace(' ', '_')}"] = (d["nvd_status"] == s).astype(float)
    out["leak_n_affected_cpes"] = d["n_affected_cpes"]
    out["leak_n_references"] = d["n_references"]
    out["leak_cvss3_blank"] = d["cvss3_score"].isna().astype(float)
    out["leak_cvss4_blank"] = d["cvss4_score"].isna().astype(float)
    out["leak_cwe_blank"] = d["cwe_ids"].fillna("").isin(["", "[]", "NVD-CWE-noinfo", "NVD-CWE-Other"]).astype(float)
    out["leak_nvd_cvss3_score"] = d["cvss3_score"].where(d["cvss3_source"] == "nvd@nist.gov")
    out["leak_refs_tagged_exploit"] = d["refs_tagged_exploit"].fillna(0).astype(float)
    out["leak_refs_exploit_host"] = d["refs_exploit_host"].fillna(0).astype(float)
    return out


def main(out_dir=OUT_DIR, data_dir=DATA_DIR):
    data, _, _ = load_with_text(out_dir, data_dir)
    for y in (2024, 2025):
        ids = data[y]["meta"]["cve_id"]
        b = banned_columns(ids, data_dir).set_index("cve_id").reindex(ids).reset_index(drop=True)
        f = pd.read_parquet(out_dir / f"features_replica_{y}.parquet").reset_index(drop=True)
        assert f["cve_id"].tolist() == data[y]["meta"]["cve_id"].tolist()
        x4 = dfx.to_v5(pd.concat([data[y]["X2"], f[SHARE_FEATURES]], axis=1))[HONEST].reset_index(drop=True)
        data[y]["XL"] = pd.concat([x4, b], axis=1)
    leaky = HONEST + [c for c in data[2024]["XL"].columns if c.startswith("leak_")]
    assert not any(c.startswith("leak_") for c in HONEST)

    rows, imps, blind_rows = [], [], []
    for name, tr, te, note in v1.DIRECTIONS:
        Xtr, ytr, Xte = data[tr]["XL"], data[tr]["y"], data[te]["XL"]
        # Person A's pre-set rule: params chosen by pooled leave-one-month-out AP on the TRAINING replica (v5 features),
        # reused unchanged for the leaky model so the only difference is the extra columns.
        params, _, _ = v1.select_lgbm(Xtr[HONEST], ytr, data[tr]["groups"], HONEST, f"v5 train {tr}")
        scores = {}
        for label, feats in (("honest", HONEST), ("leaky", leaky)):
            models = [v1.lgbm_model(params, feats, seed=s).fit(Xtr[feats], ytr) for s in BAG_SEEDS]
            scores[label] = bag([m.predict_proba(Xte[feats])[:, 1] for m in models])
            if label == "leaky":
                g = pd.Series(np.mean([m.booster_.feature_importance("gain") for m in models], axis=0), index=feats)
                imps.append((g / g.sum()).rename(name))
        # blind-spot breakdown of the HONEST bag (= Person A's v5 headline model): positives in the top k, by group
        meta = data[te]["meta"]
        blind_rows.extend(blind_breakdown(te, meta, scores["honest"]))
        res, _, names, k = v1.eval_frame(data[te]["meta"], scores)
        for n in names:
            r = res[n]
            rows.append(dict(direction=name, replica=te, note=note, k=k, positives=int(data[te]["y"].sum()),
                             model=n, hits=r["arbitrary"], expected=round(r["expected"], 2),
                             ci_lo=r["ci"][0], ci_hi=r["ci"][1], ap=round(r["ap"], 4)))
    out = pd.DataFrame(rows)
    out.to_csv(out_dir / "leakage_results.csv", index=False)
    pd.DataFrame(blind_rows).to_csv(out_dir / "v5_blindspots.csv", index=False)
    imp = pd.concat(imps, axis=1).fillna(0)
    imp["mean"] = imp.mean(axis=1)
    imp = imp.sort_values("mean", ascending=False)
    write_report(out, imp, out_dir)
    print(out[out["model"].isin(["honest", "leaky", "Exploit code, then EPSS"])].to_string(index=False))
    print(imp.head(10).round(3).to_string())
    return out, imp


def blind_breakdown(year, meta, score):
    """Exploited CVEs of one test replica split into flagged / blind-spot (Person A's st.group_of rule), with hits in the
    top k for the exploit-then-EPSS baseline and for `score` (tie rule: score, then epss_rank_in_month, then cve_id)."""
    from src.common.scoring import k_for_pool, rank_order
    k = k_for_pool(len(meta))
    d = meta.reset_index(drop=True).assign(s=score, group=st.group_of(meta.reset_index(drop=True), k))
    top_base = set(rank_order(d, ["exploit_epss"]).head(k)["cve_id"])
    top_ours = set(rank_order(d, ["s", "epss_rank_in_month"]).head(k)["cve_id"])
    pos = d[d["label"] == 1]
    rows = []
    for g in ("flagged", "blind-spot", "unflagged, EPSS-visible"):
        q = pos[pos["group"] == g]
        rows.append({"year": int(year), "group": g, "exploited": int(len(q)),
                     "baseline_caught": int(q["cve_id"].isin(top_base).sum()), "ours_caught": int(q["cve_id"].isin(top_ours).sum()),
                     "ours_caught_cves": ";".join(sorted(q.loc[q["cve_id"].isin(top_ours), "cve_id"]))})
    return rows


def write_report(out, imp, out_dir):
    piv = out.pivot_table(index="model", columns="replica", values="hits").fillna(0)
    piv["pooled"] = piv.sum(axis=1)
    h, l = piv.loc["honest", "pooled"], piv.loc["leaky", "pooled"]
    leak_share = imp.loc[[c for c in imp.index if c.startswith("leak_")], "mean"].sum()
    lines = [
        "# LEAKAGE EXPERIMENT (issue #8). Not a submission model.", "",
        "Same data, v5 features, parameter rule and 20-seed bag as the v5 headline model; the leaky model also gets banned "
        "after-the-fact columns (NVD status, CPE/reference counts, blank-vs-filled CVSS/CWE, NVD CVSS, "
        "exploit-tagged reference links). Run: `python -m src.b.leakage`.", "",
        "## In plain words",
        f"- Honest model: **{h:.0f}** exploited CVEs caught across both practice years. "
        f"With banned columns: **{l:.0f}** ({(l - h) / max(h, 1) * 100:+.0f}%).",
        f"- Banned columns carry **{leak_share * 100:.0f}%** of the leaky model's split gain. The biggest: "
        + ", ".join(f"`{c}`" for c in [c for c in imp.index if c.startswith('leak_')][:3]) + ".",
        "- That gap is what a model would claim but could never deliver on 2026, because at the snapshot "
        "those fields were not filled in yet. This is why the contract bans them.", "",
        "## Hits (top k), per test year", "",
        out[["direction", "model", "k", "positives", "hits", "expected", "ci_lo", "ci_hi", "ap"]]
        .to_markdown(index=False), "",
        "## Leaky model: share of split gain (mean of both directions)", "",
        imp["mean"].head(15).round(3).to_frame("gain share").to_markdown(), "",
        "LOW POWER: 27 and 48 positives; ranges are 90% paired bootstrap.",
    ]
    (out_dir / "b_leakage_report.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
