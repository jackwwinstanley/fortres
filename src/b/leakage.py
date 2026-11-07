"""Person B, issue #8: LEAKAGE EXPERIMENT. Never used for the submission.

Run:  python -m src.b.leakage

Question: how much better would a model LOOK if it used columns that are only filled in after the
fact (CONTRACT.md "BANNED")? Same data, same model and same parameters as Person A's v2 LightGBM;
the only difference is the extra banned columns:
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
from src.common.schema import TEXT_FEATURES, is_banned
from src.models import train_v1 as v1
from src.models.train_v2 import load_with_text

# Same parameters as the v2 LightGBM forward run (outputs/runlog.csv, v2_lgbm train2024_test2025); not tuned here.
PARAMS = {"num_leaves": 4, "min_child_samples": 100, "n_estimators": 150, "reg_lambda": 1, "scale_pos_weight": 10}
HONEST = list(v1.FEATURES) + TEXT_FEATURES
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
        data[y]["XL"] = pd.concat([data[y]["X2"].reset_index(drop=True), b], axis=1)
    leaky = HONEST + [c for c in data[2024]["XL"].columns if c.startswith("leak_")]
    assert all(is_banned(c.replace("leak_", "")) or "nvd_status" in c or "refs" in c
               for c in leaky if c.startswith("leak_")), "every extra column should be a banned one"
    assert not any(c.startswith("leak_") for c in HONEST)

    rows, imps = [], []
    for name, tr, te, note in v1.DIRECTIONS:
        Xtr, ytr, Xte = data[tr]["XL"], data[tr]["y"], data[te]["XL"]
        scores = {}
        for label, feats in (("honest", HONEST), ("leaky", leaky)):
            m = v1.lgbm_model(PARAMS, feats).fit(Xtr[feats], ytr)
            scores[label] = m.predict_proba(Xte[feats])[:, 1]
            if label == "leaky":
                g = pd.Series(m.booster_.feature_importance("gain"), index=feats)
                imps.append((g / g.sum()).rename(name))
        res, _, names, k = v1.eval_frame(data[te]["meta"], scores)
        for n in names:
            r = res[n]
            rows.append(dict(direction=name, replica=te, note=note, k=k, positives=int(data[te]["y"].sum()),
                             model=n, hits=r["arbitrary"], expected=round(r["expected"], 2),
                             ci_lo=r["ci"][0], ci_hi=r["ci"][1], ap=round(r["ap"], 4)))
    out = pd.DataFrame(rows)
    out.to_csv(out_dir / "leakage_results.csv", index=False)
    imp = pd.concat(imps, axis=1).fillna(0)
    imp["mean"] = imp.mean(axis=1)
    imp = imp.sort_values("mean", ascending=False)
    write_report(out, imp, out_dir)
    print(out[out["model"].isin(["honest", "leaky", "Exploit code, then EPSS"])].to_string(index=False))
    print(imp.head(10).round(3).to_string())
    return out, imp


def write_report(out, imp, out_dir):
    piv = out.pivot_table(index="model", columns="replica", values="hits").fillna(0)
    piv["pooled"] = piv.sum(axis=1)
    h, l = piv.loc["honest", "pooled"], piv.loc["leaky", "pooled"]
    leak_share = imp.loc[[c for c in imp.index if c.startswith("leak_")], "mean"].sum()
    lines = [
        "# LEAKAGE EXPERIMENT (issue #8). Not a submission model.", "",
        "Same data, model and parameters as the v2 LightGBM; the leaky model also gets banned "
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
