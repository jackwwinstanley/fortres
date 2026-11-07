"""Person B, issue #13: one plain-English reason per top-500 CVE -> outputs/explanations.csv

Run:  python -m src.b.explain                         # newest outputs/top500_v*.csv, template sentences
      python -m src.b.explain --top outputs/top500_final.csv
      python -m src.b.explain --granite --limit 20     # let a Granite instruct model reword them

Every sentence is built ONLY from facts our pipeline already has for that CVE (all allowed at the
snapshot; see CONTRACT.md):
  - who reported it (assigner/CNA)          - text tags (txt_* flags)
  - EPSS and its percentile within its pool - public exploit sources (exploitdb/metasploit/nuclei/poc)
  - Granite KEV-likeness percentile         - the closest past KEV entry (same year cutoff as
                                              nearest_kev_sim: KEV date_added <= Dec 31 of prior year)
The template sentence is always produced. With --granite, the model only rewords the facts list; its
sentence is kept only if check_reason() finds no number or product name that isn't in the facts,
otherwise the template is used. The facts are saved to outputs/b_explain_facts.csv for review.
"""
import argparse
import re

import numpy as np
import pandas as pd

from src.b.text_features import FLAGS, _targets
from src.common.paths import DATA_DIR, OUT_DIR

GRANITE = "ibm-granite/granite-3.3-2b-instruct"
TAGS = {
    "txt_rce": "remote code execution", "txt_unauth": "unauthenticated",
    "txt_auth_bypass": "authentication-bypass", "txt_cmd_injection": "command injection",
    "txt_deserialization": "unsafe deserialization", "txt_path_traversal": "path traversal",
    "txt_sqli": "SQL injection", "txt_priv_esc": "privilege escalation",
    "txt_memory": "memory corruption", "txt_edge_device": "VPN/firewall/edge-device",
    "txt_enterprise": "enterprise-software", "txt_browser": "web-browser",
    "txt_wordpress": "WordPress-plugin", "txt_xss": "cross-site scripting",
}
EXPLOIT_SRC = {"exploitdb": "Exploit-DB", "metasploit": "Metasploit", "nuclei": "a Nuclei template",
               "poc_github": "a GitHub proof of concept"}
GENERIC_CNA = {"cve@mitre.org", "unknown"}


def cna_name(assigner: str) -> str | None:
    """'psirt@cisco.com' -> 'Cisco'. None for generic CNAs like MITRE."""
    if not isinstance(assigner, str) or assigner in GENERIC_CNA or "@" not in assigner:
        return None
    dom = assigner.split("@")[1].split(".")
    name = dom[-2] if len(dom) >= 2 else dom[0]
    return {"wpscan": "WPScan", "vuldb": "VulDB", "github": "GitHub", "hackerone": "HackerOne",
            "jpcert": "JPCERT", "redhat": "Red Hat", "us": None}.get(name, name.capitalize())


def pool_frames():
    """All target CVEs with pool year, pool-relative percentiles and every fact column."""
    tg = _targets()
    feats = []
    for y, f in ((2024, "replica_2024.parquet"), (2025, "replica_2025.parquet"),
                 (2026, "scoreboard_features.parquet")):
        d = pd.read_parquet(OUT_DIR / f).drop(columns=["label"], errors="ignore").assign(year=y)
        d["epss_pct"] = d["epss"].rank(pct=True)
        feats.append(d)
    d = pd.concat(feats, ignore_index=True)
    tf = pd.read_parquet(OUT_DIR / "text_features.parquet")
    d = d.merge(tf, on="cve_id", how="left")
    d["kev_text_pct"] = d.groupby("year")["kev_text_score"].rank(pct=True)
    a = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "assigner"])
    d = d.merge(a, on="cve_id", how="left")
    assert d["cve_id"].isin(tg["cve_id"]).all()
    return d


def nearest_kev(ids: pd.Series, years: pd.Series) -> pd.DataFrame:
    """Closest KEV entry (cosine on Granite embeddings) under the prior-Dec-31 cutoff."""
    emb = np.load(OUT_DIR / "emb_small.npy")
    eid = pd.read_csv(OUT_DIR / "emb_ids.csv")["cve_id"]
    row = pd.Series(np.arange(len(eid)), index=eid)
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv",
                      usecols=["cve_id", "vendor", "product", "name", "date_added"])
    kev["date_added"] = pd.to_datetime(kev["date_added"])
    kev = kev[kev["cve_id"].isin(row.index)]
    out = []
    for y in sorted(years.unique()):
        m = years == y
        k = kev[(kev["date_added"] <= pd.Timestamp(f"{y - 1}-12-31")) & ~kev["cve_id"].isin(ids[m])]
        K = emb[row.loc[k["cve_id"]].to_numpy()]
        X = emb[row.loc[ids[m]].to_numpy()]
        S = X @ K.T
        j = S.argmax(axis=1)
        best = k.iloc[j].reset_index(drop=True)
        out.append(pd.DataFrame({
            "cve_id": ids[m].to_numpy(), "kev_match": best["cve_id"].to_numpy(),
            "kev_match_vendor": best["vendor"].to_numpy(), "kev_match_product": best["product"].to_numpy(),
            "kev_match_year": best["date_added"].dt.year.to_numpy(), "kev_match_sim": S.max(axis=1)}))
    return pd.concat(out, ignore_index=True)


def facts_for(top: pd.DataFrame) -> pd.DataFrame:
    d = pool_frames()
    f = top[["cve_id"]].merge(d, on="cve_id", how="left")
    missing = f["year"].isna().sum()
    assert not missing, f"{missing} top-list CVEs are not in any pool"
    f["year"] = f["year"].astype(int)
    f = f.merge(nearest_kev(f["cve_id"], f["year"]), on="cve_id", how="left")
    f["cna"] = f["assigner"].map(cna_name)
    f["tags"] = f[list(FLAGS)].apply(lambda r: [TAGS[c] for c in FLAGS if r[c] == 1], axis=1)
    f["exploits"] = f[list(EXPLOIT_SRC)].apply(lambda r: [EXPLOIT_SRC[c] for c in EXPLOIT_SRC if r[c] == 1], axis=1)
    return f


def _join(xs):
    return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]


def template(r) -> str:
    parts = []
    what = f"a {_join(r['tags'][:2])} flaw" if len(r["tags"]) else "a flaw"
    what = what.replace("a an ", "an ").replace("a a ", "a ")
    who = f" (reported by {r['cna']})" if pd.notna(r["cna"]) and r["cna"] else ""
    parts.append(f"{what[0].upper() + what[1:]}{who}")
    if r["exploits"]:
        parts.append(f"public exploit code already exists ({_join(r['exploits'])})")
    if pd.notna(r["epss"]) and r["epss_pct"] >= 0.9:
        parts.append(f"its EPSS score is in the top {max(1, round((1 - r['epss_pct']) * 100))}% of its year")
    if r["kev_match_sim"] >= 0.8:
        parts.append(f"its description closely resembles {r['kev_match']} ({r['kev_match_vendor']} "
                     f"{r['kev_match_product']}), exploited and added to KEV in {r['kev_match_year']}")
    elif r["kev_text_pct"] >= 0.9:
        parts.append("IBM Granite rates its description as very similar to past exploited CVEs")
    return "; ".join(parts) + "."


def facts_text(r) -> str:
    """The only information the LLM is allowed to use, as a bullet list."""
    lines = [f"- CVE: {r['cve_id']}"]
    if pd.notna(r["cna"]) and r["cna"]:
        lines.append(f"- Reported by: {r['cna']}")
    if r["tags"]:
        lines.append(f"- Weakness hints: {', '.join(r['tags'])}")
    if r["exploits"]:
        lines.append(f"- Public exploit code: {', '.join(r['exploits'])}")
    if pd.notna(r["epss"]):
        lines.append(f"- EPSS percentile within its year: top {max(1, round((1 - r['epss_pct']) * 100))}%")
    lines.append(f"- Most similar past exploited CVE: {r['kev_match']} ({r['kev_match_vendor']} "
                 f"{r['kev_match_product']}, added to KEV in {r['kev_match_year']}), "
                 f"similarity {'high' if r['kev_match_sim'] >= 0.8 else 'moderate'}")
    return "\n".join(lines)


def check_reason(reason: str, facts: str) -> list[str]:
    """Numbers and capitalised names in the reason that don't appear in the facts."""
    problems = []
    for n in re.findall(r"\d+(?:\.\d+)?", reason):
        if n not in facts:
            problems.append(f"number {n}")
    vocab = " ".join([*TAGS.values(), *EXPLOIT_SRC.values(), "IBM Granite KEV EPSS CVE CVEs CISA flaw"]).lower()
    allowed = set(re.findall(r"[a-z0-9\-]+", vocab))
    low_facts = facts.lower()
    for w in re.findall(r"\b[A-Z][A-Za-z0-9\-]{2,}\b", reason):
        if w.lower() not in allowed and w.lower() not in low_facts and not w.startswith("CVE-"):
            if reason.find(w) == 0 or reason[max(0, reason.find(w) - 2):reason.find(w)] in (". ", "; "):
                continue  # sentence-initial capital, not a name
            problems.append(f"name {w}")
    for c in re.findall(r"CVE-\d{4}-\d+", reason):
        if c not in facts:
            problems.append(f"cve {c}")
    return problems


def granite_rewrite(rows: pd.DataFrame) -> list[str | None]:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(GRANITE)
    model = AutoModelForCausalLM.from_pretrained(GRANITE, torch_dtype=torch.float16 if device == "mps" else None).to(device)
    out = []
    for _, r in rows.iterrows():
        msgs = [{"role": "system", "content":
                 "You write one plain-English sentence (max 35 words) explaining why a security team should "
                 "patch this vulnerability first. Use ONLY the facts given. Do not add products, numbers, "
                 "dates or claims that are not in the facts. Do not say it has been exploited."},
                {"role": "user", "content": facts_text(r)}]
        ids = tok.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt").to(device)
        gen = model.generate(ids, max_new_tokens=70, do_sample=False)
        out.append(tok.decode(gen[0, ids.shape[1]:], skip_special_tokens=True).strip().split("\n")[0])
    return out


def latest_top() -> str:
    files = sorted(OUT_DIR.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    final = OUT_DIR / "top500_final.csv"
    return str(final if final.exists() else files[-1])


def main(top_path=None, granite=False, limit=None):
    top_path = top_path or latest_top()
    top = pd.read_csv(top_path)
    if limit:
        top = top.head(limit)
    f = facts_for(top)
    f["template"] = f.apply(template, axis=1)
    f["reason"] = f["template"]
    f["source"] = "template"
    if granite:
        for i, txt in zip(f.index, granite_rewrite(f)):
            probs = check_reason(txt, facts_text(f.loc[i])) if txt else ["empty"]
            if not probs:
                f.loc[i, ["reason", "source"]] = [txt, "granite"]
            else:
                print(f"{f.loc[i, 'cve_id']}: kept template, Granite added {probs}")
    bad = {c: p for c, r, t in zip(f["cve_id"], f["reason"], f.apply(facts_text, axis=1))
           if (p := check_reason(r, t))}
    assert not bad, f"reasons with facts not in the input: {list(bad.items())[:5]}"
    assert f["cve_id"].is_unique
    f[["cve_id", "reason"]].to_csv(OUT_DIR / "explanations.csv", index=False)
    keep = ["cve_id", "year", "cna", "tags", "exploits", "epss", "epss_pct", "kev_text_pct",
            "kev_match", "kev_match_vendor", "kev_match_product", "kev_match_year", "kev_match_sim",
            "template", "reason", "source"]
    f[keep].to_csv(OUT_DIR / "b_explain_facts.csv", index=False)
    print(f"wrote explanations.csv ({len(f)} rows from {top_path}); sources: "
          f"{f['source'].value_counts().to_dict()}")
    print(f["reason"].head(8).to_string(index=False))
    return f


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--top")
    ap.add_argument("--granite", action="store_true")
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    main(a.top, a.granite, a.limit)
