"""Person B, issue #13: one plain-English reason per top-500 CVE -> outputs/explanations.csv,
now with a Granite Guardian groundedness gate.

Run:  python -m src.b.explain                          # newest outputs/top500_v*.csv, template sentences only
      python -m src.b.explain --granite                # Granite rewrites each reason, Granite Guardian checks it
      python -m src.b.explain --granite --limit 20     # first 20 only
      python -m src.b.explain --granite --no-guardian  # NOT recommended: Guardian skipped, every row falls back to the template

Facts: every sentence is built ONLY from tracked files: outputs/features_scoreboard.parquet (EPSS rank, exploit flags),
outputs/text_features.parquet (text tags, IBM Granite KEV-likeness and similarity) and the final model's
outputs/v5_top500_contrib.parquet (which feature groups drove the ranking). Nothing comes from the untracked data/ files or the
embeddings, so the file can be rebuilt from a clone. The template sentence is always produced.

Pipeline per CVE (fail closed):
  1. Granite (granite-3.3-2b-instruct) rewrites the facts into ONE sentence.
  2. Local checks reject the draft if it is empty, incomplete, too long, contains a number, name, CVE id or claim that is not in the facts,
     or uses a blocked phrase ("will be exploited", "is being exploited", "confirmed", ...).
  3. Granite Guardian (granite3-guardian:2b via Ollama, risk = groundedness; facts as the context message, the draft as the assistant
     message) must clearly answer "No" (no risk). "Yes", empty, unparseable, timeout or any error => the template is used.
Results are cached per cve_id (outputs/.cache/explain_cache.jsonl) and outputs/explanations.csv is rewritten after every CVE, so a
crash or restart resumes instead of starting over. outputs/explanations_summary.json holds the counts.
Nothing in a file may say Guardian checked a sentence unless the Guardian model actually returned "No" for it.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone

import pandas as pd

from src.b.text_features import FLAGS
from src.common.paths import OUT_DIR

GRANITE = "ibm-granite/granite-3.3-2b-instruct"
GUARDIAN_MODEL = "granite3-guardian:2b"
OLLAMA_CHAT = "http://localhost:11434/api/chat"
GUARDIAN_TIMEOUT = 60  # seconds per call (the first call also loads the model)
PROMPT_VERSION = "2026-11-08-guardian-v2"  # bump to invalidate the cache when the Granite prompt or fact wording changes
EXPLANATION_COLS = ["cve_id", "explanation", "source", "guardian_verdict"]
# `reason` repeats `explanation`: the existing dashboard reads a column called `reason`; drop it once the dashboard reads `explanation`.
OUT_COLS = [*EXPLANATION_COLS, "reason"]

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
# groups of v5 features, in words, used for "the model's strongest reasons" (contributions are summed per group; timing is skipped)
DRIVER_GROUPS = {
    "public exploit code": ["exploitdb", "metasploit", "nuclei", "poc_github", "n_flags", "any_exploit"],
    "its EPSS rank within its month": ["epss_rank_in_month", "epss_missing"],
    "the reporting organisation's history of exploited CVEs": ["assigner_prior_cves_pctrank", "assigner_kev_share",
                                                                "assigner_kev_12m_share", "assigner_kev_rate_smooth_pctrank"],
    "a mentioned vendor's history of exploited CVEs": ["vendor_kev_count_max", "vendor_kev_12m_max", "n_vendors_mentioned"],
    "description similarity to past exploited CVEs": ["kev_text_score", "nearest_kev_sim"],
    "weakness wording in the description": list(TAGS),
}
BLOCKED_PHRASES = [r"will be exploited", r"is being exploited", r"confirmed"]
CLAIMS = (r"critical|severe|severity|actively|in the wild|ransomware|zero[- ]day|has been exploited|being exploited|known exploited")
MAX_WORDS = 45


def cna_name(assigner: str) -> str | None:
    """'psirt@cisco.com' -> 'Cisco'. None for generic CNAs like MITRE. (Not used for the facts any more: the assigner is not a tracked column.)"""
    if not isinstance(assigner, str) or assigner in GENERIC_CNA or "@" not in assigner:
        return None
    dom = assigner.split("@")[1].split(".")
    name = dom[-2] if len(dom) >= 2 else dom[0]
    return {"wpscan": "WPScan", "vuldb": "VulDB", "github": "GitHub", "hackerone": "HackerOne",
            "jpcert": "JPCERT", "redhat": "Red Hat", "us": None}.get(name, name.capitalize())


# ---- facts (tracked columns and the v5 contribution file only) ------------------------------------
def top_pct(rank) -> int:
    """'top X%' from a 0-1 percentile rank (1.0 = highest)."""
    return max(1, round((1 - float(rank)) * 100))


def drivers_from_contrib(row: pd.Series, k: int = 3) -> list[str]:
    """The k feature groups with the largest positive summed contribution to this CVE's score."""
    sums = {g: float(sum(row.get(c, 0.0) for c in cols)) for g, cols in DRIVER_GROUPS.items()}
    return [g for g, v in sorted(sums.items(), key=lambda kv: -kv[1])[:k] if v > 0]


def facts_for(top: pd.DataFrame, out_dir=OUT_DIR) -> pd.DataFrame:
    """One row per top-list CVE with every fact column. Uses only tracked files; asserts coverage."""
    sb = pd.read_parquet(out_dir / "features_scoreboard.parquet", columns=["cve_id", "epss", "epss_rank_in_month", *EXPLOIT_SRC])
    tf = pd.read_parquet(out_dir / "text_features.parquet")
    pool = sb.merge(tf, on="cve_id", how="left")
    pool["kev_text_pct"] = pool["kev_text_score"].rank(pct=True)
    f = top[["cve_id"]].merge(pool, on="cve_id", how="left")
    missing = f["epss_rank_in_month"].isna().sum() + f["kev_text_score"].isna().sum()
    assert not missing, f"{missing} top-list facts are missing from the tracked files"
    contrib_path = out_dir / "v5_top500_contrib.parquet"
    contrib = pd.read_parquet(contrib_path).set_index("cve_id") if contrib_path.exists() else None
    f["tags"] = f[list(FLAGS)].apply(lambda r: [TAGS[c] for c in FLAGS if r[c] == 1], axis=1)
    f["exploits"] = f[list(EXPLOIT_SRC)].apply(lambda r: [EXPLOIT_SRC[c] for c in EXPLOIT_SRC if r[c] == 1], axis=1)
    f["epss_pct"] = f["epss_rank_in_month"].where(f["epss"].notna())
    f["drivers"] = [drivers_from_contrib(contrib.loc[c]) if contrib is not None and c in contrib.index else [] for c in f["cve_id"]]
    return f


def _join(xs):
    return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]


def similarity(r) -> str:
    return "high" if r["nearest_kev_sim"] >= 0.8 else "moderate"


def epss_notable(r) -> bool:
    return bool(pd.notna(r["epss_pct"]) and r["epss_pct"] >= 0.9)      # only a top-10% EPSS rank is worth stating


def kev_like_notable(r) -> bool:
    return bool(r["kev_text_pct"] >= 0.9)                              # same for the Granite KEV-likeness percentile


def template(r) -> str:
    parts = []
    what = f"a {_join(r['tags'][:2])} flaw" if len(r["tags"]) else "a flaw"
    what = re.sub(r"^a ([aeiou])", r"an \1", what.replace("a an ", "an ").replace("a a ", "a "))
    parts.append(what[0].upper() + what[1:])
    if r["exploits"]:
        parts.append(f"public exploit code already exists ({_join(r['exploits'])})")
    if epss_notable(r):
        parts.append(f"its EPSS score is in the top {top_pct(r['epss_pct'])}% of its month")
    if similarity(r) == "high":
        parts.append("its description is highly similar to past exploited CVEs")
    elif kev_like_notable(r):
        parts.append("IBM Granite rates its description as very similar to past exploited CVEs")
    if r["drivers"]:
        parts.append(f"the ranking model's strongest reasons are {_join(r['drivers'][:2])}")
    return "; ".join(parts) + "."


def facts_text(r) -> str:
    """The only information the rewriting LLM is allowed to use, as a bullet list."""
    lines = [f"- CVE: {r['cve_id']}"]
    if r["tags"]:
        lines.append(f"- Weakness hints: {', '.join(r['tags'])}")
    if r["exploits"]:
        lines.append(f"- Public exploit code: {', '.join(r['exploits'])}")
    if epss_notable(r):
        lines.append(f"- EPSS percentile within its month: top {top_pct(r['epss_pct'])}%")
    if kev_like_notable(r):
        lines.append(f"- IBM Granite KEV-likeness of the description within the 2026 pool: top {top_pct(r['kev_text_pct'])}%")
    if similarity(r) == "high":
        lines.append("- Description similarity to past exploited CVEs: high")
    if r["drivers"]:
        lines.append(f"- Strongest reasons in the ranking model: {', '.join(r['drivers'])}")
    return "\n".join(lines)


def facts_prose(r) -> str:
    """The same facts as plain sentences: the context message for Guardian (it judges prose better than a bullet list)."""
    s = [f"{r['cve_id']} is a vulnerability" + (f" with weakness hints of {_join(r['tags'])}." if r["tags"] else ".")]
    if r["exploits"]:
        s.append(f"Public exploit code exists: {_join(r['exploits'])}.")
    if epss_notable(r):
        s.append(f"Its EPSS percentile within its month is in the top {top_pct(r['epss_pct'])}%.")
    if kev_like_notable(r):
        s.append(f"IBM Granite rates the KEV-likeness of its description within the 2026 pool in the top {top_pct(r['kev_text_pct'])}%.")
    if similarity(r) == "high":
        s.append("Its description has high similarity to past exploited CVEs.")
    if r["drivers"]:
        s.append(f"The strongest reasons in the ranking model are {_join(r['drivers'])}.")
    return " ".join(s)


# ---- local checks -----------------------------------------------------------------------------------
def check_reason(reason: str, facts: str) -> list[str]:
    """Problems: numbers, names, CVE ids and claims not supported by the facts, and blocked phrases."""
    problems = []
    fact_numbers = set(re.findall(r"\d+(?:\.\d+)?", facts))
    for n in re.findall(r"\d+(?:\.\d+)?", reason):
        if n not in fact_numbers:
            problems.append(f"number {n}")
    vocab = " ".join([*TAGS.values(), *EXPLOIT_SRC.values(), "IBM Granite KEV EPSS CVE CVEs CISA flaw"]).lower()
    allowed = set(re.findall(r"[a-z0-9\-]+", vocab))
    low_facts = facts.lower()
    for w in re.findall(r"\b[A-Z][A-Za-z0-9\-]{2,}\b", reason):
        if w.lower() not in allowed and w.lower() not in low_facts and not w.startswith("CVE-"):
            if reason.find(w) == 0 or reason[max(0, reason.find(w) - 2):reason.find(w)] in (". ", "; "):
                continue  # sentence-initial capital, not a name
            problems.append(f"name {w}")
    for claim in re.findall(rf"\b({CLAIMS})\b", reason, re.I):
        problems.append(f"unsupported claim '{claim}'")
    for phrase in BLOCKED_PHRASES:
        if re.search(rf"\b{phrase}\b", reason, re.I):
            problems.append(f"blocked phrase '{phrase}'")
    for c in re.findall(r"CVE-\d{4}-\d+", reason):
        if c not in facts:
            problems.append(f"cve {c}")
    return problems


def local_problems(draft: str, facts: str) -> list[str]:
    """Completeness, length, unsupported-claims and phrase checks; an empty draft is a problem."""
    if not draft or not draft.strip():
        return ["empty"]
    probs = check_reason(draft, facts)
    if not draft.rstrip().endswith("."):
        probs.append("incomplete sentence")
    if len(draft.split()) > MAX_WORDS:
        probs.append("too long")
    return probs


# ---- Granite Guardian (groundedness) ----------------------------------------------------------------
def guardian_verdict(facts: str, draft: str, timeout: float = GUARDIAN_TIMEOUT, url: str = OLLAMA_CHAT) -> str:
    """Ask granite3-guardian:2b whether `draft` (assistant message) is grounded in `facts` (context message).
    The Ollama model template reads the risk from the system message ('groundedness'). Returns one of
    'No' (no risk: the only passing answer), 'Yes', 'empty', 'unparseable', 'timeout', 'error'. Never raises."""
    body = {"model": GUARDIAN_MODEL, "stream": False, "options": {"temperature": 0, "num_predict": 5},
            "messages": [{"role": "system", "content": "groundedness"},
                         {"role": "context", "content": facts},
                         {"role": "assistant", "content": draft}]}
    try:
        req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = json.load(resp)["message"]["content"]
    except (socket.timeout, TimeoutError):
        return "timeout"
    except urllib.error.URLError as e:
        return "timeout" if isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)) else "error"
    except Exception:  # noqa: BLE001  (fail closed on anything unexpected)
        return "error"
    answer = (content or "").strip().strip(".'\"").strip().lower()
    if not answer:
        return "empty"
    return {"no": "No", "yes": "Yes"}.get(answer, "unparseable")


def decide(draft: str | None, facts: str, prose: str, template_text: str, guardian=guardian_verdict) -> dict:
    """Fail-closed decision for one CVE: the Granite draft is used only if the local checks pass AND Guardian clearly says 'No'."""
    probs = local_problems(draft or "", facts)
    if probs:
        return dict(explanation=template_text, source="template", guardian_verdict="not_run", problems=probs)
    try:
        verdict = guardian(prose, draft)
    except Exception:  # noqa: BLE001
        verdict = "error"
    if verdict == "No":
        return dict(explanation=draft.strip(), source="granite", guardian_verdict="No", problems=[])
    return dict(explanation=template_text, source="template", guardian_verdict=verdict or "empty", problems=[f"guardian verdict {verdict!r}"])


# ---- Granite rewriter -------------------------------------------------------------------------------
SYSTEM_PROMPT = ("Write ONE plain-English sentence of at most 30 words saying why this vulnerability should be patched early. "
                 "Start with what kind of flaw it is. Do not repeat the CVE id and do not start with 'The vulnerability' or "
                 "'The security team'. Use ONLY the facts given; add no products, numbers, dates or claims that are not in them. "
                 "Never say it has been exploited, will be exploited or is confirmed. Mention the description similarity only "
                 "if it is high.")


class GraniteRewriter:
    """Loads granite-3.3-2b-instruct once; call it with a fact row to get one sentence."""

    def __init__(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.device = "mps" if torch.backends.mps.is_available() else "cpu"
        self.tok = AutoTokenizer.from_pretrained(GRANITE)
        self.model = AutoModelForCausalLM.from_pretrained(GRANITE, torch_dtype=torch.float16 if self.device == "mps" else None).to(self.device)

    def __call__(self, r) -> str:
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": facts_text(r)}]
        enc = self.tok.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt", return_dict=True).to(self.device)
        gen = self.model.generate(**enc, max_new_tokens=90, do_sample=False)
        return self.tok.decode(gen[0, enc["input_ids"].shape[1]:], skip_special_tokens=True).strip().split("\n")[0]


def granite_rewrite(rows: pd.DataFrame) -> list[str | None]:
    rewriter = GraniteRewriter()
    return [rewriter(r) for _, r in rows.iterrows()]


# ---- cache, incremental output, summary -------------------------------------------------------------
def cache_key(facts: str) -> str:
    return hashlib.sha1("\n".join([facts, GRANITE, GUARDIAN_MODEL, PROMPT_VERSION]).encode()).hexdigest()[:16]


def load_cache(path) -> dict:
    recs = {}
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                r = json.loads(line)
                recs[r["cve_id"]] = r
            except (json.JSONDecodeError, KeyError):
                continue  # a torn last line after a crash
    return recs


RETRY = {"timeout", "error"}  # transient Guardian failures are retried on restart; model answers are final


def rows_frame(items: list[dict], recs: dict) -> pd.DataFrame:
    """All rows of the list: finished ones from the cache, the rest as template rows marked 'pending'."""
    out = []
    for it in items:
        r = recs.get(it["cve_id"])
        if r and r["key"] == it["key"]:
            out.append(dict(cve_id=it["cve_id"], explanation=r["explanation"], source=r["source"], guardian_verdict=r["guardian_verdict"]))
        else:
            out.append(dict(cve_id=it["cve_id"], explanation=it["template"], source="template", guardian_verdict="pending"))
    d = pd.DataFrame(out, columns=EXPLANATION_COLS)
    d["reason"] = d["explanation"]
    return d[OUT_COLS]


def write_atomic(df: pd.DataFrame, path) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)


def summarize(df: pd.DataFrame, extra: dict | None = None) -> dict:
    v = df["guardian_verdict"].value_counts().to_dict()
    ran = sum(v.get(k, 0) for k in ("No", "Yes", "unparseable", "empty"))  # Guardian returned something (even if unusable)
    return {
        "total": int(len(df)),
        "passed_guardian": int(((df["source"] == "granite") & (df["guardian_verdict"] == "No")).sum()),
        "rewritten": int(sum(v.get(k, 0) for k in ("No", "Yes", "unparseable", "empty", "timeout", "error"))),
        "template_fallback": int((df["source"] == "template").sum()),
        "pending": int(v.get("pending", 0)),
        "guardian_ran": bool(v.get("No", 0) + v.get("Yes", 0) > 0),
        "guardian_model": GUARDIAN_MODEL, "granite_model": GRANITE,
        "guardian_verdicts": {k: int(n) for k, n in v.items()},
        "guardian_calls_answered": int(ran),
        "notes": "passed_guardian = Granite sentences kept because Guardian answered No; rewritten = Granite drafts that passed the local checks and were sent to "
                 "Guardian; template_fallback = template sentences used (draft failed a local check, Guardian did not clearly say No, or Granite was not run). "
                 "guardian_ran is true only if the Guardian model returned a Yes or No at least once.",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **(extra or {})}


def process(items: list[dict], draft_fn, guardian=guardian_verdict, out_dir=OUT_DIR, log=print) -> pd.DataFrame:
    """Run (or resume) the gate over `items` (dicts with cve_id, facts, prose, template, key). Writes the cache, explanations.csv and
    the summary after every CVE."""
    cache_dir = out_dir / ".cache"
    cache_dir.mkdir(exist_ok=True)
    cache_path = cache_dir / "explain_cache.jsonl"
    recs = load_cache(cache_path)
    extra = {"top_list": None}
    write_atomic(rows_frame(items, recs), out_dir / "explanations.csv")
    with open(cache_path, "a") as cache:
        for i, it in enumerate(items, 1):
            r = recs.get(it["cve_id"])
            if r and r["key"] == it["key"] and r["guardian_verdict"] not in RETRY:
                continue                                       # finished earlier: resume
            draft = draft_fn(it) if draft_fn else None
            d = decide(draft, it["facts"], it["prose"], it["template"], guardian) if draft_fn else \
                dict(explanation=it["template"], source="template", guardian_verdict="not_run", problems=["granite not run"])
            if d["source"] == "template" and d["problems"] and d["guardian_verdict"] == "not_run" and draft_fn:
                log(f"{it['cve_id']}: kept template, Granite draft rejected locally: {d['problems']}")
            rec = dict(cve_id=it["cve_id"], key=it["key"], draft=draft, **{k: d[k] for k in ("explanation", "source", "guardian_verdict")})
            cache.write(json.dumps(rec) + "\n")
            cache.flush()
            recs[it["cve_id"]] = rec
            df = rows_frame(items, recs)
            write_atomic(df, out_dir / "explanations.csv")
            (out_dir / "explanations_summary.json").write_text(json.dumps(summarize(df, extra), indent=1))
            if i % 25 == 0:
                log(f"  {i}/{len(items)} done; {summarize(df)['passed_guardian']} passed Guardian so far")
    df = rows_frame(items, recs)
    write_atomic(df, out_dir / "explanations.csv")
    return df


def latest_top() -> str:
    files = sorted(OUT_DIR.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    final = OUT_DIR / "top500_final.csv"
    return str(final if final.exists() else files[-1])


def main(top_path=None, granite=False, limit=None, use_guardian=True):
    top_path = top_path or latest_top()
    top = pd.read_csv(top_path)
    if limit:
        top = top.head(limit)
    f = facts_for(top)
    items = []
    for _, r in f.iterrows():
        t, facts = template(r), facts_text(r)
        assert not check_reason(t, facts), f"template for {r['cve_id']} uses facts not in the input: {check_reason(t, facts)}"
        items.append(dict(cve_id=r["cve_id"], facts=facts, prose=facts_prose(r), template=t, key=cache_key(facts), row=r))
    holder = {}

    def draft_fn(it):  # the model is loaded on first use, so resuming a finished run costs nothing
        holder.setdefault("w", GraniteRewriter())
        return holder["w"](it["row"])

    guardian = guardian_verdict if use_guardian else (lambda facts, draft: "not_run")
    df = process(items, draft_fn if granite else None, guardian)
    summary = summarize(df, {"top_list": os.path.basename(top_path)})
    (OUT_DIR / "explanations_summary.json").write_text(json.dumps(summary, indent=1))
    assert df["cve_id"].is_unique and len(df) == len(top)
    keep = ["cve_id", "tags", "exploits", "epss", "epss_pct", "kev_text_pct", "nearest_kev_sim", "drivers"]
    f[keep].assign(template=[i["template"] for i in items], explanation=df["explanation"].to_numpy(), source=df["source"].to_numpy(),
                   guardian_verdict=df["guardian_verdict"].to_numpy()).to_csv(OUT_DIR / ".cache" / "b_explain_facts.csv", index=False)  # review aid, not tracked
    print(f"wrote explanations.csv ({len(df)} rows from {top_path}); summary: {json.dumps({k: summary[k] for k in ('passed_guardian', 'rewritten', 'template_fallback', 'pending', 'guardian_ran')})}")
    print(df["explanation"].head(8).to_string(index=False))
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--top")
    ap.add_argument("--granite", action="store_true")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--no-guardian", action="store_true")
    a = ap.parse_args()
    main(a.top, a.granite, a.limit, use_guardian=not a.no_guardian)
