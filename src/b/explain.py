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
import functools
import gzip
import hashlib
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.b.text_features import FLAGS
from src.common.paths import OUT_DIR

GRANITE = "ibm-granite/granite-3.3-2b-instruct"
GUARDIAN_MODEL = "granite3-guardian:2b"
OLLAMA_CHAT = "http://localhost:11434/api/chat"
GUARDIAN_TIMEOUT = 60  # seconds per call (the first call also loads the model)
PROMPT_VERSION = "2026-11-08-restate-v6"  # part of the cache key: bump it whenever the Granite prompt or the fact wording changes, and every row is regenerated
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
# groups of v5 features, in words, used for "the model's main drivers" (contributions are summed per group; timing is skipped)
DRIVER_GROUPS = {
    "public exploit code": ["exploitdb", "metasploit", "nuclei", "poc_github", "n_flags", "any_exploit"],
    "its EPSS rank within its month": ["epss_rank_in_month", "epss_missing"],
    "the reporting organisation's history of exploited CVEs": ["assigner_prior_cves_pctrank", "assigner_kev_share",
                                                                "assigner_kev_12m_share", "assigner_kev_rate_smooth_pctrank"],
    "a mentioned vendor's history of exploited CVEs": ["vendor_kev_count_max", "vendor_kev_12m_max", "n_vendors_mentioned"],
    "description similarity to past exploited CVEs": ["kev_text_score", "nearest_kev_sim"],
    "weakness wording in the description": list(TAGS),
}
# Every phrase a sentence may not contain (regular expressions, matched as whole words, case-insensitive). One constant, grouped by class.
BLOCKED_PHRASES = [
    # claims that exploitation happened, is happening or will happen (none of this is in the facts)
    r"will be exploited", r"is being exploited", r"being exploited", r"has been exploited", r"known exploited", r"confirmed",
    r"actively", r"in the wild", r"ransomware", r"zero[- ]day",
    # severity and intensity words the facts do not contain
    r"critical", r"severe", r"severity", r"high[- ]impact", r"highly", r"serious", r"dangerous", r"widespread", r"widely",
    # nonsense seen in generated text
    r"exploit templates?",
    # predictions, interpretation and causal links: the sentence may only restate the facts
    r"likelihood", r"likely", r"indicating", r"risk of exploitation", r"potential for exploitation", r"exploitation patterns", r"mirroring",
    r"significant risk", r"strong(?:ly|er|est)?",
    r"placing", r"placed", r"thereby", r"therefore", r"thus", r"hence", r"reflecting", r"suggest(?:s|ing)?", r"impl(?:y|ies|ying)",
    r"as evidenced", r"resulting", r"leading to", r"due to",
]
MAX_WORDS = 45
# real tokens that contain a lowercase-then-uppercase letter pair; any other such token is treated as two words glued together
CAMEL_OK = {"GitHub", "ExploitDB", "WordPress", "LightGBM"}
# domain words that are legitimate but not in the general English word list (lower case)
DOMAIN_WORDS = {"github", "exploitdb", "wordpress", "lightgbm", "epss", "kev", "cve", "cves", "ibm", "granite", "nuclei", "metasploit",
                "vpn", "sql", "xss", "cisa", "db", "plugin", "plugins", "poc", "prioritised", "prioritized"}
IRREGULAR_OK = {"has"}  # forms missing from the base-form word list (checked: the only common function word it lacks)
WORDS_PATH = Path(__file__).with_name("english_words.txt.gz")  # general English word list (Webster's Second, public domain), base forms only
MAX_ATTEMPTS = 3  # attempt 0 = original prompt (greedy); 1 = prompt with an avoid-list (greedy); 2 = same, sampled with a fixed seed


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


MAX_FACTS = 3  # the model is shown, and asked to restate, at most this many facts


def selected_facts(r) -> list[tuple[str, str, str]]:
    """(kind, bullet line, plain sentence) for at most MAX_FACTS facts, in priority order: exploit code, EPSS (top 10% only), the IBM Granite
    KEV-likeness (top 10% only), high description similarity, weakness hints; the ranking model's main drivers only if fewer than two others exist.
    The rewriter, Guardian and the template all use exactly these facts."""
    out = []
    if r["exploits"]:
        out.append(("exploit", f"- Public exploit code: {', '.join(r['exploits'])}", f"Public exploit code exists: {_join(r['exploits'])}."))
    if epss_notable(r):
        x = top_pct(r["epss_pct"])
        out.append(("epss", f"- EPSS percentile within its month: top {x}%", f"Its EPSS percentile within its month is in the top {x}%."))
    if kev_like_notable(r):
        x = top_pct(r["kev_text_pct"])
        out.append(("kev", f"- IBM Granite KEV-likeness of the description within the 2026 pool: top {x}%",
                    f"IBM Granite rates the KEV-likeness of its description within the 2026 pool in the top {x}%."))
    if similarity(r) == "high":
        out.append(("sim", "- Description similarity to past exploited CVEs: high", "Its description has high similarity to past exploited CVEs."))
    if r["tags"]:
        out.append(("tags", f"- Weakness hints: {', '.join(r['tags'][:2])}", f"Its weakness hints are {_join(r['tags'][:2])}."))
    out = out[:MAX_FACTS]
    if len(out) < 2 and r["drivers"]:
        out.append(("drivers", f"- Main drivers in the ranking model: {', '.join(r['drivers'][:2])}",
                    f"The main drivers in the ranking model are {_join(r['drivers'][:2])}."))
    return out


def _fact_clause(kind: str, line: str, r) -> str:
    if kind == "exploit":
        return f"it has public exploit code ({_join(r['exploits'])})"
    if kind == "epss":
        return f"its EPSS percentile within its month is in the top {top_pct(r['epss_pct'])}%"
    if kind == "kev":
        return f"its IBM Granite KEV-likeness within the 2026 pool is in the top {top_pct(r['kev_text_pct'])}%"
    if kind == "sim":
        return "its description has high similarity to past exploited CVEs"
    if kind == "tags":
        what = f"a {_join(r['tags'][:2])} flaw"
        return "it is " + re.sub(r"^a ([aeiou])", r"an \1", what)
    return f"the ranking model's main drivers are {_join(r['drivers'][:2])}"


def template(r) -> str:
    """The fallback sentence: the same selected facts, restated in a fixed form."""
    clauses = [_fact_clause(k, line, r) for k, line, _ in selected_facts(r)]
    return "Prioritised because " + (_join(clauses) if clauses else "it is on the ranked list") + "."


def facts_text(r) -> str:
    """The only information the rewriting LLM is allowed to use, as a bullet list."""
    return "\n".join([f"- CVE: {r['cve_id']}", *[line for _, line, _ in selected_facts(r)]])


def facts_prose(r) -> str:
    """The same facts as plain sentences: the context message for Guardian (it judges prose better than a bullet list)."""
    return " ".join([f"{r['cve_id']} is a vulnerability.", *[sentence for _, _, sentence in selected_facts(r)]])


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
    for phrase in BLOCKED_PHRASES:
        m = re.search(rf"\b(?:{phrase})\b", reason, re.I)
        if m:
            problems.append(f"blocked phrase '{m.group(0).lower()}'")
    for c in re.findall(r"CVE-\d{4}-\d+", reason):
        if c not in facts:
            problems.append(f"cve {c}")
    return problems + percentage_problems(reason, facts)


@functools.lru_cache(maxsize=1)
def english_words() -> frozenset:
    """The general English word list. A missing file fails closed: every word is then unknown and every draft falls back to the template."""
    if not WORDS_PATH.exists():
        return frozenset()
    with gzip.open(WORDS_PATH, "rt") as f:
        return frozenset(w.strip() for w in f if w.strip())


def word_known(w: str) -> bool:
    """A real English word (the list has base forms only, so simple inflections are tried) or a domain word such as GitHub or VPNs."""
    w = w.lower()
    words = english_words()
    if w in IRREGULAR_OK:
        return True
    for base in (w, w[:-1] if w.endswith("s") else w):
        if base in DOMAIN_WORDS:
            return True
    if w in words:
        return True
    for suf, repl in (("s", ""), ("es", ""), ("ies", "y"), ("ed", ""), ("ed", "e"), ("ied", "y"), ("d", ""), ("ing", ""), ("ing", "e"),
                      ("ly", ""), ("ness", ""), ("ity", "e"), ("er", ""), ("ers", "")):
        if w.endswith(suf) and len(w) - len(suf) >= 3 and w[:-len(suf)] + repl in words:
            return True
    return bool(w.endswith("ing") and len(w) > 5 and w[:-4] in words)


def glue_problems(text: str, facts: str) -> list[str]:
    """Words joined without a space or garbled: (1) a lowercase letter directly followed by an uppercase letter inside a word
    ('availableGitHub'), except CAMEL_OK and tokens that appear exactly so in the facts; (2) a one-letter word glued to a capitalised
    word ('aKEV'); (3) any word that is neither in the facts, DOMAIN_WORDS nor the English word list ('vulnerabilityin', 'proof-ofof-concept')."""
    probs = []
    fact_tokens = set(re.findall(r"[A-Za-z][A-Za-z0-9]*", facts))
    fact_lower = {t.lower() for t in fact_tokens}
    for tok in re.findall(r"[A-Za-z]+", re.sub(r"'s\b", "", text)):
        if re.search(r"[a-z][A-Z]", tok) and tok not in CAMEL_OK and tok not in fact_tokens:
            probs.append(f"glued words '{tok}'")
        elif re.match(r"[aA][A-Z][a-z]", tok) and tok not in CAMEL_OK and tok not in fact_tokens:
            probs.append(f"glued words '{tok}'")
        elif len(tok) >= 2 and tok.lower() not in fact_lower and not word_known(tok):
            probs.append(f"unknown or joined word '{tok}'")
        elif len(tok) == 1 and tok.lower() not in ("a", "s") and tok not in fact_tokens:
            probs.append(f"stray letter '{tok}'")
    return list(dict.fromkeys(probs))


FACT_WORDS = {"EPSS": ("epss",), "KEV-likeness": ("kev-likeness", "granite", "kev likeness")}
OTHER_FACT_WORDS = {"similarity": ("similar",), "exploit code": ("exploit code", "proof of concept", "proof-of-concept", "metasploit", "exploit-db", "nuclei", "github")}


def percentage_problems(reason: str, facts: str) -> list[str]:
    """Every percentage must stay attached to its own fact: it sits in a clause (split at commas, semicolons and 'and') that names exactly one
    of EPSS / the IBM Granite KEV-likeness and no other fact, and carries that fact's value. A sentence may not mention EPSS or the KEV-likeness
    unless the facts contain it, and may not share one percentage between facts ('both ... in the top 3%')."""
    probs = []
    e = re.search(r"EPSS percentile within its month: top (\d+)%", facts)
    k = re.search(r"KEV-likeness[^\n]*?: top (\d+)%", facts)
    expect = {"EPSS": e.group(1) if e else None, "KEV-likeness": k.group(1) if k else None}
    low_all, low_facts = reason.lower(), facts.lower()
    mentioned = [n for n, words in FACT_WORDS.items() if any(w in low_all for w in words)]
    for name in mentioned:
        if expect[name] is None and not (name == "KEV-likeness" and "granite" in low_facts):
            probs.append(f"mentions {name} but the facts do not")
    for seg in re.split(r",\s*|;\s*|\s+and\s+", reason):
        for n in re.findall(r"(\d+(?:\.\d+)?)\s*%", seg):
            low = seg.lower()
            if re.search(r"\b(both|each|respectively|either)\b", low):
                probs.append(f"percentage {n}% shared by several facts")
            named = [name for name, words in FACT_WORDS.items() if any(w in low for w in words)]
            others = [name for name, words in OTHER_FACT_WORDS.items() if any(w in low for w in words)
                      and not (name == "similarity" and "KEV-likeness" in named)]
            if len(named) != 1 or others:
                probs.append(f"percentage {n}% not attached to exactly one fact")
            elif expect[named[0]] != n:
                probs.append(f"percentage {n}% attached to {named[0]} but that fact is {expect[named[0]]}%")
    return list(dict.fromkeys(probs))


def local_problems(draft: str, facts: str) -> list[str]:
    """Completeness, length, unsupported-claims, phrase and glue checks; an empty draft is a problem."""
    if not draft or not draft.strip():
        return ["empty"]
    probs = check_reason(draft, facts) + glue_problems(draft, facts)
    if not re.match(r"prioriti[sz]ed because\b", draft.strip(), re.I):
        probs.append("format: must start with 'Prioritised because'")
    if re.search(r"[.!?]\s+\S", draft.strip()):
        probs.append("more than one sentence")
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
SYSTEM_PROMPT = ("Write exactly ONE sentence of at most 35 words in the form: 'Prioritised because <fact>, <fact> and <fact>.' "
                 "Restate every fact given, in plain words and in the order given, and nothing else. Do not predict, interpret or explain, do not say "
                 "what a fact indicates, implies or causes, and do not link facts causally. Every percentage must stay attached to its own fact: the "
                 "EPSS percentile belongs only to EPSS and the KEV-likeness percentile only to the IBM Granite KEV-likeness. Do not repeat the CVE id "
                 "and add no products, numbers, dates or claims that are not in the facts.")


# one worked example shown to the model (facts -> sentence); it must itself pass every local check (tested)
EXAMPLE_FACTS = ("- CVE: CVE-0000-0000\n- Public exploit code: Exploit-DB\n- EPSS percentile within its month: top 7%\n"
                 "- Weakness hints: path traversal")
EXAMPLE_SENTENCE = ("Prioritised because it has public exploit code in Exploit-DB, its EPSS percentile within its month is in the top 7% "
                    "and it is a path traversal flaw.")
RETRY_ADDENDUM = (" Start with the words 'Prioritised because'. Use plain, neutral words with normal spacing and spelling. Do not use any of these words or "
                  "phrases: likelihood, likely, indicating, risk of exploitation, potential for exploitation, strong, mirroring, placing, due to, "
                  "high-impact, highly, serious, dangerous, widespread, widely, actively, in the wild, ransomware, zero-day, confirmed, critical, severe.")


class GraniteRewriter:
    """Loads granite-3.3-2b-instruct once; call it with a fact row to get one sentence. attempt 0 uses the original prompt (greedy);
    attempts 1 and 2 add RETRY_ADDENDUM, and attempt 2 samples with a fixed seed derived from the CVE id."""

    def __init__(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.device = "mps" if torch.backends.mps.is_available() else "cpu"
        self.tok = AutoTokenizer.from_pretrained(GRANITE)
        self.model = AutoModelForCausalLM.from_pretrained(GRANITE, torch_dtype=torch.float16 if self.device == "mps" else None).to(self.device)

    def generate_batch(self, rows: list, attempt: int = 0, batch_size: int = 8) -> list[str]:
        """Same prompts as __call__, generated several rows at a time (left padding) for speed."""
        self.tok.padding_side = "left"
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        system = SYSTEM_PROMPT + (RETRY_ADDENDUM if attempt else "")
        out = []
        for i in range(0, len(rows), batch_size):
            prompts = [self.tok.apply_chat_template(
                [{"role": "system", "content": system}, {"role": "user", "content": EXAMPLE_FACTS},
                 {"role": "assistant", "content": EXAMPLE_SENTENCE}, {"role": "user", "content": facts_text(r)}],
                add_generation_prompt=True, tokenize=False) for r in rows[i:i + batch_size]]
            enc = self.tok(prompts, return_tensors="pt", padding=True, add_special_tokens=False).to(self.device)
            kw = dict(max_new_tokens=60, do_sample=False)
            if attempt >= 2:
                self.torch.manual_seed(100003 + attempt + i)
                kw = dict(max_new_tokens=70, do_sample=True, temperature=0.7, top_p=0.9)
            gen = self.model.generate(**enc, pad_token_id=self.tok.pad_token_id, **kw)
            out += [self.tok.decode(g[enc["input_ids"].shape[1]:], skip_special_tokens=True).strip().split("\n")[0] for g in gen]
        return out

    def __call__(self, r, attempt: int = 0) -> str:
        system = SYSTEM_PROMPT + (RETRY_ADDENDUM if attempt else "")
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": EXAMPLE_FACTS},
                {"role": "assistant", "content": EXAMPLE_SENTENCE}, {"role": "user", "content": facts_text(r)}]
        enc = self.tok.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt", return_dict=True).to(self.device)
        kw = dict(max_new_tokens=70, do_sample=False)
        if attempt >= 2:
            self.torch.manual_seed(int(re.sub(r"\D", "", str(r["cve_id"])) or 0) % 100003 + attempt)
            kw = dict(max_new_tokens=70, do_sample=True, temperature=0.7, top_p=0.9)
        gen = self.model.generate(**enc, **kw)
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


def load_history(path) -> list[dict]:
    """Every record ever written to the cache, in order (the cache is append-only)."""
    recs = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
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
    assert (df["reason"] == df["explanation"]).all(), "reason must be an exact copy of explanation"
    tmp = path.with_suffix(path.suffix + ".tmp")
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)


def problem_class(p: str) -> str:
    """Group a local-check problem for the summary ('number 7' -> 'number not in facts')."""
    for prefix, label in (("number ", "number not in facts"), ("name ", "name not in facts"), ("cve ", "cve id not in facts"),
                          ("unknown or joined word", "unknown or joined word"), ("glued words", "glued words"), ("stray letter", "stray letter"),
                          ("percentage", "percentage not on its own fact"), ("mentions ", "mentions a fact that is not in the facts"), ("format:", "format (not 'Prioritised because ...')")):
        if p.startswith(prefix):
            return label
    return p


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
                 "guardian_ran is true only if the Guardian model returned a Yes or No at least once; template rows whose guardian_verdict is not_run were never "
                 "shown to Guardian.",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **(extra or {})}


def run_stats(items: list[dict], recs: dict, history: list[dict]) -> dict:
    """Extra summary fields, derived from the cache only (so they survive crashes and resumes): local-check failures by class (a row can
    count under several), and the rows whose first, cached Granite sentence failed TODAY's checks and were regenerated."""
    by_id = {it["cve_id"]: it for it in items}
    fails = {}
    for it in items:
        r = recs.get(it["cve_id"])
        if r and r["key"] == it["key"] and r["guardian_verdict"] == "not_run":
            probs = r.get("problems") or local_problems(r.get("draft") or "", it["facts"])    # older records did not store the problems
            for c in {problem_class(p) for p in probs}:
                fails[c] = fails.get(c, 0) + 1
    first = {}
    for r in history:
        first.setdefault(r["cve_id"], r)
    inv_classes, regen, passed = {}, 0, 0
    for c, r0 in first.items():
        it, r = by_id.get(c), recs.get(c)
        if not it or not r or r0["key"] != it["key"] or r is r0 or r.get("attempt", 0) < 1:
            continue
        if r0["source"] == "granite" and r0["guardian_verdict"] == "No":
            probs = local_problems(r0.get("draft") or r0["explanation"], it["facts"])
            if probs:
                regen += 1
                passed += r["source"] == "granite"
                for k in {problem_class(p) for p in probs}:
                    inv_classes[k] = inv_classes.get(k, 0) + 1
    old_prompt = sum(1 for c in {r["cve_id"] for r in history if r["cve_id"] in by_id and r["key"] != by_id[r["cve_id"]]["key"]}
                     if recs.get(c) and recs[c]["key"] == by_id[c]["key"])
    return {"prompt_version": PROMPT_VERSION, "rows_regenerated_for_new_prompt": old_prompt,
            "local_check_failures": dict(sorted(fails.items(), key=lambda kv: -kv[1])),
            "invalidated_by_new_checks": regen, "invalidated_by_class": inv_classes,
            "regenerated_passed_guardian": passed, "regenerated_template_fallback": regen - passed}


def process(items: list[dict], draft_fn, guardian=guardian_verdict, out_dir=OUT_DIR, log=print, time_box_minutes=None,
            batch_draft_fn=None, batch_size: int = 8) -> pd.DataFrame:
    """Run (or resume) the gate over `items` (dicts with cve_id, facts, prose, template, key). draft_fn(item, attempt) returns a draft;
    batch_draft_fn(items, attempt), if given, does the same for several items at once (faster).
    Cached Granite sentences that fail TODAY's local checks are invalidated and regenerated (attempts 1..MAX_ATTEMPTS-1, local failures only),
    then go through Guardian. Writes the cache, explanations.csv and the summary after every chunk of rows; an optional time box leaves the
    remaining rows as template rows marked 'pending'."""
    cache_dir = out_dir / ".cache"
    cache_dir.mkdir(exist_ok=True)
    cache_path = cache_dir / "explain_cache.jsonl"
    recs = load_cache(cache_path)
    invalidated = {}
    for it in items:
        r = recs.get(it["cve_id"])
        if r and r["key"] == it["key"] and r["source"] == "template":
            r["explanation"] = it["template"]                  # template rows always show today's template wording
        if r and r["key"] == it["key"] and r["source"] == "granite":
            probs = local_problems(r.get("draft") or r["explanation"], it["facts"])
            if probs:
                invalidated[it["cve_id"]] = probs
                del recs[it["cve_id"]]
    if invalidated:
        log(f"{len(invalidated)} cached Granite sentences fail the current local checks and will be regenerated")
    write_atomic(rows_frame(items, recs), out_dir / "explanations.csv")
    pending = [it for it in items
               if not ((r := recs.get(it["cve_id"])) and r["key"] == it["key"] and r["guardian_verdict"] not in RETRY)]
    deadline = time.monotonic() + 60 * time_box_minutes if time_box_minutes else None
    done_n = 0
    with open(cache_path, "a") as cache:
        for c0 in range(0, len(pending), batch_size):
            chunk = pending[c0:c0 + batch_size]
            if deadline and time.monotonic() > deadline:
                log(f"time box of {time_box_minutes} minutes reached with {len(pending) - c0} rows left: they keep the template and are marked 'pending'")
                break
            result = {}
            if not draft_fn and not batch_draft_fn:
                for it in chunk:
                    result[it["cve_id"]] = (None, dict(explanation=it["template"], source="template", guardian_verdict="not_run",
                                                       problems=["granite not run"]), 0)
            else:
                open_rows = {it["cve_id"]: it for it in chunk}
                for attempt in range(MAX_ATTEMPTS):
                    need = [it for it in open_rows.values() if attempt >= (1 if it["cve_id"] in invalidated else 0)]
                    if not open_rows:
                        break
                    if not need:
                        continue                                 # only rows that start at a later attempt are open
                    drafts = batch_draft_fn(need, attempt) if batch_draft_fn else [draft_fn(it, attempt) for it in need]
                    for it, draft in zip(need, drafts):
                        d = decide(draft, it["facts"], it["prose"], it["template"], guardian)
                        result[it["cve_id"]] = (draft, d, attempt)
                        if d["source"] == "granite" or d["guardian_verdict"] != "not_run":
                            del open_rows[it["cve_id"]]          # accepted, or Guardian already judged it: no retry
                for cid, (draft, d, attempt) in result.items():
                    if d["source"] == "template" and d["guardian_verdict"] == "not_run":
                        log(f"{cid}: kept template, Granite draft rejected locally: {d['problems']}")
            for it in chunk:
                draft, d, attempt = result[it["cve_id"]]
                rec = dict(cve_id=it["cve_id"], key=it["key"], draft=draft, attempt=attempt, problems=d["problems"],
                           **{k: d[k] for k in ("explanation", "source", "guardian_verdict")})
                cache.write(json.dumps(rec) + "\n")
                recs[it["cve_id"]] = rec
            cache.flush()
            df = rows_frame(items, recs)
            write_atomic(df, out_dir / "explanations.csv")
            (out_dir / "explanations_summary.json").write_text(json.dumps(summarize(df, run_stats(items, recs, load_history(cache_path))), indent=1))
            done_n += len(chunk)
            log(f"  {done_n}/{len(pending)} done; {summarize(df)['passed_guardian']} passed Guardian so far")
    df = rows_frame(items, recs)
    write_atomic(df, out_dir / "explanations.csv")
    (out_dir / "explanations_summary.json").write_text(json.dumps(summarize(df, run_stats(items, recs, load_history(cache_path))), indent=1))
    return df


def latest_top() -> str:
    files = sorted(OUT_DIR.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    final = OUT_DIR / "top500_final.csv"
    return str(final if final.exists() else files[-1])


def main(top_path=None, granite=False, limit=None, use_guardian=True, time_box=None):
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

    def draft_fn(it, attempt=0):  # the model is loaded on first use, so resuming a finished run costs nothing
        holder.setdefault("w", GraniteRewriter())
        return holder["w"](it["row"], attempt)

    def batch_fn(batch, attempt=0):
        holder.setdefault("w", GraniteRewriter())
        return holder["w"].generate_batch([it["row"] for it in batch], attempt)

    guardian = guardian_verdict if use_guardian else (lambda facts, draft: "not_run")
    df = process(items, draft_fn if granite else None, guardian, time_box_minutes=time_box, batch_draft_fn=batch_fn if granite else None)
    summary = json.loads((OUT_DIR / "explanations_summary.json").read_text())
    summary["top_list"] = os.path.basename(top_path)
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
    ap.add_argument("--time-box", type=float, help="stop after this many minutes; unfinished rows stay template and are marked pending")
    a = ap.parse_args()
    main(a.top, a.granite, a.limit, use_guardian=not a.no_guardian, time_box=a.time_box)
