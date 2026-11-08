"""Person B, issue #12: Granite fact extraction -> outputs/extracted_features.parquet (contract file).

Run:  python -m src.b.extract --limit 50     # quick timing test
      python -m src.b.extract                # top CVEs of each pool (see select())

A local Granite instruct model reads ONE description at a time and must answer with constrained JSON:
  product_type       one of PRODUCT_TYPES
  auth_required      yes | no | unknown
  network_reachable  yes | no | unknown
  impact_type        one of IMPACT_TYPES
Anything outside the allowed values becomes null, and guard() fixes or blanks labels the description
contradicts (e.g. 'wordpress_plugin' when WordPress is never mentioned; 'unauthenticated' in the text forces auth_required=no). The same prompt and settings are used for every pool
(replica 2024 / 2025 and the scoreboard). Time-safety: it reads only the description, with post-attack
phrases already stripped (outputs/b_texts.parquet), exactly like the txt_* flags.

Status: DESCRIPTIVE. The feature freeze has passed, so these columns are used to describe the blind spots
and the top 500 (dashboard and write-up), not as model inputs.
Which CVEs: per pool, the top N by kev_text_score plus the top N by within-month EPSS rank, every CVE
in the newest top-500 list (label-blind). `--profile` additionally labels every exploited replica CVE into the cache for
the descriptive blind-spot profile only; extracted_features.parquet is always written from the label-blind set. Rows are cached in outputs/b_extract_cache.parquet, so reruns resume.
"""
import argparse
import json
import re
import time

import pandas as pd

from src.common.paths import OUT_DIR

GRANITE = "ibm-granite/granite-3.3-2b-instruct"
PRODUCT_TYPES = ["network_edge_device", "web_application", "wordpress_plugin", "operating_system", "browser",
                 "enterprise_server_software", "iot_or_firmware", "library_or_framework", "desktop_application",
                 "mobile_app", "other"]
IMPACT_TYPES = ["remote_code_execution", "privilege_escalation", "authentication_bypass", "information_disclosure",
                "denial_of_service", "cross_site_scripting", "sql_injection", "file_read_or_write", "other"]
YNU = ["yes", "no", "unknown"]
FIELDS = {"product_type": PRODUCT_TYPES, "auth_required": YNU, "network_reachable": YNU, "impact_type": IMPACT_TYPES}
CACHE = OUT_DIR / "b_extract_cache.parquet"
SYSTEM = """You label software vulnerabilities. Read the description and answer with ONLY one JSON object.

Keys and allowed values (pick exactly one each):
"product_type":
  network_edge_device = VPN, firewall, router, gateway, load balancer, remote-access appliance
  web_application = any web app, CMS, PHP/Java/.NET site or admin panel (not WordPress)
  wordpress_plugin = only if the text says WordPress
  operating_system = Windows, Linux kernel, macOS, iOS, Android OS
  browser = Chrome, Firefox, Safari, Edge, WebKit, V8
  enterprise_server_software = servers and server products: FTP, mail, database, Exchange, VMware, backup, monitoring
  iot_or_firmware = cameras, printers, IoT, embedded firmware
  library_or_framework = a code library, package or framework
  desktop_application = software installed on a PC (office, media player, ActiveX)
  mobile_app = only an app for phones
  other = none of these
"auth_required": yes = the attacker must log in or be authenticated first; no = unauthenticated or remote attacker without login; unknown = not stated
"network_reachable": yes = attackable over a network or the internet; no = needs local or physical access; unknown = not stated
"impact_type": remote_code_execution, privilege_escalation, authentication_bypass, information_disclosure,
  denial_of_service, cross_site_scripting, sql_injection, file_read_or_write, other (choose the main consequence)

Example
Description: An unauthenticated remote attacker can send a crafted request to the SSL VPN of FortiOS to execute arbitrary code.
Answer: {"product_type": "network_edge_device", "auth_required": "no", "network_reachable": "yes", "impact_type": "remote_code_execution"}"""


def parse(text: str) -> dict:
    """Pull the JSON object out of the model's answer; keep only allowed values (else None)."""
    m = re.search(r"\{.*?\}", text, re.S)
    try:
        raw = json.loads(m.group(0)) if m else {}
    except json.JSONDecodeError:
        raw = {}
    out = {}
    for k, allowed in FIELDS.items():
        v = str(raw.get(k, "")).strip().lower().replace(" ", "_").replace("-", "_")
        out[k] = v if v in allowed else None
    return out

# ---- consistency guard: the description must support the label (same idea as the explanation fact-checker) ----
NEEDS = {  # product_type -> words that must appear in the description
    "wordpress_plugin": r"wordpress|\bwp[- ]",
    "mobile_app": r"android|\bios\b|iphone|ipad|mobile app|smartphone|phone app",
    "browser": r"chrome|chromium|firefox|safari|webkit|\bedge\b|\bv8\b|browser",
    "operating_system": r"windows|linux|kernel|macos|\bios\b|android|freebsd|unix|operating system",
    "network_edge_device": r"vpn|firewall|router|gateway|load balancer|remote access|switch|access point|appliance",
}
WEB = r"\.php|\.asp|\.jsp|web|http|cms|admin panel|portal|site"
UNAUTH = r"\bunauthenticated\b|without (prior )?authentication|no authentication|without logging in|unauthorized remote"
AUTH = r"\bauthenticated (user|attacker|admin|remote)|requires authentication|post-auth|logged[- ]in|with valid credentials"


def guard(row: dict, desc: str) -> tuple[dict, list[str]]:
    """Fix or blank labels that the description contradicts. Returns (row, list of changes)."""
    d, out, changes = desc.lower(), dict(row), []
    pt = out.get("product_type")
    if pt in NEEDS and not re.search(NEEDS[pt], d):
        out["product_type"] = "web_application" if re.search(WEB, d) else None
        changes.append(f"product_type {pt}->{out['product_type']}")
    if re.search(UNAUTH, d) and out.get("auth_required") != "no":
        changes.append(f"auth_required {out.get('auth_required')}->no")
        out["auth_required"] = "no"
    elif re.search(AUTH, d) and not re.search(UNAUTH, d) and out.get("auth_required") != "yes":
        changes.append(f"auth_required {out.get('auth_required')}->yes")
        out["auth_required"] = "yes"
    return out, changes


def select(n_per_score: int = 1500, with_positives: bool = False) -> pd.DataFrame:
    """Label-blind selection (top N by kev_text_score and by EPSS rank per pool + the newest top-500). with_positives=True
    also adds every exploited replica CVE: ONLY for the descriptive profile, never for extracted_features.parquet."""
    tf = pd.read_parquet(OUT_DIR / "text_features.parquet", columns=["cve_id", "kev_text_score"])
    picks = []
    for f in ("features_replica_2024", "features_replica_2025", "features_scoreboard"):
        d = pd.read_parquet(OUT_DIR / f"{f}.parquet", columns=["cve_id", "epss_rank_in_month"]).merge(tf, on="cve_id")
        picks += [d.nlargest(n_per_score, "kev_text_score")["cve_id"], d.nlargest(n_per_score, "epss_rank_in_month")["cve_id"]]
    if with_positives:  # descriptive blind-spot profile only (labels never feed a model)
        for y in (2024, 2025):
            r = pd.read_parquet(OUT_DIR / f"replica_{y}.parquet", columns=["cve_id", "label"])
            picks.append(r.loc[r["label"] == 1, "cve_id"])
    tops = sorted(OUT_DIR.glob("top500_v*.csv"), key=lambda p: int(re.findall(r"\d+", p.stem)[-1]))
    if tops:
        picks.append(pd.read_csv(tops[-1])["cve_id"])
    ids = pd.Series(pd.concat(picks).unique(), name="cve_id")
    texts = pd.read_parquet(OUT_DIR / "b_texts.parquet", columns=["cve_id", "description"])
    return texts[texts["cve_id"].isin(ids)].reset_index(drop=True)


def run(rows: pd.DataFrame, batch: int = 16) -> pd.DataFrame:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    tok = AutoTokenizer.from_pretrained(GRANITE, padding_side="left")
    model = AutoModelForCausalLM.from_pretrained(
        GRANITE, torch_dtype=torch.float16 if device == "mps" else None).to(device)
    out, t0 = [], time.time()
    for i in range(0, len(rows), batch):
        chunk = rows.iloc[i:i + batch]
        prompts = [tok.apply_chat_template([{"role": "system", "content": SYSTEM},
                                            {"role": "user", "content": "Description: " + d[:1500] + "\nAnswer:"}],
                                           add_generation_prompt=True, tokenize=False)
                   for d in chunk["description"]]
        enc = tok(prompts, return_tensors="pt", padding=True).to(device)
        with torch.no_grad():
            gen = model.generate(**enc, max_new_tokens=70, do_sample=False)
        answers = tok.batch_decode(gen[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)
        for c, a, desc in zip(chunk["cve_id"], answers, chunk["description"]):
            row, changes = guard(parse(a), desc)
            out.append({"cve_id": c, **row, "guard_changes": "; ".join(changes)})
        if (i // batch) % 20 == 0:
            done = i + len(chunk)
            print(f"{done:,}/{len(rows):,} in {time.time() - t0:,.0f}s "
                  f"(~{(time.time() - t0) / done * (len(rows) - done) / 60:.0f} min left)", flush=True)
    return pd.DataFrame(out)


def main(limit=None, n_per_score=1500, profile=False):
    """profile=False: label the label-blind set and write the contract file extracted_features.parquet.
    profile=True: also label the exploited replica CVEs into the cache (for src.b.profile); the contract file is still
    written from the label-blind set only, so its coverage can never encode the label."""
    rows = select(n_per_score, with_positives=profile)
    blind_rows = select(n_per_score) if profile else rows
    cache = pd.read_parquet(CACHE) if CACHE.exists() else pd.DataFrame(columns=["cve_id", *FIELDS, "guard_changes"])
    todo = rows[~rows["cve_id"].isin(cache["cve_id"])]
    if limit:
        todo = todo.head(limit)
    print(f"{len(rows):,} CVEs selected, {len(cache):,} cached, {len(todo):,} to label")
    step = 400
    for s in range(0, len(todo), step):  # save as we go so a stop loses at most one step
        new = run(todo.iloc[s:s + step])
        cache = pd.concat([cache, new], ignore_index=True).drop_duplicates("cve_id", keep="last")
        cache.to_parquet(CACHE, index=False)
    out = cache[cache["cve_id"].isin(blind_rows["cve_id"])].copy()
    print(f"consistency guard changed {(out['guard_changes'].fillna('') != '').mean():.0%} of rows")
    out = out.drop(columns=["guard_changes"])
    for k in FIELDS:
        out[k] = out[k].astype("string").astype(object).where(out[k].notna(), None)
    out = out.sort_values("cve_id").reset_index(drop=True)
    out.to_parquet(OUT_DIR / "extracted_features.parquet", index=False)
    print(f"wrote extracted_features.parquet: {len(out):,} rows; null share:",
          out[list(FIELDS)].isna().mean().round(3).to_dict())
    for k in FIELDS:
        print(k, out[k].value_counts(dropna=False).head(6).to_dict())
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    ap.add_argument("--n-per-score", type=int, default=1500)
    ap.add_argument("--profile", action="store_true", help="also label exploited replica CVEs for the descriptive profile")
    a = ap.parse_args()
    main(a.limit, a.n_per_score, a.profile)
