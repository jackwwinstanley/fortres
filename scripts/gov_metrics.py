"""IBM watsonx.governance scoring of our explanation sentences, guarded so that nothing costly happens unless asked for.

Two separate results, never mixed:
  * LOCAL  (free, no credentials, no IBM service): token / embedding / readability metrics computed on this machine with the
    IBM watsonx.governance SDK -> outputs/gov_metrics.csv + outputs/gov_metrics_summary.json   (`--local`)
  * HOSTED (uses the IBM Cloud Lite quota): Granite Guardian faithfulness, answer relevance and harm, and IBM's HAP and PII
    detectors, run by IBM watsonx.governance on IBM Cloud -> outputs/watsonx_gov_metrics.csv + outputs/watsonx_gov_summary.json
    (`--run --confirm-spend`). Written only after a real run.

Modes
  (no flags)                      DRY RUN: checks the inputs and prints what a hosted run would do (rows, metrics, region/plan,
                                  calls = rows to score x metrics, cached rows, SDK version). No network, no files written.
  --check-one --confirm-spend     ONE row x 5 metrics = 5 hosted calls, to test the credentials. Writes nothing but the cache.
  --run --confirm-spend [--rows sample100|all]
                                  the hosted run. sample100 (default) = fixed random sample of 100, seed 31.
  --local                         the free local metrics on all rows (no credentials; sets the SDK's WATSONX_SERVER=WXGOV
                                  switch, which lets its token/embedding methods run without a client).
  --import-hosted CSV --scored-at COMMIT
                                  seed the cache from an earlier hosted run's per-row CSV (no IBM call). Refused unless
                                  explanations.csv, the fact inputs and src/b/explain.py are byte-identical at COMMIT and now.

Safety: a hosted run needs BOTH --run (or --check-one) and --confirm-spend AND WATSONX_APIKEY in the environment. Before any
mode except the dry run's report, the inputs must be final: outputs/explanations.csv covers exactly the ids of the primary
model's top-500 list, outputs/explanations_summary.json has pending == 0 and its top_list is that list. Results are cached per
row under outputs/.cache/gov (gitignored), keyed by cve_id + hash(facts, sentence) + SDK version, and written after every
batch, so a sample run followed by --rows all only pays for new rows. The first quota / rate-limit error stops the run cleanly
(recorded in `stopped`); transient network errors are retried at most twice; nothing loops. This module is never imported by
refresh_all, the tests' other modules, the dashboard or any other code. Only public CVE facts (src.b.explain.facts_prose) and
our own sentences are sent; nothing under data/. The key and instance ids are never printed or written.

Environment (the SDK needs Python >=3.11,<3.14; the repo runs on 3.14, so it gets its own env; never add it to requirements.txt):
    uv venv --python 3.11 .venv-gov
    uv pip install --python .venv-gov/bin/python -r requirements-gov.txt
    .venv-gov/bin/python -m scripts.gov_metrics                         # dry run
    .venv-gov/bin/python -m scripts.gov_metrics --local                 # free local scores, all rows
    set -a; source /path/to/.env; set +a                                # puts WATSONX_APIKEY in the environment, prints nothing
    .venv-gov/bin/python -m scripts.gov_metrics --check-one --confirm-spend
    .venv-gov/bin/python -m scripts.gov_metrics --run --confirm-spend --rows all
Optional environment: WATSONX_REGION (default ca-tor), WXG_INSTANCE_NAME (default watsonx.governance-pv: a display name).
"""
import argparse
import hashlib
import importlib.metadata as md
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"
CACHE = OUT / ".cache" / "gov"
SAMPLE_N, SAMPLE_SEED = 100, 31
REGION_DEFAULT = "ca-tor"
INSTANCE_DEFAULT = "watsonx.governance-pv"
PLAN = "Lite"
FACT_INPUTS = ["outputs/explanations.csv", "outputs/features_scoreboard.parquet", "outputs/text_features.parquet",
               "outputs/v5_top500_contrib.parquet", "src/b/explain.py"]

# hosted: (SDK class, method, output column)
HOSTED = [("FaithfulnessMetric", "granite_guardian", "faithfulness__granite_guardian"),
          ("AnswerRelevanceMetric", "granite_guardian", "answer_relevance__granite_guardian"),
          ("OutputHAPMetric", None, "output_hap"),
          ("OutputPIIMetric", None, "output_pii"),
          ("HarmMetric", "granite_guardian", "harm__granite_guardian")]
# local: (SDK class, method, what it compares, note)
LOCAL = [
    ("FaithfulnessMetric", "token_k_precision", "output vs facts", "share of the sentence's tokens found in the facts"),
    ("FaithfulnessMetric", "sentence_bert_mini_lm", "output vs facts", "MiniLM embedding similarity, sentence vs facts"),
    ("AnswerSimilarityMetric", "token_recall", "output vs template", "share of the template sentence's tokens in our sentence"),
    ("AnswerSimilarityMetric", "bert_score_recall", "output vs template", "BERTScore recall vs the template sentence"),
    ("AnswerSimilarityMetric", "sentence_bert_mini_lm", "output vs template", "MiniLM embedding similarity vs template"),
    ("AnswerRelevanceMetric", "token_recall", "output vs fixed question", "question is one we wrote; low information"),
    ("TextGradeLevelMetric", "flesch_kincaid_grade", "output only", "readability (textstat)"),
    ("TextReadingEaseMetric", "flesch_reading_ease", "output only", "readability (textstat)"),
]
# no-credential inventory probe (local mode): every metric/method that applies to one (input, context, output) sentence
INVENTORY = [
    ("FaithfulnessMetric", ["token_k_precision", "sentence_bert_mini_lm", "llm_as_judge", "granite_guardian", "faithfulness_model"]),
    ("AnswerRelevanceMetric", ["token_recall", "llm_as_judge", "granite_guardian", "answer_relevance_model"]),
    ("ContextRelevanceMetric", ["token_precision", "sentence_bert_bge", "sentence_bert_mini_lm", "llm_as_judge", "granite_guardian",
                                "context_relevance_model"]),
    ("AnswerSimilarityMetric", ["token_recall", "bert_score_recall", "sentence_bert_mini_lm", "llm_as_judge"]),
    *[(c, [None]) for c in ["TextGradeLevelMetric", "TextReadingEaseMetric", "HAPMetric", "OutputHAPMetric", "PIIMetric",
                            "OutputPIIMetric", "HarmMetric", "SocialBiasMetric", "ProfanityMetric", "ViolenceMetric",
                            "SexualContentMetric", "UnethicalBehaviorMetric", "EvasivenessMetric", "JailbreakMetric",
                            "HarmEngagementMetric", "PromptSafetyRiskMetric", "TopicRelevanceMetric", "KeywordDetectionMetric",
                            "RegexDetectionMetric", "OutputTokenCountMetric"]],
]
EXTRA_KW = {"KeywordDetectionMetric": {"keywords": ["password"]}, "RegexDetectionMetric": {"regex_patterns": [r"\d{3}-\d{2}-\d{4}"]},
            "TopicRelevanceMetric": {"system_prompt": "Explain CVE prioritisation."},
            "PromptSafetyRiskMetric": {"system_prompt": "Explain CVE prioritisation."}}
BATCH = 25
QUOTA_PAT = re.compile(r"\b429\b|quota|rate.?limit|too many requests|limit (?:has been )?(?:reached|exceeded)|exceeded|"
                       r"insufficient|lite plan|capacity units?|\b402\b", re.I)
TRANSIENT_PAT = re.compile(r"timed? ?out|timeout|connection (?:reset|aborted|refused|error)|temporarily|\b50[234]\b|"
                           r"remote ?disconnected|name resolution", re.I)


class Refused(SystemExit):
    pass


def refuse(msg: str):
    print(f"gov_metrics: refused: {msg}", file=sys.stderr)
    raise Refused(2)


def sdk_version() -> str:
    try:
        return md.version("ibm-watsonx-gov")
    except md.PackageNotFoundError:
        return "not installed"


def redact(s: str) -> str:
    v = os.environ.get("WATSONX_APIKEY")
    if v:
        s = s.replace(v, "<redacted>")
    s = re.sub(r"\x1b\[[0-9;]*m", "", s)
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<redacted-id>", s)
    s = re.sub(r"crn:[^\s'\"]+", "<redacted-crn>", s)
    return re.sub(r"[A-Za-z0-9_-]{32,}", "<redacted>", s)


# ---- inputs -----------------------------------------------------------------------------------------------------------
def primary_list(out: Path = OUT) -> str:
    """The primary model's top-500 file: top500_final.csv if present, else top500_<tag>.csv from headline.json's `primary`."""
    if (out / "top500_final.csv").exists():
        return "top500_final.csv"
    prim = json.loads((out / "headline.json").read_text()).get("primary", "")
    m = re.match(r"\s*(v\d+)\b", prim)
    if not m:
        refuse(f"cannot tell the primary model from headline.json primary={prim!r}")
    return f"top500_{m.group(1)}.csv"


def input_problems(out: Path = OUT) -> list[str]:
    import pandas as pd
    probs = []
    top_name = primary_list(out)
    try:
        s = json.loads((out / "explanations_summary.json").read_text())
    except FileNotFoundError:
        return ["outputs/explanations_summary.json is missing"]
    if s.get("pending", None) != 0:
        probs.append(f"explanations_summary.json pending = {s.get('pending')!r}, must be 0")
    if s.get("top_list") != top_name:
        probs.append(f"explanations_summary.json top_list = {s.get('top_list')!r}, primary model's list is {top_name!r}")
    ex = pd.read_csv(out / "explanations.csv")
    top = pd.read_csv(out / top_name)
    if ex["cve_id"].duplicated().any():
        probs.append("explanations.csv has duplicate cve_ids")
    a, b = set(ex["cve_id"]), set(top["cve_id"])
    if a != b:
        probs.append(f"explanations.csv ids differ from {top_name}: {len(a - b)} extra, {len(b - a)} missing")
    if ex["explanation"].isna().any():
        probs.append("explanations.csv has empty explanations")
    return probs


def build_rows(out: Path = OUT):
    import pandas as pd
    sys.path.insert(0, str(ROOT))
    from src.b import explain as E
    ex = pd.read_csv(out / "explanations.csv")
    f = E.facts_for(ex[["cve_id"]], out_dir=out).set_index("cve_id", drop=False)
    return pd.DataFrame({"record_id": ex["cve_id"], "source": ex["source"],
                         "input_text": "Why is " + ex["cve_id"] + " prioritised?",
                         "context": [E.facts_prose(f.loc[c]) for c in ex["cve_id"]], "generated_text": ex["explanation"],
                         "ground_truth": [E.template(f.loc[c]) for c in ex["cve_id"]]})


def select_rows(df, rows: str):
    if rows == "all":
        return df.reset_index(drop=True)
    return df.sample(n=min(SAMPLE_N, len(df)), random_state=SAMPLE_SEED).reset_index(drop=True)


def rows_label(rows: str, n: int) -> str:
    return "all rows" if rows == "all" else f"fixed random sample of {n}, seed {SAMPLE_SEED}"


# ---- cache ------------------------------------------------------------------------------------------------------------
def row_key(cve: str, facts: str, sentence: str, version: str) -> str:
    h = hashlib.sha256(f"{facts}\n\x00\n{sentence}\n\x00\n{version}".encode()).hexdigest()[:16]
    return f"{cve}__{h}"


def cache_get(key: str, cache: Path = CACHE) -> dict:
    p = cache / f"{key}.json"
    return json.loads(p.read_text()).get("values", {}) if p.exists() else {}


def cache_put(key: str, values: dict, where: str, cache: Path = CACHE):
    cache.mkdir(parents=True, exist_ok=True)
    p = cache / f"{key}.json"
    old = json.loads(p.read_text()) if p.exists() else {"values": {}}
    old["values"].update(values)
    old["where"] = where
    old["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(old, indent=1))
    tmp.replace(p)


def keys_for(df, version: str) -> list[str]:
    return [row_key(c, f, s, version) for c, f, s in zip(df["record_id"], df["context"], df["generated_text"])]


# ---- hosted (network only here) ---------------------------------------------------------------------------------------
def make_client():
    """Log in with WATSONX_APIKEY and target the named watsonx.governance instance. Returns (client, where)."""
    import requests
    from ibm_watsonx_gov.clients.api_client import APIClient
    from ibm_watsonx_gov.entities.credentials import Credentials
    region = os.environ.setdefault("WATSONX_REGION", REGION_DEFAULT)
    name = os.environ.get("WXG_INSTANCE_NAME", INSTANCE_DEFAULT)
    os.environ.pop("WATSONX_SERVER", None)
    if not os.environ.get("WXG_SERVICE_INSTANCE_ID"):  # several instances on the account: the SDK cannot choose one itself
        tok = requests.post("https://iam.cloud.ibm.com/identity/token", timeout=30,
                            data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                                  "apikey": os.environ["WATSONX_APIKEY"]}).json()["access_token"]
        res = requests.get("https://resource-controller.cloud.ibm.com/v2/resource_instances?limit=100", timeout=30,
                           headers={"Authorization": "Bearer " + tok}).json().get("resources", [])
        hit = [r for r in res if r.get("name") == name and r.get("region_id") == region and r.get("state") == "active"]
        if len(hit) != 1:
            refuse(f"expected exactly one active {name} in {region}, found {len(hit)}")
        os.environ["WXG_SERVICE_INSTANCE_ID"] = hit[0]["guid"]  # this process only
    client = APIClient(credentials=Credentials.create_from_env())
    return client, f"IBM watsonx.governance ({name}, {region}, {PLAN} plan) on IBM Cloud"


def score_batch(client, cls: str, method, df) -> dict:
    """One SDK evaluation through MetricsEvaluator (the SDK sets up its watsonx.governance context only there)."""
    import ibm_watsonx_gov.metrics as M
    from ibm_watsonx_gov.config import GenAIConfiguration
    from ibm_watsonx_gov.evaluators import MetricsEvaluator
    cfg = GenAIConfiguration(input_fields=["input_text"], context_fields=["context"], output_fields=["generated_text"],
                             reference_fields=["ground_truth"], record_id_field="record_id")
    metric = getattr(M, cls)(**({"method": method} if method else {}))
    res = MetricsEvaluator(configuration=cfg, api_client=client).evaluate(
        data=df[["record_id", "input_text", "context", "generated_text", "ground_truth"]], metrics=[metric])
    vals = {x.record_id: x.value for agg in res.metrics_result for x in agg.record_level_metrics}
    if len(vals) != len(df):
        raise RuntimeError(f"SDK returned {len(vals)} values for {len(df)} rows")
    return vals


def call_with_retry(fn, *a, retries: int = 2):
    """Transient network errors: at most `retries` more tries. Anything else (quota included) is raised at once."""
    for attempt in range(retries + 1):
        try:
            return fn(*a)
        except Exception as e:  # noqa: BLE001
            msg = f"{type(e).__name__}: {e}"
            if QUOTA_PAT.search(msg) or not TRANSIENT_PAT.search(msg) or attempt == retries:
                raise
            time.sleep(2 * (attempt + 1))


def hosted(rows: str, one: bool, out: Path = OUT, cache: Path = CACHE) -> dict:
    t0 = time.time()
    df = select_rows(build_rows(out), rows)
    if one:
        df = df.head(1)
    version = sdk_version()
    keys = keys_for(df, version)
    client, where = make_client()
    stopped, calls = None, 0
    for cls, method, col in HOSTED:
        todo = [i for i, k in enumerate(keys) if col not in cache_get(k, cache)]
        for s in range(0, len(todo), BATCH):
            idx = todo[s:s + BATCH]
            part = df.iloc[idx]
            try:
                vals = call_with_retry(score_batch, client, cls, method, part)
                calls += len(part)
            except Exception as e:  # noqa: BLE001
                msg = redact(f"{type(e).__name__}: {e}")[:1500]
                kind = "quota or rate limit" if QUOTA_PAT.search(msg) else "error"
                stopped = f"{kind} on {cls}/{method or 'default'} after {calls} scored calls: {msg}"
                break
            for i in idx:
                cache_put(keys[i], {col: vals[df["record_id"].iat[i]]}, where, cache)
        if stopped:
            break
    result = dict(df=df, keys=keys, where=where, stopped=stopped, calls=calls, version=version,
                  secs=round(time.time() - t0, 1))
    if not one:
        write_hosted(result, rows, out, cache)
    return result


def hosted_claim(where: str, n: int, by_source: dict, complete: bool) -> str:
    src = ", ".join(f"{v} {k}" for k, v in sorted(by_source.items()))
    s = f"{n} explanation sentences ({src}) scored with metrics hosted on {where}"
    return s + ("." if complete else " (incomplete run: see `stopped`).")


def write_hosted(r: dict, rows: str, out: Path = OUT, cache: Path = CACHE):
    import pandas as pd
    df, keys = r["df"], r["keys"]
    tab = pd.DataFrame({"cve_id": df["record_id"], "source": df["source"]})
    for _, _, col in HOSTED:
        tab[col] = [cache_get(k, cache).get(col) for k in keys]
    cols = [c for _, _, c in HOSTED]
    scored = tab.dropna(subset=cols)
    metrics = []
    for cls, method, col in HOSTED:
        s = tab[col].dropna().astype(float)
        m = dict(column=col, metric=cls, method=method, where=r["where"], n=int(len(s)))
        if len(s):
            m.update(mean=round(s.mean(), 4), median=round(s.median(), 4), min=round(s.min(), 4), max=round(s.max(), 4),
                     n_ge_0_5=int((s >= 0.5).sum()),
                     mean_by_source={k: round(v, 4) for k, v in s.groupby(tab.loc[s.index, "source"]).mean().items()})
        metrics.append(m)
    by_source = {k: int(v) for k, v in scored["source"].value_counts().items()}
    summary = dict(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sdk="ibm-watsonx-gov", sdk_version=r["version"], where=r["where"],
        claim=hosted_claim(r["where"], int(len(scored)), by_source, complete=r["stopped"] is None and len(scored) == len(tab)),
        rows=dict(file="outputs/explanations.csv", which=rows_label(rows, len(tab)), requested=int(len(tab)),
                  n=int(len(scored)), by_source=by_source),
        sent="public CVE facts (src.b.explain.facts_prose) and our own explanation sentences only; nothing from data/",
        usage_or_cost=f"not reported by the SDK or API responses; {PLAN} plan",
        metrics=metrics, stopped=r["stopped"], calls_this_run=r["calls"], runtime_secs=r["secs"],
    )
    tab.to_csv(out / "watsonx_gov_metrics.csv", index=False)
    (out / "watsonx_gov_summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n")
    print(json.dumps({k: summary[k] for k in ("claim", "stopped", "calls_this_run", "runtime_secs")}, indent=1))


# ---- local (free) -----------------------------------------------------------------------------------------------------
def colname(cls, method):
    base = re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", cls.removesuffix("Metric")).lower()
    return f"{base}__{method}" if method else base


def local(out: Path = OUT):
    for k in list(os.environ):  # never any credentials in the local run
        if k.startswith(("WATSONX", "WXG", "WML", "IBM_CLOUD", "IBMCLOUD")):
            os.environ.pop(k)
    os.environ["WATSONX_SERVER"] = "WXGOV"
    import pandas as pd
    import ibm_watsonx_gov.metrics as M
    from ibm_watsonx_gov.config import GenAIConfiguration
    cfg = GenAIConfiguration(input_fields=["input_text"], context_fields=["context"], output_fields=["generated_text"],
                             reference_fields=["ground_truth"], record_id_field="record_id")
    t0 = time.time()
    df = build_rows(out)
    data = df[["record_id", "input_text", "context", "generated_text", "ground_truth"]]
    inventory = []
    for server in (None, "WXGOV"):  # as installed, then with the SDK's WATSONX_SERVER switch; no client, so no IBM call
        os.environ.pop("WATSONX_SERVER", None)
        if server:
            os.environ["WATSONX_SERVER"] = server
        for cls, methods in INVENTORY:
            for m in methods:
                try:
                    kw = dict(EXTRA_KW.get(cls, {}), **({"method": m} if m else {}))
                    r = getattr(M, cls)(**kw).evaluate(data=data.head(3), configuration=cfg)
                    status, err = ("ran", "") if r is not None else ("error", "SDK returned no result")
                except Exception as e:  # noqa: BLE001
                    status, err = "error", redact(f"{type(e).__name__}: {e}")
                    err = err.split("Reason:")[0] + ("Reason: " + err.split("Missing package")[-1][:200] if "Missing package" in err else "")
                inventory.append(dict(metric=cls, method=m, watsonx_server_env=server, no_credentials_result=status, error=err[:500]))
    os.environ["WATSONX_SERVER"] = "WXGOV"
    t1 = time.time()
    tab = df[["record_id", "source"]].rename(columns={"record_id": "cve_id"}).copy()
    summary_metrics = []
    for cls, m, compares, note in LOCAL:
        ts = time.time()
        metric = getattr(M, cls)(method=m)
        r = metric.evaluate(data=data, configuration=cfg)
        col = colname(cls, m)
        tab[col] = tab["cve_id"].map({x.record_id: x.value for x in r.record_level_metrics})
        s = tab[col].astype(float)
        summary_metrics.append(dict(column=col, metric=cls, method=m, compares=compares, note=note,
                                    where="local (this machine; IBM watsonx.governance SDK, no IBM service called)",
                                    n=int(s.notna().sum()), mean=round(s.mean(), 4), median=round(s.median(), 4),
                                    min=round(s.min(), 4), max=round(s.max(), 4),
                                    mean_by_source={k: round(v, 4) for k, v in s.groupby(tab["source"]).mean().items()},
                                    secs=round(time.time() - ts, 1)))
    tab.to_csv(out / "gov_metrics.csv", index=False)
    freeze = sorted(f"{d.metadata['Name']}=={d.version}" for d in md.distributions())
    summary = dict(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sdk="ibm-watsonx-gov", sdk_version=sdk_version(), sdk_requires_python=md.metadata("ibm-watsonx-gov")["Requires-Python"],
        python=platform.python_version(), env=".venv-gov (separate from the project venv)",
        claim=f"Computed locally with the IBM watsonx.governance SDK on {len(df)} explanation sentences. "
              "No IBM service was called: no credentials were set.",
        credentials_used=False,
        credentialed_route="kept separately: hosted results go only to outputs/watsonx_gov_summary.json (--run --confirm-spend)",
        how_local_methods_were_enabled=("The SDK's token/embedding methods need a client unless its own WATSONX_SERVER=WXGOV "
                                        "environment switch is set; with it they compute locally via unitxt."),
        rows=dict(file="outputs/explanations.csv", n=len(df), which="all rows", by_source=df["source"].value_counts().to_dict()),
        inputs=dict(context="src.b.explain.facts_prose", generated_text="explanations.csv explanation",
                    ground_truth="src.b.explain.template", input_text="'Why is <CVE> prioritised?' (fixed question we wrote)"),
        metrics=summary_metrics, inventory=inventory,
        runtime_secs=dict(total=round(time.time() - t0, 1), inventory=round(t1 - t0, 1), local_scoring_all_rows=round(time.time() - t1, 1)),
        pip_freeze=freeze)
    (out / "gov_metrics_summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n")
    print(summary["claim"])


# ---- import an earlier hosted run into the cache (no IBM call) ---------------------------------------------------------
def import_hosted(csv: Path, commit: str, where: str, out: Path = OUT, cache: Path = CACHE, root: Path = ROOT) -> int:
    import pandas as pd

    def blob(rev, path):
        return subprocess.run(["git", "-C", str(root), "rev-parse", f"{rev}:{path}"], capture_output=True, text=True).stdout.strip()

    changed = [p for p in FACT_INPUTS if not blob(commit, p) or blob(commit, p) != blob("HEAD", p)]
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--", *FACT_INPUTS], capture_output=True,
                           text=True).stdout.strip()
    if changed or dirty:
        refuse(f"inputs differ between {commit} and now ({', '.join(changed) or 'uncommitted changes'}); cannot reuse scores")
    old = pd.read_csv(csv)
    cols = [c for _, _, c in HOSTED if c in old.columns]
    df = build_rows(out).set_index("record_id", drop=False)
    version = sdk_version()
    n = 0
    for _, r in old.iterrows():
        if r["cve_id"] not in df.index:
            continue
        row = df.loc[r["cve_id"]]
        vals = {c: float(r[c]) for c in cols if pd.notna(r[c])}
        if vals:
            cache_put(row_key(row["record_id"], row["context"], row["generated_text"], version), vals, where, cache)
            n += 1
    print(f"imported {n} rows x {len(cols)} metrics into {cache.relative_to(ROOT) if cache.is_relative_to(ROOT) else cache}")
    return n


# ---- dry run ----------------------------------------------------------------------------------------------------------
def dry_run(rows: str, out: Path = OUT, cache: Path = CACHE) -> str:
    probs = input_problems(out)
    lines = ["DRY RUN: nothing sent, nothing written."]
    lines.append(f"inputs: {'OK (final list, pending 0)' if not probs else 'NOT READY: ' + '; '.join(probs)}")
    version = sdk_version()
    df = select_rows(build_rows(out), rows)
    keys = keys_for(df, version)
    todo = sum(1 for k in keys for _, _, c in HOSTED if c not in cache_get(k, cache))
    region = os.environ.get("WATSONX_REGION", REGION_DEFAULT)
    name = os.environ.get("WXG_INSTANCE_NAME", INSTANCE_DEFAULT)
    lines += [f"rows: {rows_label(rows, len(df))} ({len(df)} rows; "
              + ", ".join(f"{v} {k}" for k, v in df["source"].value_counts().items()) + ")",
              "metrics (hosted): " + ", ".join(f"{c}" for _, _, c in HOSTED),
              f"target: IBM watsonx.governance {name}, region {region}, {PLAN} plan",
              f"calls: {len(df)} rows x {len(HOSTED)} metrics = {len(df) * len(HOSTED)}; already cached: "
              f"{len(df) * len(HOSTED) - todo}; would call IBM: {todo}",
              f"SDK: ibm-watsonx-gov {version}",
              f"credentials in environment: {'yes' if os.environ.get('WATSONX_APIKEY') else 'no'}",
              f"to run: --run --confirm-spend --rows {rows}"]
    text = "\n".join(lines)
    print(text)
    return text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--check-one", action="store_true")
    ap.add_argument("--confirm-spend", action="store_true")
    ap.add_argument("--rows", choices=["sample100", "all"], default="sample100")
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--import-hosted", type=Path)
    ap.add_argument("--scored-at")
    ap.add_argument("--where", default=None, help="for --import-hosted: the `where` of the earlier run")
    a = ap.parse_args(argv)
    if a.import_hosted:
        if not a.scored_at:
            refuse("--import-hosted needs --scored-at COMMIT")
        if probs := input_problems():
            refuse("; ".join(probs))
        where = a.where or f"IBM watsonx.governance ({INSTANCE_DEFAULT}, {REGION_DEFAULT}, {PLAN} plan) on IBM Cloud"
        import_hosted(a.import_hosted, a.scored_at, where)
        return 0
    if a.local:
        if probs := input_problems():
            refuse("; ".join(probs))
        local()
        return 0
    if not (a.run or a.check_one):
        dry_run(a.rows)
        return 0
    if not a.confirm_spend:
        refuse("a hosted run needs both --run (or --check-one) and --confirm-spend")
    if not os.environ.get("WATSONX_APIKEY"):
        refuse("WATSONX_APIKEY is not set in the environment")
    if probs := input_problems():
        refuse("; ".join(probs))
    r = hosted(a.rows, one=a.check_one)
    if a.check_one:
        print(json.dumps({"check_one": "ok" if not r["stopped"] else "failed", "stopped": r["stopped"],
                          "calls": r["calls"]}, indent=1))
    return 0 if not r["stopped"] else 3


if __name__ == "__main__":
    sys.exit(main())
