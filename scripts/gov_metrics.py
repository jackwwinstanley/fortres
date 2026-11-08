"""Score our explanation sentences with the IBM watsonx.governance Python SDK (ibm-watsonx-gov), run locally.

Run (needs the separate Python 3.11 env, because ibm-watsonx-gov requires Python >=3.11,<3.14 and the repo runs on 3.14):
    uv venv --python 3.11 .venv-gov
    uv pip install --python .venv-gov/bin/python "ibm-watsonx-gov[metrics]" sentence-transformers bert-score
    .venv-gov/bin/python -m scripts.gov_metrics

What it does
1. Inventory: tries every SDK metric/method that applies to a single (input, context, output) sentence on 3 rows, with ALL
   watsonx credentials removed from the environment, and records whether it ran or the exact error.
2. Local run: sets WATSONX_SERVER=WXGOV (an environment switch the SDK itself reads; with it the SDK skips its
   `api_client.credentials` lookup for the token/embedding methods) and computes every method that needs no IBM service on
   all rows of outputs/explanations.csv. No API key is set, so nothing can be sent to IBM. The embedding methods load public
   Hugging Face models (MiniLM, BGE, BERTScore's model) to run on this machine; only the model names leave it.

Inputs, per CVE (the SAME facts src/b/explain.py builds, imported from it, never edited):
    context        = explain.facts_prose(row)  - the facts as plain sentences (what Granite Guardian checks against in explain.py)
    generated_text = outputs/explanations.csv `explanation`
    ground_truth   = explain.template(row)     - the fixed-form sentence built from the same facts (reference for answer similarity)
    input_text     = "Why is <CVE> prioritised?" - a fixed question we wrote (the SDK requires an input field)
Nothing under data/ is read. Outputs: outputs/gov_metrics.csv (per row), outputs/gov_metrics_summary.json (aggregates).
"""
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

for k in list(os.environ):  # never use anyone's credentials, even if set
    if k.startswith(("WATSONX", "WXG", "WML", "IBM_CLOUD", "IBMCLOUD")):
        os.environ.pop(k)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from src.b import explain as E  # noqa: E402
from ibm_watsonx_gov.config import GenAIConfiguration  # noqa: E402
import ibm_watsonx_gov.metrics as M  # noqa: E402

OUT = ROOT / "outputs"
CFG = GenAIConfiguration(input_fields=["input_text"], context_fields=["context"], output_fields=["generated_text"],
                         reference_fields=["ground_truth"], record_id_field="record_id")

# (class, method, what it compares, note)
LOCAL = [
    ("FaithfulnessMetric", "token_k_precision", "output vs facts", "share of the sentence's tokens found in the facts"),
    ("FaithfulnessMetric", "sentence_bert_mini_lm", "output vs facts", "MiniLM embedding similarity, sentence vs facts"),
    ("AnswerSimilarityMetric", "token_recall", "output vs template", "share of the template sentence's tokens in our sentence"),
    ("AnswerSimilarityMetric", "bert_score_recall", "output vs template", "BERTScore recall vs the template sentence"),
    ("AnswerSimilarityMetric", "sentence_bert_mini_lm", "output vs template", "MiniLM embedding similarity vs template"),
    ("AnswerRelevanceMetric", "token_recall", "output vs fixed question", "question is one we wrote; low information"),
    ("TextGradeLevelMetric", "flesch_kincaid_grade", "output only", "readability (textstat)"),
    ("TextReadingEaseMetric", "flesch_reading_ease", "output only", "readability (textstat)"),
    # Not scored per row (still in the inventory): ContextRelevance compares only our fixed question with the facts, never the
    # sentence, and returned 1 value for 500 rows; OutputTokenCount returned 0 for every row (needs token-usage fields).
]
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


def redact(s: str) -> str:
    return re.sub(r"[A-Za-z0-9_-]{32,}", "<redacted>", re.sub(r"\x1b\[[0-9;]*m", "", s))


def build_rows() -> pd.DataFrame:
    ex = pd.read_csv(OUT / "explanations.csv")
    f = E.facts_for(ex[["cve_id"]]).set_index("cve_id", drop=False)
    return pd.DataFrame({"record_id": ex["cve_id"], "source": ex["source"], "input_text": "Why is " + ex["cve_id"] + " prioritised?",
                         "context": [E.facts_prose(f.loc[c]) for c in ex["cve_id"]], "generated_text": ex["explanation"],
                         "ground_truth": [E.template(f.loc[c]) for c in ex["cve_id"]]})


def run(cls, method, df):
    kw = dict(EXTRA_KW.get(cls, {}))
    if method:
        kw["method"] = method
    metric = getattr(M, cls)(**kw)
    r = metric.evaluate(data=df[["record_id", "input_text", "context", "generated_text", "ground_truth"]], configuration=CFG)
    if r is None:
        raise RuntimeError("SDK returned no result")
    return metric, {x.record_id: x.value for x in r.record_level_metrics}


def colname(cls, method):
    base = re.sub(r"(?<!^)(?=[A-Z])", "_", cls.removesuffix("Metric")).lower()
    return f"{base}__{method}" if method else base


def main():
    t0 = time.time()
    df = build_rows()
    probe = df.head(3)

    inventory = []
    for server in (None, "WXGOV"):  # first exactly as installed, then with the SDK's own WATSONX_SERVER switch
        os.environ.pop("WATSONX_SERVER", None)
        if server:
            os.environ["WATSONX_SERVER"] = server
        for cls, methods in INVENTORY:
            for m in methods:
                try:
                    metric, _ = run(cls, m, probe)
                    status, err = "ran", None
                except Exception as e:  # noqa: BLE001
                    status, err = "error", redact(f"{type(e).__name__}: {e}")
                    err = err.split("Reason:")[0] + ("Reason: " + err.split("Missing package")[-1][:200] if "Missing package" in err else "")
                inventory.append(dict(metric=cls, method=m, watsonx_server_env=server, no_credentials_result=status,
                                      error=(err or "")[:500]))
                print(f"[inventory server={server}] {cls}/{m}: {status}", flush=True)

    os.environ["WATSONX_SERVER"] = "WXGOV"
    t1 = time.time()
    out = df[["record_id", "source"]].rename(columns={"record_id": "cve_id"}).copy()
    summary_metrics = []
    for cls, m, compares, note in LOCAL:
        ts = time.time()
        try:
            metric, vals = run(cls, m, df)
            col = colname(cls, m or getattr(metric, "method", None))
            out[col] = out["cve_id"].map(vals)
            s = out[col].astype(float)
            summary_metrics.append(dict(column=col, metric=cls, method=m or getattr(metric, "method", None), compares=compares, note=note,
                                        where="local (this machine; IBM watsonx.governance SDK, no IBM service called)",
                                        n=int(s.notna().sum()), mean=round(s.mean(), 4), median=round(s.median(), 4),
                                        min=round(s.min(), 4), max=round(s.max(), 4),
                                        mean_by_source={k: round(v, 4) for k, v in s.groupby(out["source"]).mean().items()},
                                        secs=round(time.time() - ts, 1)))
        except Exception as e:  # noqa: BLE001
            summary_metrics.append(dict(metric=cls, method=m, where="local", error=redact(f"{type(e).__name__}: {e}")[:500]))
        print(f"[local] {cls}/{m}: done in {time.time() - ts:.1f}s", flush=True)
    t2 = time.time()

    out.to_csv(OUT / "gov_metrics.csv", index=False)
    freeze = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True).stdout.split()
    if not freeze:
        freeze = sorted(f"{d.metadata['Name']}=={d.version}" for d in md.distributions())
    summary = dict(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sdk="ibm-watsonx-gov", sdk_version=md.version("ibm-watsonx-gov"), sdk_requires_python=md.metadata("ibm-watsonx-gov")["Requires-Python"],
        python=platform.python_version(), env=".venv-gov (separate from the project venv)",
        claim="Computed with the IBM watsonx.governance SDK, run locally. No IBM service was called: no credentials were set.",
        credentials_used=False, credentialed_route="skipped: WATSONX_APIKEY was not set in the environment",
        how_local_methods_were_enabled=("As installed, every token/embedding method of Faithfulness, AnswerRelevance, ContextRelevance "
                                        "and AnswerSimilarity fails with no client ('NoneType' object has no attribute 'credentials' / "
                                        "'watsonx.governance context is missing'). With the SDK's own WATSONX_SERVER=WXGOV environment "
                                        "switch they compute locally via unitxt. Readability ran without it."),
        rows=dict(file="outputs/explanations.csv", n=len(df), which="all rows", by_source=df["source"].value_counts().to_dict()),
        inputs=dict(context="src.b.explain.facts_prose (same facts as the Granite prompt)", generated_text="explanations.csv explanation",
                    ground_truth="src.b.explain.template (fixed-form sentence from the same facts)",
                    input_text="'Why is <CVE> prioritised?' (fixed question we wrote)"),
        metrics=summary_metrics,
        inventory=inventory,
        runtime_secs=dict(total=round(time.time() - t0, 1), inventory=round(t1 - t0, 1), local_scoring_all_rows=round(t2 - t1, 1)),
        pip_freeze=freeze,
    )
    (OUT / "gov_metrics_summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n")
    print(json.dumps({k: summary[k] for k in ("sdk_version", "runtime_secs")}), flush=True)


if __name__ == "__main__":
    main()
