"""Person B: regenerate every Person B output from Person A's final files, in the right order.

Run:  python -m src.b.refresh_all                  # fast path (~1.5 min): drift, leakage + blind spots, charts, story data, checks, number sweep
      python -m src.b.refresh_all --text           # also rebuild descriptions, Granite embeddings and text_features first
      python -m src.b.refresh_all --priors         # also rebuild the #12 track-record priors and their v5 evaluation
      python -m src.b.refresh_all --explanations   # also regenerate the Granite reasons with Person A's explain.py
                                                   # (Guardian gate; needs Ollama running); run AFTER the final top500 exists
      python -m src.b.refresh_all --all            # everything above

Stops at the first failing step and says which one. See docs/person_b_runbook.md.
"""
import argparse
import subprocess
import sys
import time

from src.common import primary
from src.common.paths import OUT_DIR, REPO_ROOT

PY = sys.executable


def step(name: str, args: list[str]) -> None:
    t0 = time.time()
    print(f"\n=== {name}: {' '.join(args)}", flush=True)
    r = subprocess.run([PY, *args], cwd=REPO_ROOT)
    if r.returncode != 0:
        sys.exit(f"FAILED at step '{name}' (exit {r.returncode}). Fix it and re-run; finished steps are safe to repeat.")
    print(f"--- {name} done in {time.time() - t0:,.0f}s", flush=True)


def main(text=False, priors=False, explanations=False):
    if text:
        step("descriptions", ["-m", "src.b.texts"])
        for p in OUT_DIR.glob("emb_small_part*.npy"):   # embed.py resumes from chunks; new texts need fresh chunks
            p.unlink()
        step("Granite embeddings", ["-m", "src.b.embed"])
        step("text features", ["-m", "src.b.text_features"])
    step("drift check", ["-m", "src.b.drift"])
    step(f"leakage + {primary.PRIMARY} blind spots", ["-m", "src.b.leakage"])
    step("leakage numbers into headline.json", ["-m", "src.b.headline_leakage"])   # train_v5 rewrites headline.json without this key
    if priors:
        step("track-record priors", ["-m", "src.b.priors"])
        step("priors evaluation on v5", ["-m", "src.b.eval_priors"])
    step("error analysis", ["-m", "src.b.error_analysis"])
    if explanations:
        step("Granite reasons (Person A's explain.py, Guardian gate)", ["-m", "src.b.explain", "--granite"])
    step("charts", ["-m", "src.b.charts"])
    step("story / dashboard data", ["-m", "src.b.export_story"])
    step("tests", ["-m", "pytest", "-q"])
    step("contract check", ["scripts/check_contract.py"])
    step("number sweep (docs vs outputs)", ["scripts/number_sweep.py"])
    print("\nAll Person B outputs refreshed. Review `git status`, then commit the tracked files listed in docs/person_b_runbook.md.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--priors", action="store_true")
    ap.add_argument("--explanations", action="store_true")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    main(a.text or a.all, a.priors or a.all, a.explanations or a.all)
