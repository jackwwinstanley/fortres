"""Person B: measure the text features on the replica pools and write outputs/b_text_report.md.

Run:  python -m src.b.report --label "year cutoff, stripped text"

Each run scores the current outputs/text_features.parquet against replica_2024 / replica_2025
labels (ROC AUC + hits@k with the shared k rule) and stores the result under --label in
outputs/b_text_metrics.json; the markdown report is rebuilt from every stored label so
before/after runs sit side by side. The text classifier for year Y never sees year-Y labels,
so each replica year is a held-out evaluation.
"""
import argparse
import json

import pandas as pd
from sklearn.metrics import roc_auc_score

from src.common.paths import OUT_DIR
from src.common.scoring import hits_at_k, k_for_pool

METRICS = OUT_DIR / "b_text_metrics.json"
REPORT = OUT_DIR / "b_text_report.md"
SCORES = ("kev_text_score", "nearest_kev_sim")


def measure() -> dict:
    tf = pd.read_parquet(OUT_DIR / "text_features.parquet")
    res = {}
    for y in (2024, 2025):
        r = pd.read_parquet(OUT_DIR / f"replica_{y}.parquet", columns=["cve_id", "label"])
        d = r.merge(tf, on="cve_id", how="left")
        assert d[list(SCORES)].notna().all().all(), f"replica_{y} has CVEs without text features"
        k = k_for_pool(len(d))
        res[str(y)] = {"pool": len(d), "positives": int(d["label"].sum()), "k": k}
        for s in SCORES:
            res[str(y)][s] = {"auc": round(float(roc_auc_score(d["label"], d[s])), 4),
                              "hits": hits_at_k(d, s, k=k)}
    return res


def write_report(all_runs: dict) -> None:
    lines = ["# Person B text features: replica evaluation", "",
             "ROC AUC and hits@k (k = round(500 * pool / 72670)) on each held-out replica year.",
             "Produced by `python -m src.b.report`.", ""]
    for y in ("2024", "2025"):
        first = next(iter(all_runs.values()))[y]
        lines += [f"## Replica {y} (pool {first['pool']:,}, {first['positives']} positives, k = {first['k']})", "",
                  "| run | kev_text_score AUC | kev_text_score hits | nearest_kev_sim AUC | nearest_kev_sim hits |",
                  "|---|---|---|---|---|"]
        for label, run in all_runs.items():
            r = run[y]
            lines.append(f"| {label} | {r['kev_text_score']['auc']:.4f} | {r['kev_text_score']['hits']} "
                         f"| {r['nearest_kev_sim']['auc']:.4f} | {r['nearest_kev_sim']['hits']} |")
        lines.append("")
    REPORT.write_text("\n".join(lines))


def main(label: str) -> dict:
    all_runs = json.loads(METRICS.read_text()) if METRICS.exists() else {}
    all_runs[label] = measure()
    METRICS.write_text(json.dumps(all_runs, indent=1))
    write_report(all_runs)
    print(REPORT.read_text())
    return all_runs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    main(ap.parse_args().label)
