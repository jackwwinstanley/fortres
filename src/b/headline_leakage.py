"""Put the leakage experiment's hit counts into outputs/headline.json, read from the primary model's leakage file
(src/common/primary.py: outputs/v6_leakage_results.csv).

Run:  python -m src.b.headline_leakage

Adds (or replaces) one key, `leakage`, and leaves every other key as it was. Nothing is typed by hand: the counts are the
`hits` column of the `honest` and `leaky` rows of leakage_results.csv (written by `python -m src.b.leakage`), per direction.
Re-run this after re-running the leakage experiment; it is safe to repeat.
"""
import json

import pandas as pd

from src.common import primary
from src.common.paths import OUT_DIR

# headline.json key -> `direction` value in leakage_results.csv (same naming as the other headline.json blocks)
DIRECTIONS = {"forward_train2024_test2025": "train2024_test2025", "stability_train2025_test2024": "train2025_test2024"}
ARMS = ("honest", "leaky")


def leakage_summary(csv_path=None) -> dict:
    """Pooled hits plus the forward / stability split for the honest and the leaky model."""
    csv_path = primary.file("leakage") if csv_path is None else csv_path
    df = pd.read_csv(csv_path)
    out = {"source": f"outputs/{csv_path.name}"}
    for arm in ARMS:
        per_dir = {}
        for key, direction in DIRECTIONS.items():
            rows = df[(df["model"] == arm) & (df["direction"] == direction)]
            if len(rows) != 1:
                raise ValueError(f"{csv_path}: expected exactly one row for model={arm!r}, direction={direction!r}, got {len(rows)}")
            per_dir[key] = int(rows["hits"].iloc[0])
        out[arm] = {"pooled_hits": sum(per_dir.values()), **per_dir}
    return out


def update_headline(out_dir=OUT_DIR) -> dict:
    """Write the `leakage` key into out_dir/headline.json (placed before the closing `note`) and return it."""
    path = out_dir / "headline.json"
    head = json.loads(path.read_text())
    note = head.pop("note", None)
    head.pop("leakage", None)
    head["leakage"] = leakage_summary(primary.file("leakage", out_dir=out_dir))
    if note is not None:
        head["note"] = note
    path.write_text(json.dumps(head, indent=1))  # same format train_v5.py writes
    return head["leakage"]


if __name__ == "__main__":
    print(json.dumps(update_headline(), indent=1))
