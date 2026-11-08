"""Train v6 exactly as src/models/train_v6.py does for the 2026 list and save the 20 boosters.  Run:  python scripts/save_v6_models.py

Same data (the 2024 and 2025 replicas), same settings (outputs/headline.json `final_params`, chosen by train_v6), same seeds (0-19), same model
factory (src/common/primary.py). Writes models/v6/seed_NN.txt (LightGBM text format) and models/v6/manifest.json. Needs data/.
tests/test_app_score.py checks that the saved models reproduce outputs/top500_v6.csv byte for byte.
"""
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.b import rank as R  # noqa: E402
from src.common import primary  # noqa: E402
from src.common.paths import OUT_DIR  # noqa: E402
from src.models import train_v1 as v1  # noqa: E402
from src.models.train_v5 import FEATURES_V5  # noqa: E402

MODELS = ROOT / "models" / "v6"
SEEDS = list(range(20))


def main() -> int:
    F5 = list(FEATURES_V5)
    data, _ = R.load()
    X_all = pd.concat([data[2024]["X5"], data[2025]["X5"]], ignore_index=True)
    y_all = np.concatenate([data[2024]["y"], data[2025]["y"]])
    params = json.loads((OUT_DIR / "headline.json").read_text())["final_params"]
    MODELS.mkdir(parents=True, exist_ok=True)
    for s in SEEDS:
        primary.lgbm(params, F5, s).fit(X_all[F5], y_all).booster_.save_model(str(MODELS / f"seed_{s:02d}.txt"))
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (MODELS / "manifest.json").write_text(json.dumps({
        "model": primary.PRIMARY, "commit": commit, "seeds": SEEDS, "params": params, "fixed": {k: v for k, v in v1.FIXED.items()},
        "features": F5, "train_rows": int(len(X_all)), "train_positives": int(y_all.sum())}, indent=1) + "\n")
    size = sum(p.stat().st_size for p in MODELS.iterdir())
    print(f"saved {len(SEEDS)} boosters + manifest to models/v6: {size / 1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
