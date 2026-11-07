"""Validate every contract file present in outputs/.  Exit 1 on any FAIL."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import pyarrow as pa  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

from scripts.check_top500 import check as check_top500  # noqa: E402
from src.common import schema as S  # noqa: E402
from src.common.paths import OUT_DIR  # noqa: E402


def _type_ok(t: pa.DataType, code: str) -> bool:
    return {
        "str": pa.types.is_string(t) or pa.types.is_large_string(t),
        "date": pa.types.is_date(t) or pa.types.is_timestamp(t),
        "float": pa.types.is_floating(t),
        "int8": pa.types.is_int8(t),
    }[code]


def check_parquet(path: Path, spec: dict) -> list[str]:
    probs = []
    table = pq.read_table(path)
    names = set(table.column_names)
    for col, code in spec["cols"].items():
        if col not in names:
            probs.append(f"missing column {col}")
        elif not _type_ok(table.schema.field(col).type, code):
            probs.append(f"{col}: dtype {table.schema.field(col).type}, expected {code}")
    prefix = spec.get("prefix_int8")
    if prefix:
        flags = [c for c in names if c.startswith(prefix)]
        if not flags:
            probs.append(f"no int8 flag columns prefixed '{prefix}'")
        for c in flags:
            if not pa.types.is_int8(table.schema.field(c).type):
                probs.append(f"{c}: flag columns must be int8")
    if probs:
        return probs
    df = table.to_pandas()
    for col in spec["cols"]:
        if col not in spec["nullable"] and df[col].isna().any():
            probs.append(f"{col}: {int(df[col].isna().sum())} nulls not allowed")
    for col in spec.get("binary", []):
        if col in df and not df[col].dropna().isin([0, 1]).all():
            probs.append(f"{col}: values must be 0/1")
    if spec.get("unique_cve") and df["cve_id"].duplicated().any():
        probs.append("cve_id not unique")
    if "n_rows" in spec and len(df) != spec["n_rows"]:
        probs.append(f"expected {spec['n_rows']} rows, got {len(df)}")
    return probs


def check_csv(path: Path, spec: dict) -> list[str]:
    df = pd.read_csv(path, dtype=str)
    probs = []
    if list(df.columns) != spec["cols"]:
        probs.append(f"columns {list(df.columns)}, expected {spec['cols']}")
    elif spec["unique_cve"] and df["cve_id"].duplicated().any():
        probs.append("cve_id not unique")
    return probs


def check_embeddings(out: Path) -> list[str]:
    arr = np.load(out / S.EMB_NPY, mmap_mode="r")
    ids = pd.read_csv(out / S.EMB_IDS, dtype=str)
    probs = []
    if arr.dtype != np.float32:
        probs.append(f"dtype {arr.dtype}, expected float32")
    if arr.ndim != 2 or arr.shape[0] != len(ids):
        probs.append(f"rows: npy {arr.shape} vs emb_ids.csv {len(ids)}")
    return probs


def main(out: Path = OUT_DIR) -> int:
    results = []  # (name, problems | None)
    for name, spec in S.SCHEMAS.items():
        p = out / name
        results.append((name, check_parquet(p, spec) if p.exists() else None))
    for name, spec in S.CSV_SCHEMAS.items():
        p = out / name
        results.append((name, check_csv(p, spec) if p.exists() else None))
    npy = out / S.EMB_NPY
    if npy.exists() and (out / S.EMB_IDS).exists():
        results.append((S.EMB_NPY, check_embeddings(out)))
    elif npy.exists():
        results.append((S.EMB_NPY, [f"{S.EMB_IDS} missing"]))
    else:
        results.append((S.EMB_NPY, None))
    tops = sorted(out.glob(S.TOP500_PATTERN))
    if tops:
        results += [(t.name, check_top500(t)) for t in tops]
    else:
        results.append(("top500_vN.csv", None))

    failed = 0
    for name, probs in results:
        if probs is None:
            print(f"SKIP {name}: not yet produced")
        elif probs:
            failed += 1
            print(f"FAIL {name}")
            for p in probs:
                print("  -", p)
        else:
            print(f"PASS {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
