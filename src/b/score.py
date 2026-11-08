"""Score CVEs with the saved v6 models (models/v6, written by scripts/save_v6_models.py). Used by the "Rank a dataset" page.

Scores are always computed against the whole 2026 scoreboard: each of the 20 models' outputs is turned into a percentile rank within the 72,670
scoreboard CVEs and averaged, exactly as the v6 bag is built, so a slice ranks as it does in the full list. A CVE in the scoreboard uses the
cached features (outputs/features_scoreboard.parquet, outputs/text_features.parquet). For a row outside the scoreboard only what its columns
give is computed (EPSS percentile against that month of the 2026 pool, exploit flags, timing); the rest, including the Granite text
scores, is left missing, and LightGBM's missing-value handling applies. No Granite model runs here. No banned column is read.
"""
import io
import json
import re
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR, REPO_ROOT
from src.common.schema import SHARE_FEATURES, TEXT_FEATURES
from src.features import drift_fix as dfx
from src.models.train_v1 import FEATURES as V1_FEATURES

MODELS = REPO_ROOT / "models" / "v6"
MAX_ROWS = 100_000
FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
NEEDED_OUTSIDE = ["published", "snapshot_month", "epss", *FLAGS]
PLAIN = {"published": "publication date (published)", "snapshot_month": "snapshot month (snapshot_month, YYYY-MM)", "epss": "EPSS score (epss)",
         "exploitdb": "Exploit-DB flag (exploitdb)", "metasploit": "Metasploit flag (metasploit)", "nuclei": "Nuclei flag (nuclei)", "poc_github": "GitHub proof-of-concept flag (poc_github)"}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
CUTOFF = pd.Timestamp("2026-11-04")


class UploadError(ValueError):
    """A problem with an uploaded file, with a message meant for the person who uploaded it."""


def load_models(path: Path = MODELS) -> tuple[list, list]:
    """(boosters, feature names) from models/v6."""
    m = json.loads((path / "manifest.json").read_text())
    return [lgb.Booster(model_file=str(path / f"seed_{s:02d}.txt")) for s in m["seeds"]], m["features"]


def predict_each(boosters: list, X: pd.DataFrame, features: list) -> np.ndarray:
    return np.column_stack([b.predict(X[features]) for b in boosters])


def bag_against(pred: np.ndarray, ref_sorted: np.ndarray) -> np.ndarray:
    """Average over the models of each row's percentile rank among the reference predictions (average rank for ties)."""
    n = ref_sorted.shape[0]
    per_seed = []
    for j in range(pred.shape[1]):
        left = np.searchsorted(ref_sorted[:, j], pred[:, j], side="left")
        right = np.searchsorted(ref_sorted[:, j], pred[:, j], side="right")
        per_seed.append(((left + 1 + right) / 2) / n)
    return np.mean(per_seed, axis=0)      # the same averaging as train_v4.bag, so ties break the same way


class Scorer:
    """The saved models plus the whole 2026 scoreboard as the reference."""

    def __init__(self, out_dir: Path = OUT_DIR, models: Path = MODELS):
        self.boosters, self.features = load_models(models)
        sb = pd.read_parquet(out_dir / "features_scoreboard.parquet").reset_index(drop=True)
        text = pd.read_parquet(out_dir / "text_features.parquet").set_index("cve_id").reindex(sb["cve_id"]).reset_index(drop=True)
        x2 = pd.concat([sb[V1_FEATURES], text[TEXT_FEATURES]], axis=1)
        self.X = dfx.to_v5(pd.concat([x2, sb[SHARE_FEATURES]], axis=1))[self.features].reset_index(drop=True)
        self.sb, self.text = sb, text
        pred = predict_each(self.boosters, self.X, self.features)
        self.ref_sorted = np.sort(pred, axis=0)
        self.scores = bag_against(pred, self.ref_sorted)
        self.ids = sb["cve_id"].to_numpy()
        self.index = pd.Series(np.arange(len(sb)), index=self.ids)
        self.rank_col = sb["epss_rank_in_month"].to_numpy()
        order = np.lexsort((self.ids.astype(str), -self.rank_col, -self.scores))     # score, then EPSS rank, then cve_id (as train_v6)
        self.order = order
        self.all_rank = np.empty(len(sb), dtype=int)
        self.all_rank[order] = np.arange(1, len(sb) + 1)
        self.epss_by_month = {m: np.sort(g.dropna().to_numpy()) for m, g in sb.groupby("snapshot_month")["epss"]}
        self.epss_all = np.sort(sb["epss"].dropna().to_numpy())
        self._score_sorted = np.sort(self.scores)

    def top_ids(self, n: int = 500) -> list:
        return self.ids[self.order[:n]].tolist()

    def epss_rank(self, month: str, epss: float) -> float:
        """Percentile of an EPSS score within that month of the 2026 pool (missing EPSS -> 0, as in training)."""
        if pd.isna(epss):
            return 0.0
        ref = self.epss_by_month.get(month, self.epss_all)
        return float((np.searchsorted(ref, epss, "left") + 1 + np.searchsorted(ref, epss, "right")) / 2 / max(len(ref), 1))

    def outside_row(self, r: pd.Series) -> dict:
        x = {f: np.nan for f in self.features}
        month = str(r["snapshot_month"])
        eom = pd.Timestamp(month + "-01") + pd.offsets.MonthEnd(0)
        pub = pd.to_datetime(r["published"], errors="coerce")
        epss = pd.to_numeric(r["epss"], errors="coerce")
        flags = [int(pd.to_numeric(r[f], errors="coerce") or 0) for f in FLAGS]
        x.update(epss_missing=int(pd.isna(epss)), epss_rank_in_month=self.epss_rank(month, epss), n_flags=sum(flags), any_exploit=max(flags),
                 days_to_snapshot=(eom - pub).days if pd.notna(pub) else np.nan, days_to_cutoff=(CUTOFF - eom).days)
        x.update(dict(zip(FLAGS, flags)))
        return x

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """df: at least cve_id (validated by read_upload). Returns one row per input CVE with score, ranks and in_scoreboard."""
        known = df["cve_id"].isin(self.index.index).to_numpy()
        n = len(df)
        s = np.empty(n)
        all_rank = np.empty(n, dtype=int)
        epss_rank = np.empty(n)
        if known.any():
            i = self.index.loc[df.loc[known, "cve_id"]].to_numpy()
            s[known] = bag_against(predict_each(self.boosters, self.X.iloc[i], self.features), self.ref_sorted)   # really runs the 20 models
            all_rank[known], epss_rank[known] = self.all_rank[i], self.rank_col[i]
        if (~known).any():
            rows = pd.DataFrame([self.outside_row(r) for _, r in df[~known].iterrows()])[self.features]
            out = bag_against(predict_each(self.boosters, rows, self.features), self.ref_sorted)
            s[~known] = out
            epss_rank[~known] = rows["epss_rank_in_month"].to_numpy()
            all_rank[~known] = len(self.scores) - np.searchsorted(self._score_sorted, out, "left") + 1
        res = pd.DataFrame({"cve_id": df["cve_id"].to_numpy(), "score": s, "rank_all_2026": all_rank, "epss_rank": epss_rank, "in_scoreboard": known})
        res = res.sort_values(["score", "epss_rank", "cve_id"], ascending=[False, False, True], kind="mergesort").reset_index(drop=True)
        res.insert(0, "rank_in_upload", np.arange(1, n + 1))
        return res


def read_upload(file, known_ids: set | None = None) -> pd.DataFrame:
    """Read and validate an uploaded CSV. Raises UploadError with a plain message; never lets a parsing traceback through."""
    try:
        raw = file.read() if hasattr(file, "read") else Path(file).read_bytes()
        if isinstance(raw, bytes) and b"\x00" in raw:
            raise ValueError("binary content")
        df = pd.read_csv(io.BytesIO(raw) if isinstance(raw, bytes) else io.StringIO(raw), dtype=str)
    except Exception as e:
        raise UploadError(f"This file could not be read as a CSV ({type(e).__name__}). Please upload a comma-separated file with a header row.") from None
    df.columns = [str(c).strip().lower() for c in df.columns]
    if "cve_id" not in df.columns:
        raise UploadError("This file has no cve_id column. Please upload a CSV with the scoreboard's columns: at least cve_id.")
    if len(df) == 0:
        raise UploadError("This file has no rows.")
    if len(df) > MAX_ROWS:
        raise UploadError(f"This file has {len(df):,} rows. The limit is {MAX_ROWS:,}.")
    df["cve_id"] = df["cve_id"].astype(str).str.strip().str.upper()
    bad = ~df["cve_id"].map(lambda c: bool(CVE.match(c)))
    if bad.all():
        raise UploadError("None of the values in the cve_id column look like a CVE id (for example CVE-2026-1234).")
    if bad.any():
        df = df[~bad]
    df = df.drop_duplicates("cve_id").reset_index(drop=True)
    if known_ids is not None:
        outside = ~df["cve_id"].isin(known_ids)
        if outside.any():
            if "snapshot_month" not in df.columns and "published" in df.columns:
                df["snapshot_month"] = pd.to_datetime(df["published"], errors="coerce").dt.strftime("%Y-%m")
            missing = [PLAIN[c] for c in NEEDED_OUTSIDE if c not in df.columns]
            if missing:
                raise UploadError(f"{int(outside.sum()):,} rows are not in the 2026 scoreboard, so they need these columns too: " + "; ".join(missing) + ".")
            nmonth = df.loc[outside, "snapshot_month"].astype(str).str.fullmatch(r"\d{4}-\d{2}").fillna(False)
            if not nmonth.all():
                raise UploadError(f"{int((~nmonth).sum()):,} rows outside the scoreboard have no valid snapshot month (use YYYY-MM).")
    df.attrs["dropped_bad_ids"] = int(bad.sum())
    return df


def vendors(ids) -> pd.Series:
    """Reporting organisation of each CVE, from the assigner in data/vulnerabilities.csv ('' if data/ is not present). Display only."""
    from src.b.explain import cna_name
    p = DATA_DIR / "vulnerabilities.csv"
    if not p.exists():
        return pd.Series("", index=pd.Index(ids))
    a = pd.read_csv(p, usecols=["cve_id", "assigner"]).drop_duplicates("cve_id").set_index("cve_id")["assigner"]
    return a.reindex(ids).map(cna_name).fillna("")
