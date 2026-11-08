"""New data source experiment: Nuclei templates (github.com/projectdiscovery/nuclei-templates, MIT).  Run:  python -m src.b.new_data [step]

Steps: provenance | join | eval | all.  The clone (full, not shallow) lives outside the repository: NUCLEI_REPO (default
data/outside/nuclei-templates, gitignored) and is never committed. Writes outputs/newdata_provenance.md, outputs/newdata_eval.csv,
outputs/newdata_report.md and outputs/newdata_nuclei_first_added.csv (derived: cve_id, first_added_date; MIT, see the report).

Rules fixed before any result:
- Date = the AUTHOR date of the commit that first added the template file, from one pass of
  `git log --reverse -M --name-status --format=...` with renames followed (a renamed or moved file keeps its first date). Dates
  written inside the files are never used.
- Invalid dates: an author date before the repository's first commit (root commit's committer date) or more than one day after
  its own commit's committer date is not a real first-seen date (e.g. 1970-01-01); it is MISSING (added after the first run
  showed 40 such files, before any evaluation).
- Bulk commits: a commit that adds or renames-in at least BULK_MIN (100) CVE templates is a bulk import or a restructure; dates
  coming only from such commits are MISSING (the template counts as absent), never early.
- Mapping: a template belongs to a CVE through its file name (CVE-YYYY-N) or the `cve-id:` field at HEAD; CVEs with several
  templates use the earliest date.
- Features (only these): nuclei_has_template_by_snapshot (0/1), nuclei_days_published_to_first_template (-1 if no template dated
  by the snapshot end; v5/v6 features have no blank cells, so a sentinel is used), nuclei_n_templates_by_snapshot.
  Anything dated after the end of the CVE's snapshot month is absent.
- Evaluation: v6's settings (src/common/primary.py), 20-seed rank-averaged bags, forward (train 2024 -> test 2025) first, then
  stability, then pooled; paired and event-clustered bootstrap vs v6; variants: (A) v6 + new features, (B) new features alone.
  Adoption: forward >= 18, stability >= 9, pooled gain >= 2 and >= 4 over v6's 27; ties go to v6.
"""
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from src.common.paths import DATA_DIR, OUT_DIR

NUCLEI_REPO = Path(os.environ.get("NUCLEI_REPO", DATA_DIR / "outside" / "nuclei-templates"))
MSF_REPO = Path(os.environ.get("MSF_REPO", Path.home() / "ibm" / "ext" / "metasploit-framework"))
# Secondary source (same rules): Metasploit modules (github.com/rapid7/metasploit-framework, BSD-3-Clause). A module is a
# modules/**/*.rb file; it maps to CVEs only through its References field (['CVE', 'YYYY-N']) at HEAD (Metasploit file
# names carry no CVE id). Bulk = a commit adding or renaming in >= BULK_MIN module files.
SOURCES = {"nuclei": dict(ext=".yaml", top=None, prefix="nuclei"), "metasploit": dict(ext=".rb", top="modules/", prefix="msf")}
MSF_CVE_RE = re.compile(r"""\[\s*['"]CVE['"]\s*,\s*['"](\d{4}-\d{4,7})['"]\s*\]""", re.I)
POOLS = {2024: "replica_2024.parquet", 2025: "replica_2025.parquet", 2026: "scoreboard_features.parquet"}
BULK_MIN = 100
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
NEW = ["nuclei_has_template_by_snapshot", "nuclei_days_published_to_first_template", "nuclei_n_templates_by_snapshot"]
SEEDS = list(range(20))
NOISE_FLOOR = 4


# ---------------------------------------------------------------------------------------------------- provenance (git history)
def _kept(p: str, src: str) -> bool:
    cfg = SOURCES[src]
    return p.endswith(cfg["ext"]) and (cfg["top"] is None or p.startswith(cfg["top"]))


def _counts_for_bulk(p: str, src: str) -> bool:
    return _kept(p, src) and (src != "nuclei" or bool(CVE_RE.search(Path(p).name)))


def first_added(repo: Path, src: str = "nuclei") -> pd.DataFrame:
    """One pass over the full history, oldest first. Returns one row per path ever added: path at HEAD (after renames),
    first author date, the commit that added it, and how many CVE templates that commit added or renamed in."""
    fmt = "__C__%H|%aI|%cI"
    out = subprocess.run(["git", "-C", str(repo), "log", "--reverse", "-M", "--name-status", f"--format={fmt}", "--no-color"],
                         capture_output=True, text=True, check=True).stdout
    first = {}          # current path -> (date, commit)
    commit_adds = defaultdict(int)
    cdates = {}
    commit, date = None, None
    for line in out.splitlines():
        if line.startswith("__C__"):
            commit, date, cdate = line[5:].split("|", 2)
            cdates[commit] = cdate
            continue
        if not line.strip():
            continue
        parts = line.split("\t")
        st = parts[0]
        if st.startswith("A") and len(parts) >= 2:
            p = parts[1]
            if _counts_for_bulk(p, src):
                commit_adds[commit] += 1
            prev = first.get(p)          # added again (another branch, or after a deletion): keep the EARLIEST author date
            if prev is None or datetime.fromisoformat(date) < datetime.fromisoformat(prev[0]):
                first[p] = (date, commit)
        elif st.startswith("R") and len(parts) >= 3:
            old, new = parts[1], parts[2]
            if _counts_for_bulk(new, src):
                commit_adds[commit] += 1
            cand = first.pop(old, (date, commit))
            prev = first.get(new)
            first[new] = cand if prev is None or datetime.fromisoformat(cand[0]) < datetime.fromisoformat(prev[0]) else prev
        elif st.startswith("D") and len(parts) >= 2:
            pass   # a deleted template keeps its first date: it existed from that date on
    rows = [{"path": p, "first_date": d, "commit": c} for p, (d, c) in first.items() if _kept(p, src)]
    df = pd.DataFrame(rows)
    df["commit_cve_adds"] = df["commit"].map(commit_adds).fillna(0).astype(int)
    df["first_date"] = pd.to_datetime(df["first_date"], utc=True)
    df["commit_date"] = pd.to_datetime(df["commit"].map(cdates), utc=True)
    root = subprocess.run(["git", "-C", str(repo), "log", "--max-parents=0", "--format=%cI"], capture_output=True, text=True, check=True).stdout.split()
    start = min(pd.to_datetime(root, utc=True))
    df["date_invalid"] = (df["first_date"] < start) | (df["first_date"] > df["commit_date"] + pd.Timedelta(days=1))
    return df


def cve_ids_for(repo: Path, paths: pd.Series) -> pd.Series:
    """CVE id from the file name, else from a `cve-id:` field in the file at HEAD (only if it still exists)."""
    out = []
    for p in paths:
        m = CVE_RE.search(Path(p).name)
        if m:
            out.append(m.group(0).upper())
            continue
        f = repo / p
        cid = None
        if f.exists():
            m2 = re.search(r"cve-id:\s*['\"]?(CVE-\d{4}-\d{4,7})", f.read_text(errors="ignore"), re.I)
            cid = m2.group(1).upper() if m2 else None
        out.append(cid)
    return pd.Series(out, index=paths.index)


def msf_cve_ids(repo: Path, paths: pd.Series) -> pd.Series:
    """All CVE ids in a module's References at HEAD (a deleted module cannot be mapped: None)."""
    out = []
    for p in paths:
        f = repo / p
        ids = sorted({f"CVE-{m}".upper() for m in MSF_CVE_RE.findall(f.read_text(errors="ignore"))}) if f.exists() else []
        out.append(ids or None)
    return pd.Series(out, index=paths.index)


def reference_added(repo: Path, pairs: pd.DataFrame) -> pd.Series:
    """Metasploit: the author date of the earliest commit whose diff adds the CVE's number to that module (git pickaxe
    `log -S`, renames followed). A module written before a CVE number existed only gets the CVE when the reference is added,
    so the module's own first-added date would be hindsight for that CVE."""
    from joblib import Parallel, delayed

    def one(cve, path):
        num = cve.split("-", 1)[1]
        r = subprocess.run(["git", "-C", str(repo), "log", "--follow", "--format=%aI|%cI", "-S", num, "--", path],
                           capture_output=True, text=True)
        lines = [ln for ln in r.stdout.split("\n") if ln]
        return lines[-1] if lines else None
    res = Parallel(n_jobs=8, prefer="threads")(delayed(one)(c, p) for c, p in zip(pairs["cve_id"], pairs["path"]))
    return pd.Series(res, index=pairs.index)


def templates(repo: Path = NUCLEI_REPO, src: str = "nuclei") -> pd.DataFrame:
    df = first_added(repo, src)
    if src == "metasploit":
        df["cve_id"] = msf_cve_ids(repo, df["path"])
        df["n_cves_in_file"] = df["cve_id"].map(lambda v: len(v) if v else 0)
        df = df.explode("cve_id").reset_index(drop=True)
    else:
        df["cve_id"] = cve_ids_for(repo, df["path"])
    df["bulk"] = df["commit_cve_adds"] >= BULK_MIN
    df["at_head"] = [(repo / p).exists() for p in df["path"]]
    return df


# ---------------------------------------------------------------------------------------------------- features (as-of rule)
def snap_end(months) -> pd.Series:
    return (pd.to_datetime(pd.Series(months).astype(str) + "-01", utc=True) + pd.offsets.MonthEnd(0)
            + pd.Timedelta(hours=23, minutes=59, seconds=59))


def features_for(pool: pd.DataFrame, tpl: pd.DataFrame, published: pd.Series, prefix: str = "nuclei") -> pd.DataFrame:
    """pool: cve_id, snapshot_month. tpl: cve_id, first_date, bulk. Only templates dated <= the CVE's snapshot-month end and not
    from a bulk commit count."""
    d = pool[["cve_id", "snapshot_month"]].copy().reset_index(drop=True)
    d["end"] = snap_end(d["snapshot_month"]).to_numpy()
    t = tpl[tpl["cve_id"].notna() & ~tpl["bulk"] & ~tpl.get("date_invalid", False)][["cve_id", "first_date"]]
    m = t.merge(d[["cve_id", "end"]], on="cve_id")
    m = m[m["first_date"] <= m["end"]]
    g = m.groupby("cve_id").agg(n=("first_date", "size"), first=("first_date", "min"))
    n = g["n"].reindex(d["cve_id"]).fillna(0).astype(int).to_numpy()
    first = pd.to_datetime(g["first"].reindex(d["cve_id"]).to_numpy(), utc=True)
    pub = pd.to_datetime(published.reindex(d["cve_id"]).to_numpy(), utc=True)
    days = ((first - pub) / pd.Timedelta(days=1)).to_numpy(dtype=float)
    out = pd.DataFrame({"cve_id": d["cve_id"],
                        f"{prefix}_has_template_by_snapshot": (n > 0).astype(int),
                        f"{prefix}_days_published_to_first_template": np.where(n > 0, np.nan_to_num(days, nan=-1.0), -1.0),
                        f"{prefix}_n_templates_by_snapshot": n})
    return out


def pools() -> dict:
    P = {}
    for y, f in POOLS.items():
        d = pd.read_parquet(OUT_DIR / f)
        P[y] = d[["cve_id", "snapshot_month"] + (["label"] if "label" in d.columns else [])].reset_index(drop=True)
    return P


def published() -> pd.Series:
    v = pd.read_csv(DATA_DIR / "vulnerabilities.csv", usecols=["cve_id", "published"])
    return pd.to_datetime(v.set_index("cve_id")["published"], errors="coerce", utc=True)


# ---------------------------------------------------------------------------------------------------- evaluation
def _positions(c, score):
    order = np.lexsort((c["code"], -np.asarray(c["rank"]), -np.asarray(score)))
    pos = np.empty(len(order), dtype=np.int64)
    pos[order] = np.arange(len(order))
    return pos


def new_cols(prefix: str) -> list:
    return [c.replace("nuclei", prefix, 1) for c in NEW]


def evaluate(feat: dict, runs: list, prefix: str = "nuclei", label_name: str = "Nuclei") -> pd.DataFrame:
    """feat: {year: DataFrame(cve_id, NEW...)} for 2024 and 2025. Variants: v6, A = v6 + NEW, B = NEW alone."""
    from joblib import Parallel, delayed
    from src.b import leakage as lk
    from src.b import rank as R
    from src.common import primary
    from src.common.scoring import clustered_paired_bootstrap_hits, paired_bootstrap_hits
    from src.models import stress_v2 as st
    from src.models import train_v1 as v1
    from src.models.train_v4 import bag, ci, kev_events
    from src.models.train_v5 import FEATURES_V5, bootstrap_p

    F5 = list(FEATURES_V5)
    NEWC = new_cols(prefix)
    A, B = f"A: v6 + {label_name} features", f"B: {label_name} features alone"
    data, ctx = R.load()
    kev = pd.read_csv(DATA_DIR / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"]).drop_duplicates("cve_id").set_index("cve_id")
    for y in (2024, 2025):
        ids = data[y]["meta"]["cve_id"].reset_index(drop=True)
        f = feat[y].set_index("cve_id").reindex(ids)
        assert f[NEWC].notna().all().all()
        for c in NEWC:
            data[y]["X5"][c] = f[c].to_numpy()
    variants = {"v6": F5, A: F5 + NEWC, B: list(NEWC)}

    def fit(params, feats, Xtr, ytr, Xte, s):
        return primary.lgbm(params, feats, s).fit(Xtr[feats], ytr).predict_proba(Xte[feats])[:, 1]

    def bag_of(params, feats, Xtr, ytr, Xte, seeds):
        return bag(Parallel(n_jobs=4)(delayed(fit)(params, feats, Xtr, ytr, Xte, s) for s in seeds))

    rows, scores, P = [], {}, {}
    for d in st.DIRS:
        c = ctx[d]
        P[d] = primary.direction_params(d[0], c["tr"]["X5"], c["tr"]["y"], c["tr"]["groups"], F5)
        for name, feats in variants.items():
            scores[(name, d)] = bag_of(P[d], feats, c["tr"]["X5"], c["tr"]["y"], c["te"]["X5"], SEEDS)
            runs.append({"run": f"{name} {d}", "status": "ok", "hits": st.hits_of(c, scores[(name, d)])})
    label = {st.DIRS[0]: "forward (train 2024 -> test 2025)", st.DIRS[1]: "stability (train 2025 -> test 2024)"}
    Bc, Be = {}, {}
    names = list(variants)
    for j, d in enumerate(st.DIRS):
        c = ctx[d]
        pos = [_positions(c, scores[(n, d)]) for n in names]
        meta = c["meta"].reset_index(drop=True)
        Bc[d] = paired_bootstrap_hits(c["label"], pos, c["k"], n=1000, seed=0)
        Be[d] = clustered_paired_bootstrap_hits(c["label"], kev_events(meta, kev), pos, c["k"], n=1000, seed=0)
    for test, dirs in (("forward (train 2024 -> test 2025)", [st.DIRS[0]]), ("stability (train 2025 -> test 2024)", [st.DIRS[1]]),
                       ("pooled", list(st.DIRS))):
        for i, n in enumerate(names):
            h = sum(st.hits_of(ctx[d], scores[(n, d)]) for d in dirs)
            row = {"test": test, "variant": n, "hits": h}
            if i:
                h6 = sum(st.hits_of(ctx[d], scores[("v6", d)]) for d in dirs)
                row["diff_vs_v6"] = h - h6
                row["cve_level_90"] = str([round(x) for x in ci(sum(Bc[d][:, i] - Bc[d][:, 0] for d in dirs))])
                row["event_clustered_90"] = str([round(x) for x in ci(sum(Be[d][:, i] - Be[d][:, 0] for d in dirs))])
            rows.append(row)
    res = pd.DataFrame(rows)

    # placebo for variant A: labels shuffled within each snapshot month of the training year, 10 x 5-seed bags vs 10 real 5-seed bags
    real, null = [], []
    for j in range(10):
        r_, n_ = 0, 0
        for d in st.DIRS:
            c = ctx[d]
            r_ += st.hits_of(c, bag_of(P[d], variants[A], c["tr"]["X5"], c["tr"]["y"], c["te"]["X5"], range(100 + 5 * j, 105 + 5 * j)))
            rng = np.random.default_rng(j)
            y = np.asarray(c["tr"]["y"]).copy()
            months = np.asarray(c["tr_months"])
            for m in np.unique(months):
                ix = np.where(months == m)[0]
                y[ix] = y[rng.permutation(ix)]
            n_ += st.hits_of(c, bag_of(P[d], variants[A], c["tr"]["X5"], y, c["te"]["X5"], range(1000 + 5 * j, 1005 + 5 * j)))
        real.append(r_)
        null.append(n_)
    d_obs, d_ci, p_boot = bootstrap_p(real, null)
    placebo = {"real_mean": float(np.mean(real)), "shuffled_mean": float(np.mean(null)), "diff": d_obs, "ci90": list(d_ci), "p": p_boot}
    runs.append({"run": "placebo (A, labels shuffled within month, 10 x 5-seed bags)", "status": "ok", **{k: str(v) for k, v in placebo.items()}})

    # leakage experiment: honest (A's columns) vs the same plus the banned after-the-fact columns
    leak = {}
    for d in st.DIRS:
        tr, te = d
        XL = {}
        for y in (tr, te):
            idsy = data[y]["meta"]["cve_id"]
            b = lk.banned_columns(idsy, DATA_DIR).set_index("cve_id").reindex(idsy).reset_index(drop=True)
            XL[y] = pd.concat([data[y]["X5"].reset_index(drop=True), b], axis=1)
        honest = variants[A]
        leaky = honest + [c for c in XL[tr].columns if c.startswith("leak_")]
        for arm, feats in ((f"honest (v6 + {label_name})", honest), ("with banned columns", leaky)):
            leak[(arm, d)] = st.hits_of(ctx[d], bag_of(P[d], feats, XL[tr], data[tr]["y"], XL[te], SEEDS))
    lrows = [{"test": label[d], "variant": f"leakage: {arm}", "hits": leak[(arm, d)]} for arm in (f"honest (v6 + {label_name})", "with banned columns") for d in st.DIRS]
    lrows += [{"test": "pooled", "variant": f"leakage: {arm}", "hits": sum(leak[(arm, d)] for d in st.DIRS)} for arm in (f"honest (v6 + {label_name})", "with banned columns")]
    res = pd.concat([res, pd.DataFrame(lrows)], ignore_index=True)
    return res, placebo


def verdict(res: pd.DataFrame, name: str) -> dict:
    h = res[res["variant"] == name].set_index("test")["hits"]
    v6 = res[res["variant"] == "v6"].set_index("test")["hits"]
    f, s = "forward (train 2024 -> test 2025)", "stability (train 2025 -> test 2024)"
    gain = int(h["pooled"] - v6["pooled"])
    ok = bool(h[f] >= v6[f] and h[s] >= v6[s] and gain >= 2 and gain >= NOISE_FLOOR)
    return {"variant": name, "forward": int(h[f]), "stability": int(h[s]), "pooled": int(h["pooled"]), "pooled_gain": gain, "passes": ok}


if __name__ == "__main__":
    print("use the driver in the report step: python -m src.b.new_data_run", file=sys.stderr)
