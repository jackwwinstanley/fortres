"""Zoo aggregator (step 4). python -m src.b.zoo.aggregate -> outputs/zoo_summary.md
Reads outputs/zoo/*.csv (every row = one attempted run). Applies the fixed screening / confirmation / tie-break rules."""
import glob
import json
from datetime import datetime, timezone

import pandas as pd

from src.b.zoo import harness as H

TIE_BREAK = ["m19", "m09", "m11", "m12", "m02", "m18", "m07", "m01", "m06", "m03", "m08"]
ADOPT_DEADLINE = "2026-11-08T07:30:00+00:00"  # 2:30 AM EST


def rows():
    fs = [f for f in sorted(glob.glob(str(H.ZOO / "m*.csv"))) if not f.endswith("_check.csv")]
    return pd.concat([pd.read_csv(f) for f in fs], ignore_index=True) if fs else pd.DataFrame()


def latest(df):
    df = df.copy()
    df["seed_set"] = df["seed_set"].astype(str)
    return df.sort_values("timestamp").groupby(["method", "variant", "seed_set"], as_index=False).tail(1)


def threshold():
    b = pd.read_csv(H.ZOO / "baselines.csv")
    p = b[b["baseline"] == "I"]["pooled"]
    return max(2, int(p.max() - p.min())), int(p.max() - p.min())


def screen(r, thr):
    if r["status"] != "ok":
        return r["status"]
    ok = r["forward"] >= r["forward_I"] and r["stability"] >= r["stability_I"] and r["pooled_delta_I"] >= thr
    return "passed screening" if ok else "failed screening"


def survivors():
    df = latest(rows())
    thr, _ = threshold()
    main = df[df["seed_set"] == H.MAIN_SET]
    return [(r["method"], r["variant"]) for _, r in main.iterrows() if screen(r, thr) == "passed screening"]


def confirmation(df, m, v):
    """Survivor variant on the 3 other seed sets: pooled > I pooled on all three, forward >= I forward in each.
    Deterministic standalone survivors: the blend with I is re-run on those sets too and reported."""
    out = []
    for ss in H.CONFIRM_SETS:
        r = df[(df["method"] == m) & (df["variant"] == v) & (df["seed_set"] == ss)]
        if r.empty or r.iloc[0]["status"] != "ok":
            out.append((ss, None))
            continue
        r = r.iloc[0]
        out.append((ss, (int(r["forward"]), int(r["stability"]), int(r["pooled"]), int(r["pooled_I"]), int(r["forward_I"]),
                         bool(r["pooled"] > r["pooled_I"] and r["forward"] >= r["forward_I"]))))
    return out


def main():
    allr = rows()
    df = latest(allr)
    thr, spread = threshold()
    base = pd.read_csv(H.ZOO / "baselines.csv")
    main_ = df[df["seed_set"] == H.MAIN_SET].copy()
    main_["verdict"] = main_.apply(lambda r: screen(r, thr), axis=1)
    conf = {}
    for _, r in main_[main_["verdict"] == "passed screening"].iterrows():
        c = confirmation(df, r["method"], r["variant"])
        conf[(r["method"], r["variant"])] = c
        if all(x is not None and x[5] for _, x in c):
            main_.loc[_, "verdict"] = "confirmed"
    order = {m: i for i, m in enumerate(TIE_BREAK)}
    main_["mid"] = main_["method"].str[:3]
    main_ = main_.sort_values(["mid", "variant"], key=lambda s: s.map(order) if s.name == "mid" else s)
    confirmed = main_[main_["verdict"] == "confirmed"].sort_values("mid", key=lambda s: s.map(order))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    L = ["# Method zoo summary (b/zoo)", "",
         f"Generated {now} by `python -m src.b.zoo.aggregate` from `outputs/zoo/*.csv`. Harness: `src/b/zoo/harness.py` (frozen in its own commit "
         "before any method ran). Features: frozen v5. Forward = train 2024 -> test 2025 (k = 243, 48 positives); stability = train 2025 -> test 2024 "
         "(k = 198, 27 positives); pooled = sum. Hits = KEV positives in the top k (ties: EPSS rank, then cve_id). LOW POWER: 75 positives in total.", "",
         "## Baselines (20-seed bags, per-seed scores cached)", "",
         "| baseline | seed set | forward | stability | pooled |", "|---|---|---|---|---|"]
    L += [f"| {r.baseline} | {r.seed_set} | {r.forward} | {r.stability} | {r.pooled} |" for r in base.itertuples()]
    L += ["", f"I's pooled spread over the 4 seed sets (measured): **{spread}**. Screening gain threshold = max(2, spread) = **{thr}**.", "",
          "## Rules (fixed before any result)", "",
          f"- Screening (seeds 0-19): forward >= I's forward, stability >= I's stability, pooled gain over I >= {thr}.",
          "- Confirmation: survivor re-run on seed sets 1000-1019, 2000-2019, 3000-3019 (deterministic methods: their blend with I re-run too); "
          "must beat I's pooled on all three and not lose forward in any.",
          "- Tie-break: " + ", ".join(TIE_BREAK) + ". Nothing adopted after 2:30 AM EST. 'Adopted' = named here only; no list or doc regenerated.",
          "- Feature coverage on the 2026 scoreboard = share of rows where the feature differs from its most common training value; 0 -> rejected.", "",
          "## Results (seeds 0-19): forward first, then stability, then pooled; delta vs I with 90% paired-bootstrap interval", "",
          "| method | variant | forward (I) | stability (I) | pooled (I) | delta vs I pooled [90%] | fwd random-tie hits | 2026 coverage | status |",
          "|---|---|---|---|---|---|---|---|---|"]
    for _, r in main_.iterrows():
        if r["status"] == "failed":
            L.append(f"| {r['method']} | {r['variant']} | - | - | - | - | - | - | failed: {r['reason']} |")
            continue
        cov = r.get("coverage_2026")
        cov = ", ".join(f"{k} {v:.0%}" for k, v in json.loads(cov).items()) if isinstance(cov, str) else "n/a"
        L.append(f"| {r['method']} | {r['variant']} | {int(r['forward'])} ({int(r['forward_I'])}) | {int(r['stability'])} ({int(r['stability_I'])}) | "
                 f"{int(r['pooled'])} ({int(r['pooled_I'])}) | {int(r['pooled_delta_I']):+d} {r['pooled_delta_I_90']} | {r['forward_hits_random_ties']} | {cov} | {r['verdict']} |")
    L += ["", "## Confirmation", ""]
    if not conf:
        L.append("No method variant passed screening, so nothing was re-run for confirmation.")
    for (m, v), c in conf.items():
        L.append(f"- {m} / {v}: " + "; ".join(f"{ss}: " + ("missing/failed" if x is None else f"{x[0]}/{x[1]}/{x[2]} vs I pooled {x[3]} (I fwd {x[4]}) -> {'beats' if x[5] else 'does not beat'}")
                                             for ss, x in c))
        for ss in H.CONFIRM_SETS:
            b = df[(df["method"] == m) & (df["variant"] == "blend_I") & (df["seed_set"] == ss)]
            if v == "standalone" and not b.empty and b.iloc[0]["status"] == "ok":
                b = b.iloc[0]
                L.append(f"  - blend_I on {ss}: {int(b['forward'])}/{int(b['stability'])}/{int(b['pooled'])} vs I {int(b['pooled_I'])}")
    L += ["", "## Adoption", ""]
    if confirmed.empty:
        L.append("**No survivor.** Nothing in the zoo passes screening and confirmation; I (and the v6 list) stay as they are.")
    else:
        top = confirmed.iloc[0]
        late = now > ADOPT_DEADLINE
        L.append(f"Survivor by tie-break: **{top['method']} / {top['variant']}**" + (" (but generated after 2:30 AM EST: NOT adopted)" if late else
                 ". Drop-in: same output (one score per CVE, top 500 by the same tie rule) as the v6 list; no list regenerated here."))
    fails = allr[allr["status"] == "failed"]
    L += ["", "## Runs attempted and failures", "",
          f"Runs attempted (every row in outputs/zoo/m*.csv, including failures and confirmation re-runs): **{len(allr)}** "
          f"({len(df)} distinct method x variant x seed set).", ""]
    if fails.empty:
        L.append("No failures.")
    for _, r in fails.iterrows():
        later = df[(df["method"] == r["method"]) & (df["variant"] == r["variant"]) & (df["seed_set"].astype(str) == str(r["seed_set"]))]
        sup = " (superseded: re-run after a fix and completed)" if not later.empty and later.iloc[0]["status"] == "ok" else ""
        L.append(f"- {r['timestamp']} {r['method']} / {r['variant']} / seeds {r['seed_set']}: {r['reason']}{sup}")
    L += ["", "## Checks", "", "- m02 CWE missingness by nvd_status (check only, never a feature): `outputs/zoo/m02_cwe_missingness_check.csv`.",
          "- Leak rules: methods see only v5 features, description text, CWE ids (m02), snapshot EPSS/exploit flags and in-fold labels; label-dependent steps "
          "(chi-square, CWE shrinkage, TF-IDF model, Cox, inner CV) fit on the training year only, feature-variant training rows leave-one-month-out. "
          "m19's discriminator is label-blind (training year vs 2026 scoreboard)."]
    (H.OUT_DIR / "zoo_summary.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
