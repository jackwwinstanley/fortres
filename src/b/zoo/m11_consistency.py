"""m11 consistency check (rules: outputs/zoo/m11_consistency_rules.md, committed before any new result).
python -m src.b.zoo.m11_consistency -> outputs/zoo/m11_consistency.csv, outputs/zoo/m11_consistency.md
Every scored run goes through harness.evaluate (rows in outputs/zoo/m11_regex.csv and m11_placebo.csv). The 10-set mean
interval and the scoreboard overlap re-create the same scores with the harness's own functions (hits checked equal)."""
import json

import numpy as np
import pandas as pd

from src.b.zoo import harness as H
from src.b.zoo import m11_regex as m11
from src.common.scoring import paired_bootstrap_hits
from src.models import stress_v2 as st
from src.models.train_v4 import bag

FRESH = {f"{a}-{a + 19}": list(range(a, a + 20)) for a in (4000, 5000, 6000, 7000, 8000, 9000)}
H.SEED_SETS.update(FRESH)
ALL = [H.MAIN_SET, *H.CONFIRM_SETS, *FRESH]


def placebo_fn(i):
    def fn(train, apply, seed, env):
        f = m11.feature(train, apply, seed, env)
        rng = np.random.default_rng(10_000 + i)
        perm = st.within_month_permutation(apply.months, rng)
        return f.iloc[perm].reset_index(drop=True)
    return fn


def m11_score(d, ss):
    pools, _, _ = H.load()
    tr, te = pools[d[0]], pools[d[1]]
    seeds = H.SEED_SETS[ss]
    env = {"direction": d}
    ftr = H.oof_features(m11.feature, tr, seeds[0], env)
    fte = m11.feature(tr, te, seeds[0], env).reset_index(drop=True).astype(float)
    ftr.columns = fte.columns = [f"zoo_{x}" for x in fte.columns]
    Xtr, Xte = pd.concat([tr.X, ftr], axis=1), pd.concat([te.X, fte], axis=1)
    return bag([H.lgb_fit_predict(H.I_PARAMS[d[0]], Xtr, tr.y, Xte, s) for s in seeds])


def latest(name, variant, ss):
    d = pd.read_csv(H.ZOO / f"{name}.csv")
    d = d[(d["variant"] == variant) & (d["seed_set"].astype(str) == ss) & (d["status"] == "ok")]
    return d.sort_values("timestamp").iloc[-1]


def overlap():
    pools, _, _ = H.load()
    p = H.I_PARAMS[2025]
    a, b, sb = pools[2024], pools[2025], pools["sb"]
    X = pd.concat([a.X, b.X], ignore_index=True)
    y = np.r_[a.y, b.y]
    env = {}
    fa = H.oof_features(m11.feature, a, 0, env)  # label-free feature: OOF == direct, kept for symmetry
    fb = H.oof_features(m11.feature, b, 0, env)
    fs = m11.feature(b, sb, 0, env).astype(float)
    F = pd.concat([fa, fb], ignore_index=True)
    F.columns = fs.columns = [f"zoo_{c}" for c in fs.columns]
    sI = bag([H.lgb_fit_predict(p, X, y, sb.X, s) for s in H.SEED_SETS[H.MAIN_SET]])
    sM = bag([H.lgb_fit_predict(p, pd.concat([X, F], axis=1), y, pd.concat([sb.X, fs.reset_index(drop=True)], axis=1), s) for s in H.SEED_SETS[H.MAIN_SET]])

    def top(s):
        o = np.lexsort((sb.cve_id, -sb.rank, -s))
        return set(sb.cve_id[o[:500]])
    tI, tM = top(sI), top(sM)
    return len(tI - tM)


def main():
    # 1) fresh seed sets: plain I is cached inside evaluate (baseline_seed_scores); I+m11 through evaluate
    for ss in FRESH:
        H.evaluate("m11_regex", m11.feature, "I_plus_feature", seed_set=ss, deterministic=True, params={"patterns": m11.PATTERNS},
                   notes="consistency check, fresh seed set")
    # 2) placebo
    for i in range(5):
        H.evaluate("m11_placebo", placebo_fn(i), "I_plus_feature", seed_set=H.MAIN_SET, deterministic=True,
                   notes=f"m11 features shuffled within snapshot month, shuffle {i}")
    # 3) per-set table
    rows = []
    for ss in ALL:
        r = latest("m11_regex", "I_plus_feature", ss)
        rows.append({"seed_set": ss, "fresh": ss in FRESH, "I_forward": int(r.forward_I), "m11_forward": int(r.forward), "I_stability": int(r.stability_I),
                     "m11_stability": int(r.stability), "I_pooled": int(r.pooled_I), "m11_pooled": int(r.pooled), "delta_pooled": int(r.pooled_delta_I),
                     "delta_90_per_set": r.pooled_delta_I_90})
    t = pd.DataFrame(rows)
    # 4) 10-set mean gain, bootstrap over CVEs with the same resample applied to all 10 sets
    pools, ctx, _ = H.load()
    draws = 0
    for j, d in enumerate(H.DIRS):
        c = ctx[d]
        pos, chk = [], []
        for ss in ALL:
            sm, si = m11_score(d, ss), H.baseline_bag("I", d, ss)
            r = t[t.seed_set == ss].iloc[0]
            nm = H.DNAME[d]
            assert st.hits_of(c, sm) == r[f"m11_{nm}"] and st.hits_of(c, si) == r[f"I_{nm}"], f"recomputed hits differ for {ss} {nm}"
            pos += [H.positions(c, sm), H.positions(c, si)]
        B = paired_bootstrap_hits(c["label"], pos, c["k"], n=H.N_BOOT, seed=j)
        draws = draws + (B[:, 0::2] - B[:, 1::2]).mean(1)
    mean_gain = float(t.delta_pooled.mean())
    lo, hi = np.percentile(draws, 5), np.percentile(draws, 95)
    # 5) placebo
    pl = pd.read_csv(H.ZOO / "m11_placebo.csv")
    pl = pl[pl.status == "ok"].tail(5)
    real0 = int(t[t.seed_set == H.MAIN_SET].delta_pooled.iloc[0])
    # 6) rules
    a = (t.delta_pooled >= 1).sum() >= 9 and (t.delta_pooled >= 0).all()
    b = (t.m11_forward >= t.I_forward).all()
    c_ = (t.m11_stability >= t.I_stability).all()
    d_ = mean_gain >= 1 and lo > 0
    e = pl.pooled_delta_I.mean() < real0
    verdict = all([a, b, c_, d_, e])
    ov = overlap()
    t.to_csv(H.ZOO / "m11_consistency.csv", index=False)
    fresh = t[t.fresh]
    L = ["# m11 consistency check: I + m11 (regex exploit/PoC words) vs I", "",
         "Rules: `outputs/zoo/m11_consistency_rules.md` (committed before any new result). Code: `src/b/zoo/m11_consistency.py`; every run went through the "
         "frozen harness's `evaluate()` (rows in `m11_regex.csv`, `m11_placebo.csv`).", "",
         "**Honesty note:** the +1 bar was proposed AFTER seeing m11's +1 on seeds 0-19 (post hoc). The 3 old confirmation sets (1000/2000/3000) had also been run "
         "before the rules were written. The 6 fresh seed sets (4000-9019) are the real test.", "",
         f"## Verdict: **{'CONSISTENT - passes the +1 bar' if verdict else 'NOT consistent - m11 is not adopted, I stays'}**", "",
         "| rule | result |", "|---|---|",
         f"| (a) pooled >= I + 1 on >= 9 of 10 sets, never below I | {'pass' if a else 'FAIL'}: +1 or more on {(t.delta_pooled >= 1).sum()}/10, below I on {(t.delta_pooled < 0).sum()} |",
         f"| (b) forward never below I | {'pass' if b else 'FAIL'}: below on {(t.m11_forward < t.I_forward).sum()} sets |",
         f"| (c) stability never below I | {'pass' if c_ else 'FAIL'}: below on {(t.m11_stability < t.I_stability).sum()} sets |",
         f"| (d) 10-set mean gain >= +1 and 90% interval excludes 0 | {'pass' if d_ else 'FAIL'}: mean {mean_gain:+.1f}, 90% interval [{lo:+.1f}, {hi:+.1f}] |",
         f"| placebo (shuffled m11) gains less than real | {'pass' if e else 'FAIL'}: placebo mean {pl.pooled_delta_I.mean():+.1f} vs real {real0:+d} on seeds 0-19 |", "",
         "## Per seed set (forward / stability / pooled)", "",
         "| seed set | fresh? | I | I + m11 | pooled delta | per-set 90% interval |", "|---|---|---|---|---|---|"]
    L += [f"| {r.seed_set} | {'yes' if r.fresh else 'no'} | {r.I_forward} / {r.I_stability} / {r.I_pooled} | {r.m11_forward} / {r.m11_stability} / {r.m11_pooled} | "
          f"{r.delta_pooled:+d} | {r.delta_90_per_set} |" for r in t.itertuples()]
    L += ["", f"Mean pooled gain, all 10 sets: **{mean_gain:+.1f}** (90% interval [{lo:+.1f}, {hi:+.1f}]; paired bootstrap over CVEs, 1,000 draws per direction, the same "
          f"resample applied to all 10 sets, i.e. pooled across seeds). Fresh 6 sets only: mean {fresh.delta_pooled.mean():+.2f}, "
          f"+1 or more on {(fresh.delta_pooled >= 1).sum()}/6, below I on {(fresh.delta_pooled < 0).sum()}/6.", "",
          "## Placebo (m11 features shuffled within snapshot month, seeds 0-19)", "",
          "| shuffle | forward | stability | pooled | delta vs I |", "|---|---|---|---|---|"]
    L += [f"| {i} | {int(r.forward)} | {int(r.stability)} | {int(r.pooled)} | {int(r.pooled_delta_I):+d} |" for i, r in enumerate(pl.itertuples())]
    L += ["", "## Scoreboard picks that would change", "",
          f"If I+m11 replaced I: **{ov} of the 500** scoreboard picks change (approximation: both trained on both replicas with I's 2025 settings, seeds 0-19, "
          "top 500 by score, EPSS rank, cve_id; no top500 file written)."]
    (H.ZOO / "m11_consistency.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
