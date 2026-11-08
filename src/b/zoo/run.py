"""Zoo runner. python -m src.b.zoo.run main|confirm
Each method runs as its OWN niced background process (nice 10, so b/v6 keeps priority), at most cores-2 at once, hard cap
40 minutes. On timeout or a non-zero exit, every expected variant with no row for that seed set gets a status=failed row
with the reason, so no run is silently dropped. Logs: outputs/.cache/zoo/logs/ (not tracked)."""
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

import pandas as pd

from src.b.zoo import harness as H

CAP_S = 40 * 60
METHODS = {  # module: (variants, deterministic)
    "m01_elasticnet": (["standalone", "blend_I"], True),
    "m02_cwe_eb": (["standalone", "blend_I", "I_plus_feature"], True),
    "m03_cox": (["standalone", "blend_I"], True),
    "m06_mean_minus_sd": (["standalone", "blend_I"], True),
    "m07_extratrees": (["standalone", "blend_I"], False),
    "m08_isoforest": (["standalone", "blend_I", "I_plus_feature"], False),
    "m09_prototypes": (["standalone", "blend_I", "I_plus_feature"], True),
    "m11_regex": (["standalone", "blend_I", "I_plus_feature"], True),
    "m12_tfidf": (["standalone", "blend_I", "I_plus_feature"], True),
    "m18_balanced_bag": (["standalone", "blend_I"], False),
    "m19_adversarial": (["standalone", "blend_I", "I_plus_feature"], False),
}
LOGS = H.CACHE / "logs"
ATTEMPTS = H.ZOO / "_attempts.csv"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fill_failed(method, variants, seed_set, since, reason):
    out = H.ZOO / f"{method}.csv"
    have = pd.read_csv(out) if out.exists() else pd.DataFrame(columns=["variant", "seed_set", "timestamp"])
    have = have[(have["seed_set"].astype(str) == seed_set) & (have["timestamp"] >= since)]
    miss = [v for v in variants if v not in set(have["variant"])]
    if miss:
        rows = pd.DataFrame([{"timestamp": now(), "method": method, "variant": v, "seed_set": seed_set, "status": "failed", "reason": reason} for v in miss])
        pd.concat([pd.read_csv(out), rows], ignore_index=True).to_csv(out, index=False) if out.exists() else rows.to_csv(out, index=False)
    return miss


def run(jobs):
    """jobs: list of (method, variants, seed_set)."""
    LOGS.mkdir(parents=True, exist_ok=True)
    conc = max(1, (os.cpu_count() or 4) - 2)
    env = {**os.environ, "OMP_NUM_THREADS": "2", "MKL_NUM_THREADS": "2", "OPENBLAS_NUM_THREADS": "2", "ZOO_LGB_JOBS": "2",
           "HF_HUB_OFFLINE": "1", "TOKENIZERS_PARALLELISM": "false"}
    pending, running = list(jobs), []
    while pending or running:
        while pending and len(running) < conc:
            m, vs, ss = pending.pop(0)
            since = now()
            log = open(LOGS / f"{m}_{ss}.log", "a")
            p = subprocess.Popen(["nice", "-n", "10", sys.executable, "-m", f"src.b.zoo.{m}", "--seed-set", ss, "--variants", ",".join(vs)],
                                 stdout=log, stderr=subprocess.STDOUT, env=env)
            running.append((p, m, vs, ss, since, time.time(), log))
            H.log("START", m, ss, vs)
        time.sleep(5)
        for r in list(running):
            p, m, vs, ss, since, t0, log = r
            rc = p.poll()
            if rc is None and time.time() - t0 > CAP_S:
                p.kill()
                p.wait()
                rc = "timeout"
            if rc is None:
                continue
            running.remove(r)
            log.close()
            reason = "timeout: 40-minute cap hit" if rc == "timeout" else f"process exited with code {rc} (see log)"
            miss = fill_failed(m, vs, ss, since, reason) if rc != 0 else fill_failed(m, vs, ss, since, "process ended without writing this row")
            row = pd.DataFrame([{"timestamp": now(), "method": m, "seed_set": ss, "variants": ",".join(vs), "exit": rc,
                                 "runtime_s": round(time.time() - t0), "failed_filled": ",".join(miss)}])
            row.to_csv(ATTEMPTS, mode="a", header=not ATTEMPTS.exists(), index=False)
            H.log("END", m, ss, rc, "missing->failed:", miss)


def main(phase):
    if phase == "main":
        run([(m, vs, H.MAIN_SET) for m, (vs, _) in METHODS.items()])
    elif phase == "confirm":
        from src.b.zoo.aggregate import survivors
        jobs = []
        for m, v in survivors():
            vs = [v] + (["blend_I"] if METHODS[m][1] and v == "standalone" else [])
            for ss in H.CONFIRM_SETS:
                jobs.append((m, sorted(set(vs)), ss))
        H.log("confirm jobs", jobs)
        run(jobs)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "main")
