"""Write the sanity report (print + outputs/replica_report.md). Run:  python -m src.report
Needs outputs/replica_stats.json and baseline_results.json (from src.replicas / src.baselines)."""
import json

from src.common.paths import OUT_DIR

README_2026 = {"baseline_cvss": 7, "baseline_epss": 6, "baseline_exploit_epss": 8}


def build(out_dir=OUT_DIR) -> str:
    st = json.loads((out_dir / "replica_stats.json").read_text())
    bl = json.loads((out_dir / "baseline_results.json").read_text())
    L = ["# Replica sanity report", ""]
    L += ["Difference from the real scoreboard: June uses June signals here; the 2026 scoreboard uses July for June.", ""]
    L += ["## Pools and positives", "", "| replica | pool before exclusion | dropped (signal only / date only / both) | kept | positives | k |", "|---|---|---|---|---|---|"]
    for y in ("2024", "2025"):
        s = st[y]
        L.append(f"| {y} | {s['pool_before_exclusion']:,} | {s['dropped_signal_only']} / {s['dropped_date_only']} / {s['dropped_both']} | "
                 f"{s['kept']:,} | {s['positives']} | {bl[y]['k']} |")
    for y in ("2024", "2025"):
        if st[y]["positives"] < 50:
            L += ["", f"**WARNING: replica {y} has only {st[y]['positives']} positives (< 50). "
                      f"Hit counts and baseline comparisons are very noisy.**"]
    L += ["", "## Rows with no signal row (epss NULL, flags 0), by month", "", "| month | 2024 | 2025 |", "|---|---|---|"]
    months = sorted(set(st["2024"]["no_signal_by_month"]) | set(st["2025"]["no_signal_by_month"]), key=lambda m: m[-2:])
    for m in sorted({x[-2:] for x in months}):
        a = st["2024"]["no_signal_by_month"].get(f"2024-{m}", 0)
        b = st["2025"]["no_signal_by_month"].get(f"2025-{m}", 0)
        L.append(f"| {m} | {a:,} | {b:,} |")
    L += ["", "## Pool size per month vs the real 2026 scoreboard", "",
          "| month | 2024 | 2025 | 2026 scoreboard |", "|---|---|---|---|"]
    sb = st["scoreboard_by_month"]
    for m in [f"{i:02d}" for i in range(1, 10)]:
        L.append(f"| {m} | {st['2024']['pool_by_month'].get(f'2024-{m}', 0):,} | "
                 f"{st['2025']['pool_by_month'].get(f'2025-{m}', 0):,} | {sb.get(f'2026-{m}', 0):,} |")
    L.append("")
    L.append("(2026 June is folded into July by the judges.)")
    L += ["", "## Baselines (hits in top k) vs README 2026 top-500", "",
          "| baseline | 2024 replica | 2025 replica | README 2026 (top 500) |", "|---|---|---|---|"]
    for v, name in [("baseline_cvss", "CVSS 3 first"), ("baseline_epss", "EPSS first"), ("baseline_exploit_epss", "exploit code, then EPSS")]:
        cells = [f"{bl[y][v]['hits']} [{bl[y][v]['ci90'][0]:.0f}-{bl[y][v]['ci90'][1]:.0f}]" for y in ("2024", "2025")]
        L.append(f"| {name} | {cells[0]} | {cells[1]} | {README_2026[v]} |")
    return "\n".join(L) + "\n"


def main(out_dir=OUT_DIR):
    text = build(out_dir)
    (out_dir / "replica_report.md").write_text(text)
    print(text)


if __name__ == "__main__":
    main()
