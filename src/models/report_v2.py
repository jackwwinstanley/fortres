"""Assemble outputs/v2_report.md from the fragments.  Run last:  python -m src.models.report_v2"""
import json

import pandas as pd

from src.common.paths import OUT_DIR


def depth_section(out_dir=OUT_DIR) -> str:
    df = pd.read_csv(out_dir / "depth_curves.csv")
    L = ["## Depth curves: where the hits come from (LOW POWER)", "",
         "Cumulative tie-aware expected hits at list depths 10, 25, 50, 100, k/2, k, 1.5k and 2k "
         "(full table: `outputs/depth_curves.csv`; figure: `docs/figures/depth_curves.png`). v1 curves use predictions from the "
         "model trained on the other replica. Score-only rankings are not fitted.", ""]
    for subset in ("all", "blind-spot"):
        sub = df[df["subset"] == subset]
        order = ["10", "25", "50", "100", "k/2", "k", "1.5k", "2k"]
        for y in (2024, 2025):
            s = sub[sub["replica"] == y]
            pt = s.pivot_table(index="ranking", columns="depth_label", values="hits_expected", sort=False)[order]
            L += [f"{subset} CVEs, replica {y} (k = {int(s['k'].iloc[0])}, {int(s['positives_in_subset'].iloc[0])} positives in the subset):", "",
                  "| ranking | " + " | ".join(order) + " |", "|" + "---|" * (len(order) + 1)]
            L += [f"| {n} | " + " | ".join(f"{v:.1f}" for v in row) + " |" for n, row in pt.iterrows()]
            L += [""]
    mg = json.loads((out_dir / ".cache" / "depth_marginal.json").read_text())
    L += ["Where the baseline stops adding hits (marginal hits per 25 slots, arbitrary tie order, whole pool): " +
          "; ".join(f"replica {y}: " + ("never within 2k" if v is None else f"first window under 1 hit/25 slots ends at depth {v[0]} "
                                        f"(cumulative {v[2]} hits)") for y, v in mg.items()) + ".", ""]
    return "\n".join(L)


def main(out_dir=OUT_DIR):
    c = out_dir / ".cache"
    tc = json.loads((c / "v2_two_channel.json").read_text())
    parts = ["# v2 report: Granite text features, depth curves and two-channel allocation", "",
             "> **LOW POWER.** 27 (2024) and 48 (2025) positives, 75 in total. All numbers are noisy; differences of a few hits "
             "are within noise. Nothing was tuned on a test replica. KEV history uses the fixed prior-December-31 cutoff; no 2026 "
             "KEV information is used.", "",
             "## Rule for the final list (decided before running)", "",
             "Final 2026 list = the two-channel allocation (top s CVEs of the exploit-then-EPSS order, rest from Channel B, a "
             "no-fit blend of four prior scores) with the highest pooled hits across both replicas; ties go to the larger s. "
             "If nothing beats the best baseline's pooled expected hits, the list still uses that rule (larger s on ties) and "
             "this report says so.", "",
             depth_section(out_dir), "## Models", "", (c / "v2_models.md").read_text(), "## Two channels", "",
             (c / "v2_two_channel.md").read_text(), "## Blind spots", "", (c / "v2_blindspot.md").read_text()]
    verdict = ["## Plain verdict", ""]
    rows = {r[0]: r for r in tc["rows"]}
    base_name = "Exploit code, then EPSS"
    b25, b24 = int(rows[base_name][1]), int(rows[base_name][2])
    verdict.append(f"- Best baseline ({base_name}): {b25} hits on replica 2025 and {b24} on 2024, "
                   f"{float(tc['base_pooled_expected']):.1f} pooled expected hits.")
    for name, r in rows.items():
        if name == base_name or name.startswith(("CVSS", "EPSS", "B alone")):
            continue
        h25, h24 = int(r[1]), int(r[2])
        both = h25 > b25 and h24 > b24
        verdict.append(f"- {name}: {h25} (2025) and {h24} (2024), pooled {r[3]}; diff vs baseline {r[5]}. "
                       f"More hits than the baseline in BOTH directions: **{'yes' if both else 'no'}**.")
    verdict += ["", "Intervals that include zero mean the gain is not distinguishable from noise with 75 positives. LightGBM with text features "
                "(v2) is the only ranking with more hits than the baseline in both directions, but its paired-bootstrap "
                "interval against the baseline still includes zero; the gain over the same model without text features has a lower "
                "bound of about zero. The two-channel allocation stays within one hit of the baseline. Channel B alone is far below "
                "the baseline, so the prior scores are a complement at best, not a replacement. The final list follows the "
                "pre-set rule (best pooled allocation, ties to larger s), not the v2 models, because the rule was fixed before the "
                "results; whether to switch to a v2 model is a separate decision for the team."]
    (out_dir / "v2_report.md").write_text("\n".join(parts + verdict) + "\n")
    print("wrote v2_report.md")


if __name__ == "__main__":
    main()
