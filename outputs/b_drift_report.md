# Drift check: 2026 scoreboard vs the 2024/2025 practice pools (issue #9)

Produced by `python -m src.b.drift`. Allowed columns only (CONTRACT.md).

## In plain words
- A model trying to tell 2025 practice CVEs from 2026 scoreboard CVEs reaches ROC AUC **0.934** (0.5 = can't tell them apart), so the two sets are **clearly different**.
- Large shifts (PSI > 0.25): epss, assigner, days_to_snapshot.
- Moderate shifts (PSI 0.1-0.25): kev_text_score, nearest_kev_sim, txt_xss.
- The features that most give a 2026 CVE away: epss, assigner, days_to_snapshot.

Pool sizes: 2024: 28,839, 2025: 35,280, 2026: 72,670

## Per-feature shift (sorted by PSI 2025 vs 2026)

| feature             |   psi_2024_vs_2026 |   psi_2025_vs_2026 |   mean_2024 |   mean_2025 |   mean_2026 |
|:--------------------|-------------------:|-------------------:|------------:|------------:|------------:|
| epss                |             2.469  |             1.7015 |      0.0008 |      0.0016 |      0.0027 |
| assigner            |             0.8237 |             0.6596 |    nan      |    nan      |    nan      |
| days_to_snapshot    |             0.5234 |             0.493  |     15.276  |     14.9284 |     17.7634 |
| kev_text_score      |             0.1085 |             0.2215 |      0.2154 |      0.1932 |      0.2986 |
| nearest_kev_sim     |             0.0839 |             0.1292 |      0.7468 |      0.7492 |      0.7557 |
| txt_xss             |             0.0808 |             0.1065 |      0.1745 |      0.1905 |      0.0815 |
| txt_browser         |             0.0423 |             0.0585 |      0.0175 |      0.0133 |      0.0539 |
| txt_unauth          |             0.055  |             0.0559 |      0.0693 |      0.0688 |      0.1398 |
| txt_sqli            |             0.0087 |             0.0311 |      0.0658 |      0.0878 |      0.0447 |
| txt_wordpress       |             0.0244 |             0.0059 |      0.1103 |      0.0866 |      0.0664 |
| txt_memory          |             0.0017 |             0.0045 |      0.083  |      0.0759 |      0.0945 |
| txt_enterprise      |             0.0027 |             0.0028 |      0.0364 |      0.0362 |      0.0466 |
| txt_edge_device     |             0      |             0.0026 |      0.0279 |      0.0206 |      0.0284 |
| exploitdb           |             0.0001 |             0.0019 |      0.0008 |      0.002  |      0.0005 |
| txt_path_traversal  |             0.0004 |             0.0006 |      0.0236 |      0.0232 |      0.0269 |
| metasploit          |             0.0005 |             0.0005 |      0.0006 |      0.0006 |      0.0002 |
| poc_github          |             0.0002 |             0.0004 |      0.0193 |      0.0184 |      0.021  |
| txt_priv_esc        |             0.002  |             0.0003 |      0.0312 |      0.0267 |      0.0239 |
| txt_deserialization |             0.0003 |             0.0002 |      0.01   |      0.0131 |      0.0117 |
| nuclei              |             0.0006 |             0.0002 |      0.0036 |      0.0031 |      0.0023 |
| txt_auth_bypass     |             0.001  |             0.0001 |      0.0088 |      0.0113 |      0.0121 |
| txt_rce             |             0.0166 |             0      |      0.1099 |      0.0718 |      0.073  |
| txt_cmd_injection   |             0.0002 |             0      |      0.0248 |      0.0261 |      0.0268 |

## Spot-the-year classifier: permutation importance

| feature             |   auc_drop |
|:--------------------|-----------:|
| epss                |     0.3077 |
| assigner            |     0.1032 |
| days_to_snapshot    |     0.0958 |
| nearest_kev_sim     |     0.0148 |
| kev_text_score      |     0.0085 |
| txt_rce             |     0.0069 |
| txt_xss             |     0.0039 |
| txt_unauth          |     0.0035 |
| txt_cmd_injection   |     0.0033 |
| txt_sqli            |     0.0032 |
| txt_enterprise      |     0.0017 |
| txt_browser         |     0.0012 |
| txt_memory          |     0.0009 |
| txt_deserialization |     0.0008 |
| poc_github          |     0.0006 |
| txt_path_traversal  |     0.0006 |
| txt_auth_bypass     |     0.0005 |
| exploitdb           |     0.0004 |
| txt_edge_device     |     0.0004 |
| nuclei              |     0.0003 |
| txt_priv_esc        |     0.0002 |
| txt_wordpress       |     0.0001 |
| metasploit          |     0      |

Charts: `outputs/b_drift_psi.png`, `outputs/b_drift_classifier.png`.