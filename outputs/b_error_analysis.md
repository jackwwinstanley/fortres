# Error analysis: v5 vs the simple rule (Person B)

v5 20-seed bag rebuilt exactly as `src/models/train_v5.py`. LOW POWER: 27 and 48 KEV CVEs.

## forward: train 2024 -> test 2025 (k = 243)

Model 12 · simple rule 13 · caught by both 8 · pre-declared 50/50 blend 15 (single seeds: model mean 12.6, blend mean 15.3; blend − model 90% paired bootstrap [-1.0, 7.0])

| cve_id         | caught_by        | kev                                              |   model_rank |   rule_rank |   k |   epss_rank_in_month | exploit_flags   |   kev_text_pct | txt_tags                      |   assigner_kev_share | granite_facts                                           |
|:---------------|:-----------------|:-------------------------------------------------|-------------:|------------:|----:|---------------------:|:----------------|---------------:|:------------------------------|---------------------:|:--------------------------------------------------------|
| CVE-2025-24472 | model only       | Fortinet FortiOS and FortiProxy                  |          133 |       13645 | 243 |                0.282 | none            |          0.98  | unauth,auth_bypass,enterprise |               0.0121 | nan / no / privilege_escalation                         |
| CVE-2025-27363 | simple rule only | FreeType FreeType                                |          400 |          75 | 243 |                0.993 | poc_github      |          0.386 | rce,memory                    |               0.0016 | library_or_framework / no / remote_code_execution       |
| CVE-2025-32433 | simple rule only | Erlang Erlang/OTP                                |         1973 |          80 | 243 |                0.994 | poc_github      |          0.553 | rce,unauth,edge_device        |               0.0089 | library_or_framework / no / remote_code_execution       |
| CVE-2025-20281 | model only       | Cisco Identity Services Engine                   |           95 |         281 | 243 |                0.877 | poc_github      |          0.984 | rce,unauth                    |               0.0589 | enterprise_server_software / no / remote_code_execution |
| CVE-2025-5086  | simple rule only | Dassault Systèmes DELMIA Apriso                  |         2372 |          28 | 243 |                0.999 | nuclei          |          0.937 | rce,deserialization           |               0      | library_or_framework / no / remote_code_execution       |
| CVE-2025-5777  | model only       | Citrix NetScaler ADC and Gateway                 |           15 |         385 | 243 |                0.768 | poc_github      |          0.98  | edge_device,enterprise        |               0.0048 | network_edge_device / no / nan                          |
| CVE-2025-54253 | simple rule only | Adobe Experience Manager (AEM) Forms             |          883 |         151 | 243 |                0.968 | poc_github      |          0.942 | rce                           |               0.0541 | library_or_framework / no / remote_code_execution       |
| CVE-2025-41244 | model only       | Broadcom VMware Aria Operations and VMware Tools |           52 |         727 | 243 |                0.093 | poc_github      |          0.948 | priv_esc                      |               0.0194 | enterprise_server_software / yes / privilege_escalation |
| CVE-2025-54236 | simple rule only | Adobe Commerce and Magento                       |          327 |         182 | 243 |                0.965 | poc_github      |          0.724 | none                          |               0.0541 | nan / no / nan                                          |

## stability: train 2025 -> test 2024 (k = 198)

Model 9 · simple rule 6 · caught by both 5 · pre-declared 50/50 blend 9 (single seeds: model mean 9.15, blend mean 8.45; blend − model 90% paired bootstrap [-2.0, 2.0])

| cve_id         | caught_by        | kev                                          |   model_rank |   rule_rank |   k |   epss_rank_in_month | exploit_flags   |   kev_text_pct | txt_tags                   |   assigner_kev_share | granite_facts                                            |
|:---------------|:-----------------|:---------------------------------------------|-------------:|------------:|----:|---------------------:|:----------------|---------------:|:---------------------------|---------------------:|:---------------------------------------------------------|
| CVE-2024-23897 | simple rule only | Jenkins Jenkins Command Line Interface (CLI) |         3536 |         145 | 198 |                0.724 | poc_github      |          0.711 | unauth,enterprise          |               0.0019 | web_application / no / information_disclosure            |
| CVE-2024-23113 | model only       | Fortinet Multiple Products                   |          156 |        1841 | 198 |                0.937 | none            |          0.992 | enterprise                 |               0.0104 | enterprise_server_software / no / remote_code_execution  |
| CVE-2024-30088 | model only       | Microsoft Windows                            |           22 |         347 | 198 |                0.512 | poc_github      |          0.997 | priv_esc,enterprise        |               0.2536 | operating_system / yes / privilege_escalation            |
| CVE-2024-6670  | model only       | Progress WhatsUp Gold                        |           96 |         594 | 198 |                0.208 | poc_github      |          0.622 | unauth,sqli                |               0.0009 | enterprise_server_software / no / information_disclosure |
| CVE-2024-40711 | model only       | Veeam Backup & Replication                   |           49 |         569 | 198 |                0.215 | poc_github      |          0.937 | rce,unauth,deserialization |               0.0142 | library_or_framework / no / remote_code_execution        |
