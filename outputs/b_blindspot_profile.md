# What do the blind spots look like? (DESCRIPTIVE ONLY)

Labels by IBM Granite (granite-3.3-2b-instruct): small local model, noisy (21% of rows corrected by the consistency guard). Small groups. Post-hoc description of the practice years; never used to build or select a model. Small groups: read as rough shares.

## Login and network

| group                       |   no login needed (%) |   network reachable (%) |   labelled CVEs |   CVEs in group |
|:----------------------------|----------------------:|------------------------:|----------------:|----------------:|
| Exploited blind spots       |                    59 |                      61 |              44 |              44 |
| Exploited, had exploit code |                    77 |                      55 |              31 |              31 |
| Our 2026 picks (top500_v5)  |                    76 |                      71 |             500 |             500 |

## Product type (% of each group)

| product_type               |   Exploited blind spots |   Exploited, had exploit code |   Our 2026 picks (top500_v5) |
|:---------------------------|------------------------:|------------------------------:|-----------------------------:|
| Web application            |                      34 |                            39 |                           37 |
| Library / framework        |                      14 |                            23 |                           20 |
| Enterprise server software |                       7 |                            16 |                            9 |
| Operating system           |                      14 |                             6 |                            8 |
| Unlabelled                 |                      14 |                            10 |                           12 |
| Desktop application        |                       5 |                             0 |                            2 |
| IoT / firmware             |                       5 |                             0 |                            2 |
| VPN / firewall / edge      |                       2 |                             3 |                            4 |
| Other                      |                       2 |                             3 |                            4 |
| Browser                    |                       2 |                             0 |                            1 |
| Mobile app                 |                       2 |                             0 |                            0 |
| WordPress plugin           |                       0 |                             0 |                            1 |

## Main impact (% of each group)

| impact_type            |   Exploited blind spots |   Exploited, had exploit code |   Our 2026 picks (top500_v5) |
|:-----------------------|------------------------:|------------------------------:|-----------------------------:|
| authentication_bypass  |                      18 |                             3 |                           13 |
| cross_site_scripting   |                       7 |                             0 |                            3 |
| denial_of_service      |                       0 |                             0 |                            8 |
| file_read_or_write     |                       2 |                            10 |                            3 |
| information_disclosure |                      14 |                            19 |                           11 |
| other                  |                       2 |                             0 |                            0 |
| privilege_escalation   |                      20 |                            13 |                           20 |
| remote_code_execution  |                      32 |                            48 |                           29 |
| sql_injection          |                       2 |                             0 |                            4 |
| unlabelled             |                       2 |                             6 |                            9 |
