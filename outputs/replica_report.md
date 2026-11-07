# Replica sanity report

Difference from the real scoreboard: June uses June signals here; the 2026 scoreboard uses July for June.

## Pools and positives

| replica | pool before exclusion | dropped (signal only / date only / both) | kept | positives | k |
|---|---|---|---|---|---|
| 2024 | 28,902 | 0 / 5 / 58 | 28,839 | 27 | 198 |
| 2025 | 35,366 | 1 / 9 / 76 | 35,280 | 48 | 243 |

**WARNING: replica 2024 has only 27 positives (< 50). Hit counts and baseline comparisons are very noisy.**

**WARNING: replica 2025 has only 48 positives (< 50). Hit counts and baseline comparisons are very noisy.**

## Rows with no signal row (epss NULL, flags 0), by month

| month | 2024 | 2025 |
|---|---|---|
| 01 | 121 | 1,909 |
| 02 | 62 | 852 |
| 03 | 63 | 329 |
| 04 | 74 | 98 |
| 05 | 476 | 18 |
| 06 | 103 | 48 |
| 07 | 255 | 77 |
| 08 | 30 | 27 |
| 09 | 68 | 102 |

## Pool size per month vs the real 2026 scoreboard

| month | 2024 | 2025 | 2026 scoreboard |
|---|---|---|---|
| 01 | 2,585 | 4,267 | 4,295 |
| 02 | 2,773 | 3,664 | 4,603 |
| 03 | 3,305 | 3,982 | 6,227 |
| 04 | 3,612 | 4,024 | 5,801 |
| 05 | 4,991 | 3,967 | 6,922 |
| 06 | 3,075 | 3,674 | 0 |
| 07 | 3,105 | 3,768 | 17,678 |
| 08 | 2,885 | 3,621 | 12,242 |
| 09 | 2,508 | 4,313 | 14,902 |

(2026 June is folded into July by the judges.)

## Baselines (hits in top k) vs README 2026 top-500

| baseline | 2024 replica | 2025 replica | README 2026 (top 500) |
|---|---|---|---|
| CVSS 3 first | 0 [0-0] | 5 [2-9] | 7 |
| EPSS first | 3 [1-7] | 8 [4-13] | 6 |
| exploit code, then EPSS | 6 [2-10] | 13 [8-19] | 8 |
