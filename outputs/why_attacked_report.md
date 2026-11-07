# Why are some vulnerabilities attacked? (descriptive analysis for the pitch)

> **DESCRIPTIVE ONLY.** This analysis explains the past with today's NVD data. It is **not** used by any model, feature file or top-500 list, and nothing from it feeds into them. All statements are associations, never causes.

**Scope and definitions.** CVEs in `vulnerabilities.csv` published 2022-01-01 to 2025-09-30: 129,208 CVEs. *Attacked* = the cve_id appears in `known_exploited.csv` (CISA KEV, added on or before 2025-12-31; the file ends there): 577 CVEs, an overall rate of 0.45% (about 1 in 224). Because the CVEs are historical and the aim is to explain rather than predict, today's NVD fields (CVSS vector parts, `cwe_ids`, affected products) are used. These fields are not time-safe and must never be used as prediction features. Intervals are 95% Wilson intervals; *lift* = category attack rate / overall rate. Tables list categories with at least 200 CVEs or at least 10 attacked CVEs, sorted by lift.

## The five strongest, best-supported findings

1. **Exposure:** network-reachable CVEs that need no privileges and no user interaction were attacked at 0.72% (264 of 36,776) versus 0.34% (313 of 90,767) for all other CVSS 3 CVEs, 2.1x as often with non-overlapping 95% intervals (0.64%-0.81% vs 0.31%-0.39%); network attack vector alone barely separates (1.03x the overall rate).
2. **Weakness type:** Access of Resource Using Incompatible Type ('Type Confusion') (CWE-843) 5.4% (19 of 350, 12.2x); Authentication Bypass Using an Alternate Path or Channel (CWE-288) 3.4% (11 of 328, 7.5x); Missing Authentication for Critical Function (CWE-306) 2.7% (27 of 1,008, 6.0x); Deserialization of Untrusted Data (CWE-502) 2.1% (29 of 1,371, 4.7x) were the CWE types with the highest attack rates among those with at least 10 attacked CVEs.
3. **Who ships the CVE:** products from a few vendors dominate: Microsoft products appear in 115 of the 577 attacked CVEs (19.9%) at 2.9% of its 4,028 CVEs (6.4x), and the highest vendor attack rates are synacor 40.0% (10 of 25), webkitgtk 33.3% (11 of 33), citrix 15.9% (11 of 69), paloaltonetworks 9.1% (10 of 110).
4. **Speed:** half of the 577 attacked CVEs reached KEV within 7 days of NVD publication (quartiles 0 and 76); 64% within 30 days, 77% within 90 and 92% within 365 days (CVEs published 2022-2024, n=440); 55 were added before their NVD publication date.
5. **Invisibility:** 44 of 75 attacked CVEs (59%, 95% interval 47%-69%) in the 2024 and 2025 practice pools had no public exploit flag and a low within-month EPSS rank at the end of their publish month, and that share was 45%-75% across the vendor groups with at least 10 attacked CVEs.

## What a security team should do with this

These are practical priorities consistent with the associations above, not proven causes. Put internet-reachable, unauthenticated flaws in products that sit at the edge or manage other systems (missing-authentication, authentication-bypass, deserialization and command-injection types) at the front of the queue, especially from vendors with a history of exploited bugs, and plan for days, not months: half of the attacked CVEs reached KEV within about a week of publication and about two thirds within 30 days. Do not rely on a single signal: 1.2% of CRITICAL-severity CVEs were attacked, so about 99% of them never were, and most attacked CVEs (59% in the 2024-25 practice pools) showed neither public exploit code nor a high EPSS rank at the end of their publish month. Combine exposure (is the product reachable?), weakness type, vendor history and the exploit signals, and re-check weekly.

## Tables

### CVSS 3 attributes and the exposure combination

*attack_vector*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| NETWORK | 92,215 | 425 | 0.46% | 1.03x | 0.42%-0.51% |
| LOCAL | 31,289 | 138 | 0.44% | 0.99x | 0.37%-0.52% |
| ADJACENT_NETWORK | 2,987 | 11 | 0.37% | 0.82x | 0.21%-0.66% |
| PHYSICAL | 1,052 | 3 | 0.29% | 0.64x | 0.10%-0.84% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*attack_complexity*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| HIGH | 6,665 | 31 | 0.47% | 1.04x | 0.33%-0.66% |
| LOW | 120,878 | 546 | 0.45% | 1.01x | 0.42%-0.49% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*privileges_required*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| NONE | 66,774 | 397 | 0.59% | 1.33x | 0.54%-0.66% |
| HIGH | 11,743 | 42 | 0.36% | 0.80x | 0.26%-0.48% |
| LOW | 49,026 | 138 | 0.28% | 0.63x | 0.24%-0.33% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*user_interaction*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| NONE | 86,474 | 445 | 0.51% | 1.15x | 0.47%-0.56% |
| REQUIRED | 41,069 | 132 | 0.32% | 0.72x | 0.27%-0.38% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*scope*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| UNCHANGED | 99,694 | 505 | 0.51% | 1.13x | 0.46%-0.55% |
| CHANGED | 27,849 | 72 | 0.26% | 0.58x | 0.21%-0.33% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*confidentiality_impact*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| HIGH | 66,072 | 514 | 0.78% | 1.74x | 0.71%-0.85% |
| NONE | 29,100 | 34 | 0.12% | 0.26x | 0.08%-0.16% |
| LOW | 32,371 | 29 | 0.09% | 0.20x | 0.06%-0.13% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*integrity_impact*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| HIGH | 55,776 | 477 | 0.86% | 1.92x | 0.78%-0.94% |
| NONE | 38,100 | 65 | 0.17% | 0.38x | 0.13%-0.22% |
| LOW | 33,667 | 35 | 0.10% | 0.23x | 0.07%-0.14% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*availability_impact*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| HIGH | 68,865 | 460 | 0.67% | 1.50x | 0.61%-0.73% |
| NONE | 49,165 | 108 | 0.22% | 0.49x | 0.18%-0.27% |
| LOW | 9,513 | 9 | 0.09% | 0.21x | 0.05%-0.18% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*cvss3_severity*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| CRITICAL | 18,543 | 219 | 1.18% | 2.64x | 1.04%-1.35% |
| HIGH | 47,491 | 285 | 0.60% | 1.34x | 0.53%-0.67% |
| MEDIUM | 58,940 | 70 | 0.12% | 0.27x | 0.09%-0.15% |
| LOW | 2,567 | 3 | 0.12% | 0.26x | 0.04%-0.34% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

*network + no privileges + no user interaction*

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| network + no privileges + no user interaction | 36,776 | 264 | 0.72% | 1.61x | 0.64%-0.81% |
| all other CVSS 3 CVEs | 90,767 | 313 | 0.34% | 0.77x | 0.31%-0.39% |
| (missing) | 1,665 | 0 | 0.00% | 0.00x | 0.00%-0.23% |

### Weakness types (CWE), top by lift; a CVE with several CWE ids is counted under each

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| CWE-843 Access of Resource Using Incompatible Type ('Type Confusion' | 350 | 19 | 5.43% | 12.16x | 3.50%-8.32% |
| CWE-288 Authentication Bypass Using an Alternate Path or Channel | 328 | 11 | 3.35% | 7.51x | 1.88%-5.90% |
| CWE-306 Missing Authentication for Critical Function | 1,008 | 27 | 2.68% | 6.00x | 1.85%-3.87% |
| CWE-693 Protection Mechanism Failure | 251 | 6 | 2.39% | 5.35x | 1.10%-5.12% |
| CWE-502 Deserialization of Untrusted Data | 1,371 | 29 | 2.12% | 4.74x | 1.48%-3.02% |
| CWE-73 External Control of File Name or Path | 231 | 4 | 1.73% | 3.88x | 0.68%-4.37% |
| CWE-78 Improper Neutralization of Special Elements used in an OS Co | 2,623 | 43 | 1.64% | 3.67x | 1.22%-2.20% |
| CWE-290 Authentication Bypass by Spoofing | 311 | 5 | 1.61% | 3.60x | 0.69%-3.71% |
| CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition | 356 | 5 | 1.40% | 3.15x | 0.60%-3.25% |
| CWE-754 Improper Check for Unusual or Exceptional Conditions | 299 | 4 | 1.34% | 3.00x | 0.52%-3.39% |
| CWE-59 Improper Link Resolution Before File Access ('Link Following | 465 | 6 | 1.29% | 2.89x | 0.59%-2.79% |
| CWE-116 Improper Encoding or Escaping of Output | 233 | 3 | 1.29% | 2.88x | 0.44%-3.72% |
| CWE-94 Improper Control of Generation of Code ('Code Injection') | 2,562 | 31 | 1.21% | 2.71x | 0.85%-1.71% |
| CWE-416 Use After Free | 3,499 | 36 | 1.03% | 2.30x | 0.74%-1.42% |
| CWE-287 Improper Authentication | 1,410 | 14 | 0.99% | 2.22x | 0.59%-1.66% |
| CWE-863 Incorrect Authorization | 1,525 | 15 | 0.98% | 2.20x | 0.60%-1.62% |
| CWE-77 Improper Neutralization of Special Elements used in a Comman | 1,858 | 18 | 0.97% | 2.17x | 0.61%-1.53% |
| CWE-798 Use of Hard-coded Credentials | 760 | 7 | 0.92% | 2.06x | 0.45%-1.89% |
| CWE-707 Improper Neutralization | 219 | 2 | 0.91% | 2.05x | 0.25%-3.27% |
| CWE-122 Heap-based Buffer Overflow | 1,399 | 12 | 0.86% | 1.92x | 0.49%-1.49% |

### Vendors from affected_products.csv (vulnerable = Y), top by lift

| category | CVEs | attacked | attack rate | lift | 95% interval | share of attacked |
|---|---|---|---|---|---|---|
| synacor | 25 | 10 | 40.00% | 89.57x | 23.40%-59.26% | 1.7% |
| webkitgtk | 33 | 11 | 33.33% | 74.64x | 19.75%-50.39% | 1.9% |
| citrix | 69 | 11 | 15.94% | 35.70x | 9.14%-26.33% | 1.9% |
| paloaltonetworks | 110 | 10 | 9.09% | 20.36x | 5.01%-15.93% | 1.7% |
| vmware | 236 | 17 | 7.20% | 16.13x | 4.55%-11.23% | 2.9% |
| ivanti | 347 | 20 | 5.76% | 12.91x | 3.76%-8.73% | 3.5% |
| microsoft | 4,028 | 115 | 2.86% | 6.39x | 2.38%-3.42% | 19.9% |
| apple | 2,093 | 48 | 2.29% | 5.14x | 1.73%-3.03% | 8.3% |
| cisco | 1,067 | 24 | 2.25% | 5.04x | 1.52%-3.33% | 4.2% |
| fortinet | 595 | 13 | 2.18% | 4.89x | 1.28%-3.70% | 2.3% |
| trendmicro | 209 | 4 | 1.91% | 4.29x | 0.75%-4.82% | 0.7% |
| tp-link | 225 | 4 | 1.78% | 3.98x | 0.69%-4.48% | 0.7% |
| netapp | 902 | 15 | 1.66% | 3.72x | 1.01%-2.73% | 2.6% |
| debian | 2,651 | 44 | 1.66% | 3.72x | 1.24%-2.22% | 7.6% |
| fedoraproject | 1,872 | 31 | 1.66% | 3.71x | 1.17%-2.34% | 5.4% |
| juniper | 381 | 6 | 1.57% | 3.53x | 0.72%-3.39% | 1.0% |
| f5 | 281 | 4 | 1.42% | 3.19x | 0.55%-3.60% | 0.7% |
| apache | 917 | 13 | 1.42% | 3.17x | 0.83%-2.41% | 2.3% |
| redhat | 800 | 10 | 1.25% | 2.80x | 0.68%-2.29% | 1.7% |
| dlink | 973 | 9 | 0.92% | 2.07x | 0.49%-1.75% | 1.6% |

CVEs with no vulnerable product listed: 20,118, of which 0 attacked (see limits).

### Assigners, top by lift

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| secure@citrix.com | 63 | 11 | 17.46% | 39.10x | 10.04%-28.62% |
| 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | 145 | 12 | 8.28% | 18.53x | 4.80%-13.91% |
| psirt@paloaltonetworks.com | 177 | 10 | 5.65% | 12.65x | 3.10%-10.09% |
| security@vmware.com | 332 | 16 | 4.82% | 10.79x | 2.99%-7.68% |
| chrome-cve-admin@google.com | 1,025 | 31 | 3.02% | 6.77x | 2.14%-4.26% |
| secure@microsoft.com | 3,948 | 105 | 2.66% | 5.96x | 2.20%-3.21% |
| support@hackerone.com | 475 | 11 | 2.32% | 5.19x | 1.30%-4.10% |
| disclosure@vulncheck.com | 450 | 10 | 2.22% | 4.98x | 1.21%-4.04% |
| psirt@fortinet.com | 594 | 13 | 2.19% | 4.90x | 1.28%-3.71% |
| product-security@apple.com | 1,968 | 43 | 2.18% | 4.89x | 1.63%-2.93% |
| security@trendmicro.com | 209 | 4 | 1.91% | 4.29x | 0.75%-4.82% |
| psirt@cisco.com | 1,171 | 21 | 1.79% | 4.02x | 1.18%-2.73% |
| sirt@juniper.net | 381 | 6 | 1.57% | 3.53x | 0.72%-3.39% |
| security@apache.org | 902 | 12 | 1.33% | 2.98x | 0.76%-2.31% |
| dsap-vuln-management@google.com | 235 | 3 | 1.28% | 2.86x | 0.44%-3.69% |

### Publish year

| category | CVEs | attacked | attack rate | lift | 95% interval |
|---|---|---|---|---|---|
| 2022 | 25,073 | 128 | 0.51% | 1.14x | 0.43%-0.61% |
| 2023 | 28,816 | 160 | 0.56% | 1.24x | 0.48%-0.65% |
| 2024 | 39,953 | 152 | 0.38% | 0.85x | 0.32%-0.45% |
| 2025 | 35,366 | 137 | 0.39% | 0.87x | 0.33%-0.46% |

### KEV vendor groups of the attacked CVEs (analyst-assigned groups, `why_attacked_vendor_group_map.csv`)

| vendor group | attacked CVEs | share of attacked |
|---|---|---|
| Operating systems, browsers & platforms | 207 | 35.9% |
| Network, security & storage appliances | 138 | 23.9% |
| Enterprise & IT-management software | 119 | 20.6% |
| Web apps, CMS & open source | 58 | 10.1% |
| Chips, mobile & device firmware | 18 | 3.1% |
| Other / unclassified | 16 | 2.8% |
| IoT, cameras & embedded | 15 | 2.6% |
| Desktop & file utilities | 6 | 1.0% |

Top KEV vendors: Microsoft 105, Apple 43, Google 31, Cisco 21, Ivanti 20, VMware 14, Fortinet 13, Adobe 13, Linux 12, Apache 12.

### Speed: days from NVD publication to KEV

| cohort | group | n | q25 | median | q75 | added before publication | within 30d | within 90d | within 365d |
|---|---|---|---|---|---|---|---|---|---|
| published 2022-01..2025-09 | all attacked | 577 | 0 | 7.0 | 76 | 55 | 64% | 77% | 94% |
| published 2022-01..2025-09 | ransomware use: Known | 125 | 0 | 7.0 | 44 | 11 | 69% | 78% | 98% |
| published 2022-01..2025-09 | ransomware use: Unknown | 452 | 0 | 7.5 | 88 | 44 | 62% | 76% | 93% |
| published 2022..2024 (365-day window fully observed) | all attacked | 440 | 0 | 8.0 | 103 | 52 | 61% | 72% | 92% |
| published 2022..2024 (365-day window fully observed) | ransomware use: Known | 105 | 0 | 7.0 | 91 | 11 | 65% | 74% | 98% |
| published 2022..2024 (365-day window fully observed) | ransomware use: Unknown | 335 | 0 | 9.0 | 114 | 41 | 60% | 72% | 90% |
| published 2024-01..2025-09 only (exploit_signals cover 2024-2025) | had a public exploit flag at end of publish month | 112 | 1 | 6.5 | 43 | 5 | 67% | 83% | 100% |
| published 2024-01..2025-09 only (exploit_signals cover 2024-2025) | no exploit flag at end of publish month | 177 | 0 | 6.0 | 55 | 5 | 66% | 81% | 98% |

The exploit-flag split uses CVEs published 2024-01 to 2025-09 only, because the exploit_signals files cover 2024-2025; the flag is the state at the end of the publish month, which for a CVE attacked early can already reflect the attack (proof-of-concept code often appears after exploitation begins).

### Invisible attacked CVEs in the 2024 and 2025 practice pools

| group | attacked CVEs | invisible | share invisible | 95% interval |
|---|---|---|---|---|
| replica 2024 | 27 | 17 | 63% | 44%-78% |
| replica 2025 | 48 | 27 | 56% | 42%-69% |
| both replicas | 75 | 44 | 59% | 47%-69% |
| Enterprise & IT-management software | 22 | 11 | 50% | 31%-69% |
| Web apps, CMS & open source | 22 | 10 | 45% | 27%-65% |
| Network, security & storage appliances | 12 | 9 | 75% | 47%-91% |
| Operating systems, browsers & platforms | 11 | 8 | 73% | 43%-90% |
| IoT, cameras & embedded | 5 | 3 | 60% | 23%-88% |
| Desktop & file utilities | 2 | 2 | 100% | 34%-100% |
| Chips, mobile & device firmware | 1 | 1 | 100% | 21%-100% |

'Invisible' = no public exploit flag and a within-month EPSS rank below the cut a top-k EPSS list would make (the same definition as `outputs/blindspot_positives.csv`, cross-checked). Groups with fewer than 10 attacked CVEs are too small to compare.

## Limits

- **Association, not causation.** Nothing here shows why attackers chose a CVE; categories overlap (a CVE can be network-reachable, unauthenticated, and from a popular vendor at once) and no adjustment was made.
- **KEV is a lower bound on real attacks and is US-government focused.** A CVE missing from KEV may still have been attacked; products and vendors central to US federal systems are over-represented.
- **NVD fields are today's versions.** Details can be added after an attack, and NIST reviews KEV entries first. The zero attacked among 1,665 CVEs with no CVSS 3 data and among 20,118 CVEs with no listed product is almost certainly this review order, not evidence that such CVEs are safe.
- **Right-censoring.** CVEs published in 2025 had at most 12 months to reach KEV (the file ends 2025-12-31), so 2025 rates and long-delay shares are understated; the 365-day share is reported only for CVEs published through 2024.
- **Small counts and many comparisons.** Many categories were examined; tiny categories (for example a vendor with 25 CVEs) have wide intervals and unstable lifts. A CVE with several CWE ids or vendors counts under each.
- **Vendor groups are analyst-assigned and coarse**; vendors not recognised fall under 'Other / unclassified'. Vendors in the NVD product list use NVD naming (lower case, no spaces) and differ from the KEV `vendor` field.
- **Too good to be true?** The zero-attacked rows for missing CVSS and missing products (above) and the very high rates for a few small vendors are artifacts of review order and small samples. Treat the lifts of the largest categories as the reliable ones.
