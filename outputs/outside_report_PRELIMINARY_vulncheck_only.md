# Outside data: VulnCheck KEV (local report, not committed)

## Fields
5,809 entries. Fields: `_timestamp` (str), `cisa_date_added` (str), `cve` (list), `cwes` (list), `date_added` (str), `dueDate` (str), `knownRansomwareCampaignUse` (str), `product` (str), `reported_exploited_by_vulncheck_canaries` (bool), `required_action` (str), `shortDescription` (str), `updated_at` (str), `vendorProject` (str), `vulncheck_reported_exploitation` (list), `vulncheck_xdb` (list), `vulnerabilityName` (str)
Date fields in one entry: `dueDate`=2022-04-15T00:00:00Z, `cisa_date_added`=2022-03-25T00:00:00Z, `date_added`=2015-02-23T00:00:00Z, `updated_at`=2015-02-23T00:00:00Z, `_timestamp`=2026-08-17T22:02:52.766612193Z

## Coverage of vc_exploited_by_snapshot (after removing mirrored entries)
- 2024: 210 of 28,839 CVEs (0.73%); raw before mirror removal 210
- 2025: 181 of 35,280 CVEs (0.51%); raw before mirror removal 181
- 2026: 249 of 72,670 CVEs (0.34%); raw before mirror removal 249

## Leak checks
```
{
 "positives": 75,
 "positives_raw_flag": 33,
 "positives_flagged": 33,
 "negatives_flagged": 358,
 "flagged_in_cisa": 36,
 "vc_minus_cisa_days": {
  "0.0": -368.0,
  "0.25": -71.75,
  "0.5": -35.0,
  "0.75": -22.25,
  "1.0": -2.0
 },
 "mirrored_excluded": 0,
 "vc_entries": 5809,
 "vc_min_date": "2000-01-11",
 "top_dates": {
  "2026-10-13": 108,
  "2024-01-22": 59,
  "2021-11-03": 53,
  "2023-11-13": 48,
  "2022-03-03": 47
 },
 "share_on_top_date": 0.019,
 "date_before_published": 1134,
 "date_before_2023": 2103
}
```

## Evaluation (once each, no tuning)

| test                                | variant             |   k |   hits |   flagged_in_pool | diff_vs_v5_90   |
|:------------------------------------|:--------------------|----:|-------:|------------------:|:----------------|
| forward (train 2024 -> test 2025)   | v5 frozen           | 243 |     12 |               181 | nan             |
| forward (train 2024 -> test 2025)   | A two-tier          | 243 |     23 |               181 | [+5, +19]       |
| forward (train 2024 -> test 2025)   | B v5 + flag feature | 243 |     19 |               181 | [+3, +11]       |
| stability (train 2025 -> test 2024) | v5 frozen           | 198 |      9 |               210 | nan             |
| stability (train 2025 -> test 2024) | A two-tier          | 198 |     10 |               210 | [-5, +7]        |
| stability (train 2025 -> test 2024) | B v5 + flag feature | 198 |     14 |               210 | [+1, +10]       |
| pooled                              | v5 frozen           | nan |     21 |               nan | nan             |
| pooled                              | A two-tier          | nan |     33 |               nan | [+4, +22]       |
| pooled                              | B v5 + flag feature | nan |     33 |               nan | [+6, +19]       |