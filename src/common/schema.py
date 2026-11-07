"""Expected columns/dtypes for every contract file (see CONTRACT.md).

dtype codes: "str", "date", "float", "int" (any integer), "int8" (0/1 flags and labels).
`nullable` lists columns allowed to contain nulls; all others must be non-null.
"""

REPLICA_COLS = {
    "cve_id": "str",
    "published": "date",
    "snapshot_month": "str",
    "epss": "float",
    "exploitdb": "int8",
    "metasploit": "int8",
    "nuclei": "int8",
    "poc_github": "int8",
    "days_to_snapshot": "int",
    "days_to_cutoff": "int",
    "label": "int8",
}
FEATURE_COLS = {k: v for k, v in REPLICA_COLS.items() if k != "label"}

SCHEMAS = {
    "replica_2024.parquet": dict(
        cols=REPLICA_COLS, nullable={"epss"}, unique_cve=False, binary=["exploitdb", "metasploit", "nuclei", "poc_github", "label"]),
    "replica_2025.parquet": dict(
        cols=REPLICA_COLS, nullable={"epss"}, unique_cve=False, binary=["exploitdb", "metasploit", "nuclei", "poc_github", "label"]),
    "scoreboard_features.parquet": dict(
        cols=FEATURE_COLS, nullable={"epss"}, unique_cve=True, n_rows=72670, binary=["exploitdb", "metasploit", "nuclei", "poc_github"]),
    "text_features.parquet": dict(
        cols={"cve_id": "str", "kev_text_score": "float", "nearest_kev_sim": "float"},
        nullable=set(), unique_cve=True, prefix_int8="txt_"),
    "extracted_features.parquet": dict(
        cols={"cve_id": "str", "product_type": "str", "auth_required": "str",
              "network_reachable": "str", "impact_type": "str"},
        nullable={"product_type", "auth_required", "network_reachable", "impact_type"}, unique_cve=True),
}

_FEATURE_DTYPES = {
    "epss": "float", "epss_missing": "int8", "epss_rank_in_month": "float",
    "exploitdb": "int8", "metasploit": "int8", "nuclei": "int8", "poc_github": "int8",
    "n_flags": "int8", "any_exploit": "int8", "days_to_snapshot": "int", "days_to_cutoff": "int",
    "assigner_prior_cves": "float", "assigner_kev_count": "float", "assigner_kev_12m": "float",
    "assigner_kev_rate_smooth": "float", "n_vendors_mentioned": "int",
    "vendor_kev_count_max": "float", "vendor_kev_12m_max": "float",
    "assigner_cve_share": "float", "assigner_kev_share": "float", "assigner_kev_12m_share": "float",
    "vendor_kev_share_max": "float", "vendor_kev_12m_share_max": "float",
}
_FEAT_BASE = {"cve_id": "str", "snapshot_month": "str", "published": "date"}
_BIN = ["epss_missing", "exploitdb", "metasploit", "nuclei", "poc_github", "any_exploit"]
SCHEMAS.update({
    "features_replica_2024.parquet": dict(cols={**_FEAT_BASE, "label": "int8", **_FEATURE_DTYPES},
                                          nullable={"epss"}, unique_cve=False, binary=_BIN + ["label"]),
    "features_replica_2025.parquet": dict(cols={**_FEAT_BASE, "label": "int8", **_FEATURE_DTYPES},
                                          nullable={"epss"}, unique_cve=False, binary=_BIN + ["label"]),
    "features_scoreboard.parquet": dict(cols={**_FEAT_BASE, **_FEATURE_DTYPES}, nullable={"epss"},
                                        unique_cve=True, n_rows=72670, binary=_BIN),
})

CSV_SCHEMAS = {
    "emb_ids.csv": dict(cols=["cve_id"], unique_cve=True),
    "explanations.csv": dict(cols=["cve_id", "reason"], unique_cve=True),
    "runlog.csv": dict(cols=["timestamp", "version", "replica", "k", "hits",
                             "baseline_exploit_epss_hits", "notes"], unique_cve=False),
}

EMB_NPY, EMB_IDS = "emb_small.npy", "emb_ids.csv"
TOP500_PATTERN = "top500_v*.csv"


# ---- v1 model feature contract -------------------------------------------------------------
import re  # noqa: E402

FEATURE_GROUPS = {
    "signals": ["epss", "epss_missing", "epss_rank_in_month"],
    "flags": ["exploitdb", "metasploit", "nuclei", "poc_github", "n_flags", "any_exploit"],
    "timing": ["days_to_snapshot", "days_to_cutoff"],
    "assigner": ["assigner_prior_cves", "assigner_kev_count", "assigner_kev_12m", "assigner_kev_rate_smooth"],
    "vendor": ["n_vendors_mentioned", "vendor_kev_count_max", "vendor_kev_12m_max"],
}
V1_FEATURES = [c for cols in FEATURE_GROUPS.values() for c in cols]
# v2 adds Person B's text features (outputs/text_features.parquet). Their KEV-based parts use the same
# prior-December-31 cutoff (CONTRACT.md), and the text classifier trains only on CVEs published before the pool year.
TEXT_FEATURES = ["kev_text_score", "nearest_kev_sim",
                 "txt_rce", "txt_unauth", "txt_auth_bypass", "txt_cmd_injection", "txt_deserialization",
                 "txt_path_traversal", "txt_sqli", "txt_priv_esc", "txt_memory", "txt_edge_device",
                 "txt_enterprise", "txt_browser", "txt_wordpress", "txt_xss"]
FEATURE_GROUPS_V2 = {**FEATURE_GROUPS, "text": TEXT_FEATURES}
# scale-free candidates added at step 3e (built by src/features/build.py; shares of everything known by the history cutoff)
SHARE_FEATURES = ["assigner_cve_share", "assigner_kev_share", "assigner_kev_12m_share", "vendor_kev_share_max", "vendor_kev_12m_share_max"]
V2_FEATURES = V1_FEATURES + TEXT_FEATURES  # legacy v2 set (includes raw epss), kept so v2/v3 stay reproducible

# ---- v4: drift-robust feature set (step 3d) -------------------------------------------------
# Decision on drift evidence (outputs/v4_report.md): raw epss moved ~4x in 2026 (PSI 2.87 pooled replicas vs scoreboard), so it
# is removed; epss_rank_in_month and epss_missing stay. Every scale-type feature with PSI > 0.25 is replaced by its within-pool
# percentile rank (computed per replica / per scoreboard). src/features/drift_fix.py recomputes the PSI table and
# tests/test_drift_fix.py asserts it still yields exactly this list.
RAW_REMOVED = ["epss"]
PSI_REPLACED = ["days_to_cutoff", "assigner_prior_cves", "assigner_kev_count", "assigner_kev_12m",
                "assigner_kev_rate_smooth"]


def _rank_name(f: str) -> str:
    return f + "_pctrank"


V4_FEATURES = [_rank_name(f) if f in PSI_REPLACED else f for f in V2_FEATURES if f not in RAW_REMOVED]  # legacy (step 3d)

# ---- v5 (step 3e): the LAST feature-set change. For each scale-sensitive feature the transformation (raw / within-pool percentile
# rank / scale-free share) with the lowest PSI between the pooled replicas and the 2026 scoreboard was chosen, ties to raw, never by
# hits. src/features/drift_fix.py recomputes the choice; tests/test_drift_fix.py asserts it still matches this record.
V5_TRANSFORMS = {
    "days_to_cutoff": "days_to_cutoff",                       # raw (PSI 1.03; its rank is 2.33)
    "assigner_prior_cves": "assigner_prior_cves_pctrank",     # rank (0.86 vs raw 1.89 vs share 2.34)
    "assigner_kev_count": "assigner_kev_share",               # share (0.66 vs raw 1.17 vs rank 2.66)
    "assigner_kev_12m": "assigner_kev_12m_share",             # share (0.39 vs raw 0.78 vs rank 2.77)
    "assigner_kev_rate_smooth": "assigner_kev_rate_smooth_pctrank",  # rank (0.45 vs raw 0.74)
    "vendor_kev_count_max": "vendor_kev_count_max",           # raw (0.09)
    "vendor_kev_12m_max": "vendor_kev_12m_max",               # raw (0.23)
}
V5_FEATURES = [V5_TRANSFORMS.get(f, f) for f in V2_FEATURES if f not in RAW_REMOVED]
ALLOWED_FEATURES = V5_FEATURES  # what a model may use from now on; V1/V2/V4 lists stay for reproducing old results
# the only allowed column names that contain "kev": history features computed with the fixed
# prior-December-31 cutoff (see CONTRACT.md)
HISTORY_KEV_FEATURES = {"assigner_kev_count", "assigner_kev_12m", "assigner_kev_rate_smooth",
                        "vendor_kev_count_max", "vendor_kev_12m_max",
                        "kev_text_score", "nearest_kev_sim",
                        "assigner_kev_count_pctrank", "assigner_kev_12m_pctrank", "assigner_kev_rate_smooth_pctrank",
                        "assigner_kev_share", "assigner_kev_12m_share", "vendor_kev_share_max", "vendor_kev_12m_share_max"}
BANNED_NAMES = [r"nvd_status", r"n_affected_cpes", r"n_references", r"cvss", r"cwe",
                r"affected", r"reference", r"kev", r"description", r"last_modified"]
MONOTONE_UP = ["epss", "epss_rank_in_month", "exploitdb", "metasploit", "nuclei", "poc_github",
               "n_flags", "any_exploit"]


def is_banned(name: str) -> bool:
    """True if a feature name matches a banned pattern (allowed KEV-history features excepted)."""
    if name in HISTORY_KEV_FEATURES:
        return False
    return any(re.search(p, name.lower()) for p in BANNED_NAMES)


def check_feature_list(features, allowed=None) -> list[str]:
    """Return problems with a model's feature list (empty = OK). `allowed` defaults to ALLOWED_FEATURES (the v4 set);
    pass V2_FEATURES to check the legacy v1/v2 lists."""
    allowed = ALLOWED_FEATURES if allowed is None else allowed
    probs = [f"not in the allowed list: {f}" for f in features if f not in allowed]
    probs += [f"banned name: {f}" for f in features if is_banned(f)]
    return probs
