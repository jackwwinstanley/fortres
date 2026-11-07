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

CSV_SCHEMAS = {
    "emb_ids.csv": dict(cols=["cve_id"], unique_cve=True),
    "explanations.csv": dict(cols=["cve_id", "reason"], unique_cve=True),
    "runlog.csv": dict(cols=["timestamp", "version", "replica", "k", "hits",
                             "baseline_exploit_epss_hits", "notes"], unique_cve=False),
}

EMB_NPY, EMB_IDS = "emb_small.npy", "emb_ids.csv"
TOP500_PATTERN = "top500_v*.csv"
