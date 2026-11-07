"""Create the team task board (labels, milestones, issues) with the gh CLI. Safe to re-run:
anything that already exists (same label name / milestone title / issue title) is skipped.

Usage:  python scripts/create_board.py [--dry-run]

The repo is PUBLIC: never put secrets, tokens, personal data or raw dataset rows in issue text.
"""
import argparse
import json
import subprocess
import sys

REPO = "jackwwinstanley/ibm-breach"
ME, MATE = "jackwwinstanley", "yahyahashme"

LABELS = {  # name -> (color, description)
    "A-model": ("1d76db", "Person A: replicas, features, model"),
    "B-granite": ("8250df", "Person B: Granite, text features, dashboard"),
    "shared": ("8b949e", "Both people"),
    "stretch": ("fbca04", "Drop if it threatens the freeze"),
    "blocker": ("d73a4a", "Blocks other work"),
    "submission": ("0e8a16", "Needed for the Devpost submission"),
}
MILESTONES = {  # title -> due_on (UTC; Toronto is UTC-5 on these dates)
    "Sat 8PM Devpost draft": "2026-11-08T01:00:00Z",
    "Feature freeze 12:30AM": "2026-11-08T05:30:00Z",
    "Model freeze 3AM": "2026-11-08T08:00:00Z",
    "Submit by 11AM": "2026-11-08T16:00:00Z",
}
M_DRAFT, M_FEAT, M_MODEL, M_SUBMIT = MILESTONES

BANNED = ("nvd_status, n_affected_cpes, n_references, blank-vs-filled severity scores, "
          "cvss3_source == nvd@nist.gov scores, references.csv links, NIST-filled cwe_ids and "
          "affected_products for new CVEs, anything from KEV added after the snapshot, any 2026 KEV info")


def issue(title, owner, labels, goal, outputs, done, inputs="see Goal", notes="", milestone=None,
          close=None):
    win = title[1:title.index("]")]
    return dict(title=title, owner=owner, labels=labels, milestone=milestone, close=close,
                body="\n".join([
                    f"**Goal:** {goal}", "",
                    f"**Owner:** {owner}", f"**Target window (Toronto):** {win}", "",
                    f"**Inputs:** {inputs}", f"**Outputs:** {outputs}", "",
                    "**Done when:**", *[f"- [ ] {d}" for d in done], "",
                    f"**Notes:** {notes or 'Follow CONTRACT.md. Do not commit data/ or large files.'}"]))


ISSUES = [
    # ---- yahyahashme ----
    issue("[Sat 3:15-3:45] Confirm Devpost draft and tracks", MATE, ["B-granite", "submission"],
          "Make sure the Devpost project exists with the IBM track selected and both members listed.",
          "Devpost draft (no repo files)",
          ["Draft exists and IBM track is selected", "Both team members are listed",
           "watsonx.ai free trial signup started; note in a comment whether it works"],
          milestone=M_DRAFT),
    issue("[Sat 3:15-3:45] Environment setup", MATE, ["B-granite"],
          "Get a working local environment on branch b/granite.", "Green checks printed in a comment",
          ["Clone repo and `git checkout b/granite`", "Create venv and `pip install -r requirements.txt`",
           "`pytest -q` passes", "`python scripts/check_contract.py` runs without error"]),
    issue("[Sat 3:45-5:15] Export text for embedding", MATE, ["B-granite"],
          "Export descriptions to embed (all KEV CVEs, Jan-Sep 2024 and Jan-Sep 2025 publications, "
          "all 72,670 scoreboard CVEs, plus ~40,000 random older CVEs: published before 2024, not in KEV, fixed seed).",
          "outputs/embed_input.csv (untracked): cve_id, description",
          ["File has unique cve_id rows covering all groups above", "Random sample uses a fixed seed (documented)"],
          inputs="data/vulnerabilities.csv, data/known_exploited.csv, data/scoreboard_2026.csv",
          notes="Depends only on cve_id lists, not on replica files. Never commit this file."),
    issue("[Sat 3:45-5:15] Embedding speed test and run", MATE, ["B-granite"],
          "Embed all descriptions with granite-embedding-small-english-r2 (sentence-transformers).",
          "outputs/emb_small_part{N}.npy (chunks of 50,000) merged to outputs/emb_small.npy + outputs/emb_ids.csv",
          ["Time 1,000 descriptions and decide laptop vs Colab (Colab files are temporary: download each chunk immediately)",
           "Chunks merged; row i of the matrix matches row i of emb_ids.csv", "`python scripts/check_contract.py` passes the embedding rule"],
          inputs="outputs/embed_input.csv", notes="Embeddings are gitignored; share via the shared drive."),
    issue("[Sat 5:15-7:30] KEV-likeness text classifier", MATE, ["B-granite"],
          "Logistic regression on embeddings, trained ONLY on CVEs published before 2024 "
          "(positives: in KEV before 2024 by date_added; negatives: the older sample).",
          "outputs/text_features.parquet: cve_id, kev_text_score, nearest_kev_sim",
          ["Every CVE scored", "nearest_kev_sim = max cosine similarity to KEV CVEs added strictly before the CVE's snapshot month end",
           "Comment here explaining how time-safety is guaranteed", "`python scripts/check_contract.py` passes"],
          inputs="outputs/emb_small.npy, outputs/emb_ids.csv, data/known_exploited.csv",
          notes="Training data uses only pre-2024 info, so no replica label can leak into the text score."),
    issue("[Sat 5:15-7:30] Text-pattern flags", MATE, ["B-granite"],
          "Add int8 txt_ flag columns to text_features.parquet from the description text.",
          "outputs/text_features.parquet (txt_* columns)",
          ["Positive hints: unauthenticated, remote code execution, authentication bypass, command injection, path traversal, deserialization, appliance/VPN/gateway/firewall",
           "Negative hints: cross-site scripting, denial of service, WordPress plugin",
           "Comment lists how many CVEs hit each flag"]),
    issue("[Sat 5:15-7:30] Entire setup", MATE, ["B-granite", "stretch"],
          "30-minute time-box. Try Entire for session capture.", "Screenshot for the write-up",
          ["FIRST check what session data Entire would publish (repo is PUBLIC) and make sure no secrets are pasted into sessions",
           "Install the CLI, enable it, run `entire brain setup`",
           "Record 2-3 project rules: never use banned columns; replicas are the benchmark; freeze times"],
          notes="Drop it if it takes over 30 minutes."),
    issue("[Sat 7:30-9:00] Leakage experiment", MATE, ["B-granite"],
          "Copy A's v1 setup and train it WITH banned columns vs the honest model on both replicas.",
          "outputs/leakage_results.csv + figure in docs/figures/",
          ["Banned set includes nvd_status, n_affected_cpes, n_references, blank-CVSS indicators, reference-link features",
           "Results on both replicas, with bootstrap ranges", "Clearly labelled as a leakage experiment, never submitted"],
          inputs="A's v1 feature code (coordinate in comments on the Features v1 issue)",
          milestone=M_FEAT),
    issue("[Sat 7:30-9:00] Drift check", MATE, ["B-granite"],
          "Train a classifier to tell 2025 pool rows from 2026 scoreboard rows using allowed columns only.",
          "figure in docs/figures/ + a paragraph for the write-up",
          ["Report AUC", "List the top differing features"],
          inputs="outputs/replica_2025.parquet, outputs/scoreboard_features.parquet", milestone=M_FEAT),
    issue("[Sat 9:00-10:00] Streamlit skeleton", MATE, ["B-granite"],
          "Dashboard that runs on v0 data now.", "app/dashboard.py on b/granite",
          ["Loads outputs/top500_v0.csv and outputs/runlog.csv", "Headline bar", "Ranked table with a reason column",
           "Baseline comparison chart", "`streamlit run app/dashboard.py` works"],
          notes="Swap in final data later without changing the layout."),
    issue("[Sat 9:00-10:00] Independent review of allowed vs banned columns", MATE, ["shared"],
          "Second pair of eyes on the column lists.", "A comment on this issue with findings",
          ["Compare the ALLOWED/BANNED lists in CONTRACT.md against docs/DATA_DICTIONARY.md",
           "Comment anything missing or wrongly allowed"], milestone=M_FEAT),
    issue("[Sat 10:00-12:30] Granite fact extraction", MATE, ["B-granite", "stretch"],
          "Use a Granite instruct model (watsonx.ai or local) to return constrained JSON per CVE: "
          "product_type, auth_required, network_reachable, impact_type. Top ~3,000 CVEs per pool.",
          "outputs/extracted_features.parquet",
          ["Same prompt and settings for train and score", "`python scripts/check_contract.py` passes", "Dropped if not done by the freeze"],
          milestone=M_FEAT, notes="Drop if not done by the feature freeze."),
    issue("[Sun 12:30-2:00] Granite explanations", MATE, ["B-granite"],
          "One sentence per final top-500 CVE using ONLY facts supplied by our pipeline "
          "(vendor, weakness hints, EPSS, exploit flags, nearest KEV match).",
          "outputs/explanations.csv: cve_id, reason",
          ["500 rows, unique cve_id", "A check shows explanations introduce no product or number not in the input facts"],
          inputs="outputs/top500_final.csv and the feature tables"),
    issue("[Sun 12:30-2:00] Charts in one consistent style", MATE, ["B-granite"],
          "One consistent style for the write-up and the Best Data Visualization entry.", "PNGs in docs/figures/",
          ["Baselines vs ours with ranges", "Leakage inflation", "Positive rate by month vs days left (outputs/positive_rate_by_month.csv)", "Drift"]),
    issue("[Sun 4:30-7:30] Finish dashboard and video script", MATE, ["B-granite", "submission"],
          "Final data in the dashboard and a storyboard for the video.", "app/dashboard.py + video script",
          ["Every headline number verified against outputs/runlog.csv", "2-minute video script/storyboard written"],
          milestone=M_SUBMIT),
    # ---- me ----
    issue("[Sat 3:15-3:45] Skeleton, CONTRACT.md and branches", ME, ["A-model"],
          "Repo skeleton, CONTRACT.md, branches main / a/model / b/granite.", "CONTRACT.md, src/common/, scripts/, tests/",
          ["Skeleton committed", "Branches exist"], close="Done in commit 477990b (skeleton) and 2bec987 (parquet tracking)."),
    issue("[Sat 3:45-5:15] Replicas, scorer, baselines, v0 top 500", ME, ["A-model"],
          "Two benchmark replicas, shared scorer, three baselines, v0 top 500.",
          "outputs/replica_2024.parquet, outputs/replica_2025.parquet, outputs/scoreboard_features.parquet, outputs/top500_v0.csv, outputs/runlog.csv",
          ["`python -m src.replicas` and `python -m src.baselines` run", "pytest passes",
           "outputs/top500_v0.csv passes scripts/check_top500.py"],
          close="All outputs committed on a/model in commit 18fc885; pytest and check_top500 pass."),
    issue("[Sat 5:15-7:30] Features v1 + LightGBM", ME, ["A-model"],
          "Allowed columns only: EPSS rank within month, assigner/vendor history from KEV entries before each snapshot, days_to_snapshot, days_to_cutoff.",
          "model code in src/, runlog.csv rows",
          ["Beats all three baselines on BOTH replicas (train 2024/test 2025 and the reverse)", "Bootstrap ranges reported"],
          inputs="outputs/replica_*.parquet, outputs/scoreboard_features.parquet"),
    issue("[Sat 7:30-9:00] Integrate Granite text features (v2)", ME, ["A-model"],
          "Join outputs/text_features.parquet into the model.", "runlog.csv rows with and without Granite features",
          ["With/without comparison on both replicas", "A feature is kept only if it helps on both"],
          inputs="outputs/text_features.parquet (from the Granite issues)"),
    issue("[Sat 9:00-10:00] Lock the honest feature set", ME, ["A-model"],
          "Freeze the final column list.", "Column list in README.md",
          ["Final list written in README.md", "Mentor/IBM staff asked to sanity-check allowed vs banned columns"], milestone=M_FEAT),
    issue("[Sat 10:00-12:30] Robustness checks", ME, ["A-model"],
          "Check the result is not luck.", "figures/tables for the write-up",
          ["Bootstrap intervals", "Per-month results", "Rank-averaged ensemble", "Late-month 'exploited in the wild' wording confirmed to exist at publish time"],
          milestone=M_FEAT),
    issue("[Sun 12:30-3:00] Final model and top 500", ME, ["A-model"],
          "Produce the submission file.", "outputs/top500_final.csv, git tag final-model",
          ["Passes scripts/check_top500.py", "Repo tagged `final-model`", "Numbers reproduced from a clean clone"],
          milestone=M_MODEL),
    issue("[Sun 4:30-7:30] README and write-up", ME, ["A-model", "submission"],
          "Write-up for Devpost.", "README.md and write-up text",
          ["Question and method", "Every column used and why", "Leakage handling", "Limits"], milestone=M_SUBMIT),
    # ---- both ----
    issue("[Pinned] Team rules", f"{ME} and {MATE}", ["shared"],
          "Working agreement for the team.", "none",
          ["One owner per file", "Branches a/model and b/granite; merge to main only when pytest and check_contract pass",
           "Pull hourly", "No new features after Sun 12:30AM; model freeze Sun 3AM", "Both sleep Sun 3:00-4:30; submit by Sun 11AM (deadline is noon)",
           "Scoring rule: k = round(500 * pool / 72670); ties broken by cve_id",
           f"Banned columns (leakage experiment only): `{BANNED}`"]),
    issue("[Sun 7:30-11:00] Video and submission", f"{ME} and {MATE}", ["shared", "submission"],
          "Record the video and submit.", "Devpost submission",
          ["Record the 2-minute video (A: model and results; B: demo)", "Public YouTube/Drive link",
           "Git history audit: `git ls-files | grep -E '^data/|\\.csv$'` and `git log --all --stat | grep data/` show no data files (repo is already public)",
           "Every Devpost field filled", "Both members listed and tracks selected", "Submission page verified"],
          milestone=M_SUBMIT),
]
ASSIGNEES = {ME: [ME], MATE: [MATE], f"{ME} and {MATE}": [ME, MATE]}


def gh(*args, input=None, check=True):
    r = subprocess.run(["gh", *args], capture_output=True, text=True, input=input)
    if check and r.returncode:
        raise RuntimeError(r.stderr.strip() or r.stdout.strip())
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    dry = ap.parse_args().dry_run
    report = {"created": [], "skipped": [], "failed": []}

    labels = {l["name"] for l in json.loads(gh("label", "list", "--repo", REPO, "--limit", "200", "--json", "name"))}
    for name, (color, desc) in LABELS.items():
        if name in labels:
            report["skipped"].append(f"label {name}")
        elif not dry:
            gh("label", "create", name, "--repo", REPO, "--color", color, "--description", desc)
            report["created"].append(f"label {name}")

    ms = {m["title"] for m in json.loads(gh("api", f"repos/{REPO}/milestones?state=all&per_page=100"))}
    for title, due in MILESTONES.items():
        if title in ms:
            report["skipped"].append(f"milestone {title}")
        elif not dry:
            gh("api", f"repos/{REPO}/milestones", "-f", f"title={title}", "-f", f"due_on={due}")
            report["created"].append(f"milestone {title}")

    existing = {i["title"]: i for i in json.loads(gh(
        "issue", "list", "--repo", REPO, "--state", "all", "--limit", "500", "--json", "number,title,state"))}
    for it in ISSUES:
        try:
            if it["title"] in existing:
                report["skipped"].append(f"issue {it['title']}")
                continue
            if dry:
                continue
            cmd = ["issue", "create", "--repo", REPO, "--title", it["title"], "--body-file", "-"]
            for l in it["labels"]:
                cmd += ["--label", l]
            for a in ASSIGNEES[it["owner"]]:
                cmd += ["--assignee", a]
            if it["milestone"]:
                cmd += ["--milestone", it["milestone"]]
            url = gh(*cmd, input=it["body"]).strip()
            report["created"].append(f"issue {url}")
            if it["close"]:
                gh("issue", "close", url, "--reason", "completed", "--comment", it["close"])
            if it["title"] == "[Pinned] Team rules":
                gh("issue", "pin", url, check=False)
        except RuntimeError as e:
            report["failed"].append(f"{it['title']}: {e}")
    print(json.dumps(report, indent=1))
    sys.exit(1 if report["failed"] else 0)


if __name__ == "__main__":
    main()
