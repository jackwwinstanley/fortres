"""The "Rank a dataset" page: saved models reproduce the submitted list byte for byte, slices rank consistently, uploads fail with clear messages."""
import io
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.b import score as sc
from src.common.paths import OUT_DIR, REPO_ROOT

need = pytest.mark.skipif(not (sc.MODELS / "manifest.json").exists(), reason="saved models not present (python scripts/save_v6_models.py)")


@pytest.fixture(scope="module")
def S():
    return sc.Scorer()


@need
def test_saved_models_reproduce_top500_byte_for_byte(S, tmp_path):
    p = tmp_path / "top.csv"
    pd.DataFrame({"cve_id": S.top_ids(500)}).to_csv(p, index=False)
    assert p.read_bytes() == (OUT_DIR / "top500_v6.csv").read_bytes()


@need
def test_scoring_the_whole_scoreboard_through_the_upload_path_gives_the_same_order(S):
    res = S.score(pd.DataFrame({"cve_id": S.ids}))
    assert res["cve_id"].head(500).tolist() == (OUT_DIR / "top500_v6.csv").read_text().split()[1:]
    assert (res["rank_all_2026"].to_numpy() == res["rank_in_upload"].to_numpy()).all()


@need
def test_a_one_month_slice_keeps_the_full_ranking_order(S):
    ids = S.sb.loc[S.sb["snapshot_month"] == "2026-05", "cve_id"]
    res = S.score(pd.DataFrame({"cve_id": ids.to_numpy()}))
    assert res["rank_all_2026"].is_monotonic_increasing


@pytest.mark.parametrize("raw,needle", [
    (b"hello,world\n1,2\n", "no cve_id column"),
    (b"cve_id\nnot-a-cve\n", "look like a CVE id"),
    (b"\x00\x01\x02binary", "could not be read"),
    (b"cve_id\n", "no rows"),
])
def test_malformed_files_get_a_clear_message(raw, needle):
    with pytest.raises(sc.UploadError) as e:
        sc.read_upload(io.BytesIO(raw), set())
    assert needle in str(e.value)


def test_too_many_rows_are_refused():
    raw = "cve_id\n" + "\n".join(f"CVE-2026-{i:05d}" for i in range(sc.MAX_ROWS + 1))
    with pytest.raises(sc.UploadError, match="limit"):
        sc.read_upload(io.BytesIO(raw.encode()), None)


@need
def test_rows_outside_the_scoreboard_list_what_is_missing_then_score_without_crashing(S):
    with pytest.raises(sc.UploadError, match="EPSS score"):
        sc.read_upload(io.BytesIO(b"cve_id\nCVE-2026-9999999\n"), set(S.ids))
    raw = b"cve_id,published,snapshot_month,epss,exploitdb,metasploit,nuclei,poc_github\nCVE-2026-9999999,2026-05-03,2026-05,0.42,0,0,1,1\n"
    df = sc.read_upload(io.BytesIO(raw), set(S.ids))
    res = S.score(df)
    assert len(res) == 1 and not res["in_scoreboard"].iloc[0] and 0 < res["score"].iloc[0] <= 1 and res["rank_all_2026"].iloc[0] >= 1


@need
def test_reason_badges_match_explanations_csv(S):
    import importlib.util
    spec = importlib.util.spec_from_file_location("rank_page", REPO_ROOT / "app" / "rank_page.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    exp = pd.read_csv(OUT_DIR / "explanations.csv").set_index("cve_id")
    facts = pd.DataFrame()
    for cve in S.top_ids(500)[:40]:
        reason, label = m.label_and_reason(cve, True, True, facts, exp)
        assert reason == exp.loc[cve, "explanation"]
        assert label == ("Checked by Granite Guardian" if exp.loc[cve, "guardian_verdict"] == "No" else "Template reason")


def test_no_banned_words_on_the_page():
    text = (REPO_ROOT / "app" / "rank_page.py").read_text().lower()
    for bad in ("predicts", "detects", "proves", "real-time"):
        assert bad not in text


def test_score_module_reads_no_banned_column():
    src = (REPO_ROOT / "src" / "b" / "score.py").read_text()
    for bad in ("nvd_status", "n_affected_cpes", "n_references", "cvss", "references.csv", "affected_products"):
        assert bad not in src
    assert np.isfinite(sc.MAX_ROWS)


def test_make_app_samples_writes_the_two_files(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("make_app_samples", REPO_ROOT / "scripts" / "make_app_samples.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    sb = pd.DataFrame({"cve_id": [f"CVE-2026-{i:05d}" for i in range(3000)], "snapshot_month": ["2026-05"] * 100 + ["2026-07"] * 2900, "epss": 0.1})
    src = tmp_path / "scoreboard.csv"; sb.to_csv(src, index=False)
    assert m.main(src, tmp_path / "samples") == 0
    assert len(pd.read_csv(tmp_path / "samples" / m.ONE_MONTH)) == 100
    a = (tmp_path / "samples" / m.RANDOM).read_bytes()
    assert len(pd.read_csv(tmp_path / "samples" / m.RANDOM)) == 2000
    assert m.main(src, tmp_path / "samples") == 0 and (tmp_path / "samples" / m.RANDOM).read_bytes() == a      # fixed seed
    assert m.main(tmp_path / "absent.csv", tmp_path / "x") == 2


def test_the_page_says_how_to_make_a_missing_sample():
    text = (REPO_ROOT / "app" / "rank_page.py").read_text()
    assert "run python scripts/make_app_samples.py first" in text
