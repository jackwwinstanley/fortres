"""refresh_all must work in a clean clone without --text: no import of the removed nearest_kev, a clear skip when the untracked
extraction cache is missing, and the leakage key put back into headline.json right after the leakage step."""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.b import error_analysis, export_story, refresh_all
from src.b.text_features import FLAGS


def test_export_story_no_longer_imports_nearest_kev_from_explain():
    src = Path(export_story.__file__).read_text()
    assert "from src.b.explain import cna_name\n" in src
    assert "from src.b.explain import cna_name, nearest_kev" not in src
    from src.b import explain
    assert not hasattr(explain, "nearest_kev")           # it is gone from explain.py, so nothing may import it


def test_headline_leakage_runs_right_after_the_leakage_step(monkeypatch):
    seen = []
    monkeypatch.setattr(refresh_all, "step", lambda name, args: seen.append((name, args)))
    refresh_all.main()
    names = [n for n, _ in seen]
    i = names.index("leakage + v5 blind spots")
    assert seen[i + 1] == ("leakage numbers into headline.json", ["-m", "src.b.headline_leakage"])
    assert seen[i][1] == ["-m", "src.b.leakage"]


def test_error_analysis_skips_clearly_and_writes_nothing_when_the_extraction_cache_is_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(error_analysis.st, "prepare", lambda *a, **k: pytest.fail("must not rebuild anything without the cache"))
    assert error_analysis.main(out_dir=tmp_path, data_dir=tmp_path) is None
    out = capsys.readouterr().out
    assert "SKIPPED error analysis" in out and "b_extract_cache.parquet" in out and "left unchanged" in out
    assert list(tmp_path.iterdir()) == []                # the committed outputs are untouched


def test_example_block_keeps_the_committed_values_and_says_so_when_inputs_are_absent(tmp_path, capsys):
    site = tmp_path / "site"
    site.mkdir()
    committed = {"cve": "CVE-2025-24472", "description": "committed text", "nearest": {"cve": "CVE-2023-1", "similarity": 0.9}}
    (site / "story.json").write_text(json.dumps({"example": committed, "other": 1}))
    block = export_story.example_block(None, None, out_dir=tmp_path / "outputs", data_dir=tmp_path, site_data=site)
    assert block == committed
    msg = capsys.readouterr().out
    assert "NOTE export_story" in msg and "emb_small.npy" in msg and "b_texts.parquet" in msg and "unchanged" in msg


def test_example_block_fails_clearly_when_inputs_are_absent_and_there_is_nothing_to_keep(tmp_path):
    with pytest.raises(SystemExit) as e:
        export_story.example_block(None, None, out_dir=tmp_path / "outputs", data_dir=tmp_path, site_data=tmp_path / "nosite")
    assert "refresh_all --text" in str(e.value)


def test_example_block_uses_the_embeddings_when_present(tmp_path):
    ex = export_story.EXAMPLE                                   # CVE-2025-24472: KEV entries added up to 2024-12-31 count
    out = tmp_path / "outputs"
    out.mkdir()
    ids = [ex, "CVE-2020-1", "CVE-2021-2", "CVE-2025-9"]
    emb = np.array([[1.0, 0.0, 0.0], [0.6, 0.8, 0.0], [0.9, 0.1, 0.0], [1.0, 0.0, 0.0]], dtype="float32")   # CVE-2025-9 is closest but added later
    np.save(out / "emb_small.npy", emb)
    pd.DataFrame({"cve_id": ids}).to_csv(out / "emb_ids.csv", index=False)
    pd.DataFrame({"cve_id": ids, "description": ["desc " + i for i in ids]}).to_parquet(out / "b_texts.parquet")
    pd.DataFrame({"cve_id": ["CVE-2020-1", "CVE-2021-2", "CVE-2025-9"], "vendor": ["A", "B", "C"], "product": ["pa", "pb", "pc"],
                  "name": ["na", "nb", "nc"], "date_added": ["2022-01-01", "2023-06-01", "2025-03-01"]}).to_csv(tmp_path / "known_exploited.csv", index=False)
    tf = pd.DataFrame({"kev_text_score": [0.9, 0.1, 0.5, 0.2], **{f: [1, 0, 0, 0] if f == list(FLAGS)[0] else [0, 0, 0, 0] for f in FLAGS}}, index=pd.Index(ids, name="cve_id"))
    block = export_story.example_block(tf, pd.Series(ids), out_dir=out, data_dir=tmp_path, site_data=tmp_path / "site")
    assert block["nearest"]["cve"] == "CVE-2021-2" and block["nearest"]["vendor"] == "B"      # best match under the cutoff, not CVE-2025-9
    assert block["nearest"]["similarity"] == pytest.approx(0.9, abs=1e-3)       # dot product of the (normalised) embeddings, as before
    assert block["description"] == "desc " + ex and block["kev_text_pct"] == pytest.approx(0.75) and block["cve"] == ex
