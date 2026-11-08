import json

import pandas as pd
import pytest

from src.b import headline_leakage as hl


def _results(tmp_path, drop=None):
    rows = [(d, m, h) for d, honest, leaky in (("train2024_test2025", 12, 17), ("train2025_test2024", 9, 11))
            for m, h in (("CVSS 3 first", 1), ("honest", honest), ("leaky", leaky))]
    df = pd.DataFrame(rows, columns=["direction", "model", "hits"])
    if drop is not None:
        df = df[~((df["direction"] == drop[0]) & (df["model"] == drop[1]))]
    from src.common import primary
    p = primary.file("leakage", out_dir=tmp_path)   # the primary model's leakage file name
    df.to_csv(p, index=False)
    return p


def test_summary_reads_hits_per_direction_and_pools_them(tmp_path):
    s = hl.leakage_summary(_results(tmp_path))
    assert s["honest"] == {"pooled_hits": 21, "forward_train2024_test2025": 12, "stability_train2025_test2024": 9}
    assert s["leaky"] == {"pooled_hits": 28, "forward_train2024_test2025": 17, "stability_train2025_test2024": 11}


def test_summary_refuses_a_missing_or_duplicated_row(tmp_path):
    with pytest.raises(ValueError):
        hl.leakage_summary(_results(tmp_path, drop=("train2025_test2024", "leaky")))


def test_update_headline_adds_one_key_before_note_and_is_repeatable(tmp_path):
    _results(tmp_path)
    before = {"primary": "v5", "pooled_hits_bag": 21, "positives": {"2024": 27}, "note": "LOW POWER"}
    (tmp_path / "headline.json").write_text(json.dumps(before, indent=1))
    hl.update_headline(tmp_path)
    once = (tmp_path / "headline.json").read_text()
    hl.update_headline(tmp_path)
    assert (tmp_path / "headline.json").read_text() == once
    after = json.loads(once)
    assert list(after) == ["primary", "pooled_hits_bag", "positives", "leakage", "note"]
    assert {k: v for k, v in after.items() if k != "leakage"} == before
