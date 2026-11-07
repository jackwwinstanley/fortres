import pandas as pd

from scripts.check_top500 import check

ids = [f"CVE-2026-{i:05d}" for i in range(600)]


def sb(tmp_path):
    p = tmp_path / "sb.csv"
    pd.DataFrame({"cve_id": ids}).to_csv(p, index=False)
    return p


def write(tmp_path, rows, name="t.csv", col="cve_id", extra=False):
    df = pd.DataFrame({col: rows})
    if extra:
        df["score"] = 1
    p = tmp_path / name
    df.to_csv(p, index=False)
    return p


def test_valid(tmp_path):
    assert check(write(tmp_path, ids[:500]), sb(tmp_path)) == []


def test_499_rows(tmp_path):
    assert any("expected 500" in p for p in check(write(tmp_path, ids[:499]), sb(tmp_path)))


def test_duplicates(tmp_path):
    rows = ids[:499] + [ids[0]]
    assert any("duplicate" in p for p in check(write(tmp_path, rows), sb(tmp_path)))


def test_unknown_id(tmp_path):
    rows = ids[:499] + ["CVE-1999-9999"]
    assert any("not in scoreboard" in p for p in check(write(tmp_path, rows), sb(tmp_path)))


def test_extra_column(tmp_path):
    assert any("header" in p for p in check(write(tmp_path, ids[:500], extra=True), sb(tmp_path)))


def test_whitespace(tmp_path):
    rows = [" " + ids[0]] + ids[1:500]
    assert any("whitespace" in p for p in check(write(tmp_path, rows), sb(tmp_path)))
