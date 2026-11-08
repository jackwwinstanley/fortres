"""Without the competition data (data/ is not in the repo) the checkers and the rebuild steps print one clear line and
exit non-zero instead of a traceback."""
import subprocess
import sys

import pytest

from src.common import paths
from src.common.paths import REPO_ROOT

MSG = "(competition data, not in the repo)"


def test_require_data_exits_with_a_clear_message(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        paths.require_data(tmp_path / "vulnerabilities.csv")
    assert e.value.code == 2 and MSG in capsys.readouterr().err


def test_check_top500_says_it_needs_the_scoreboard(tmp_path):
    r = subprocess.run([sys.executable, "scripts/check_top500.py", "outputs/top500_v6.csv", "--scoreboard", str(tmp_path / "scoreboard_2026.csv")],
                       cwd=REPO_ROOT, capture_output=True, text=True)
    assert r.returncode != 0 and MSG in r.stderr and "scoreboard_2026.csv" in r.stderr and "Traceback" not in r.stderr


def test_check_contract_says_it_needs_the_scoreboard(tmp_path, capsys):
    import scripts.check_contract as cc
    assert cc.main(scoreboard=tmp_path / "scoreboard_2026.csv") == 1
    out = capsys.readouterr().out
    assert "FAIL top500_v6.csv" in out and MSG in out


@pytest.mark.parametrize("module", ["src.replicas", "src.features.build"])
def test_rebuild_steps_say_they_need_vulnerabilities_csv(module, tmp_path, capsys):
    import importlib
    m = importlib.import_module(module)
    with pytest.raises(SystemExit) as e:
        m.main(data_dir=tmp_path, out_dir=tmp_path / "out")
    assert e.value.code == 2 and "vulnerabilities.csv" in capsys.readouterr().err
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())


def test_train_v6_says_it_needs_vulnerabilities_csv(tmp_path, monkeypatch, capsys):
    from src.models import train_v6
    monkeypatch.setattr(train_v6, "DATA_DIR", tmp_path)
    with pytest.raises(SystemExit) as e:
        train_v6.main()
    assert e.value.code == 2 and "vulnerabilities.csv" in capsys.readouterr().err
