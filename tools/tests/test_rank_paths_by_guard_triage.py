"""Tests for tools/rank-paths-by-guard-triage.py (RANK-6 engine-harness-author
guard-triage ordering helper)."""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "rank-paths-by-guard-triage.py"
_spec = importlib.util.spec_from_file_location("rank_paths_by_guard_triage", _MOD_PATH)
rk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rk)


def _write_triage(ws: Path, units):
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "guard_triage.json").write_text(
        json.dumps({"schema": "x", "risk_units": units}), encoding="utf-8"
    )


def test_unit_file_strips_func_suffix():
    assert rk._unit_file("src/A.sol:deposit") == "src/A.sol"
    assert rk._unit_file("src/A.sol:294") == "src/A.sol"  # loc form
    assert rk._unit_file("src/A.sol") == "src/A.sol"


def test_high_risk_ranks_first(tmp_path):
    _write_triage(tmp_path, [
        {"unit": "src/Low.sol:f", "score": 1},
        {"unit": "src/High.sol:g", "score": 9},
    ])
    fr = rk.load_file_risk(tmp_path)
    out = rk.rank(["src/Low.sol", "src/High.sol"], fr, tmp_path)
    assert out == ["src/High.sol", "src/Low.sol"]


def test_unranked_go_last_alphabetical(tmp_path):
    _write_triage(tmp_path, [{"unit": "src/Risky.sol:f", "score": 5}])
    fr = rk.load_file_risk(tmp_path)
    out = rk.rank(["src/Zeta.sol", "src/Alpha.sol", "src/Risky.sol"], fr, tmp_path)
    # Risky (scored) first; the two unscored fall back to alphabetical
    assert out == ["src/Risky.sol", "src/Alpha.sol", "src/Zeta.sol"]


def test_max_score_per_file(tmp_path):
    _write_triage(tmp_path, [
        {"unit": "src/A.sol:f1", "score": 2},
        {"unit": "src/A.sol:f2", "score": 7},
        {"unit": "src/B.sol:g", "score": 4},
    ])
    fr = rk.load_file_risk(tmp_path)
    assert fr["src/A.sol"] == 7  # max wins
    out = rk.rank(["src/B.sol", "src/A.sol"], fr, tmp_path)
    assert out == ["src/A.sol", "src/B.sol"]


def test_dedup_preserves_then_sorts(tmp_path):
    fr = {}  # no triage -> sort -u fallback
    out = rk.rank(["z.sol", "a.sol", "z.sol", ""], fr, tmp_path)
    assert out == ["a.sol", "z.sol"]


def test_missing_triage_is_sort_u(tmp_path):
    fr = rk.load_file_risk(tmp_path)  # no file
    assert fr == {}
    out = rk.rank(["c.sol", "a.sol", "b.sol"], fr, tmp_path)
    assert out == ["a.sol", "b.sol", "c.sol"]


def test_corrupt_triage_fail_open(tmp_path):
    (tmp_path / ".auditooor").mkdir(parents=True)
    (tmp_path / ".auditooor" / "guard_triage.json").write_text("{not json", encoding="utf-8")
    assert rk.load_file_risk(tmp_path) == {}


def test_basename_fallback_match(tmp_path):
    # stdin path is absolute; triage stores ws-relative -> basename fallback
    _write_triage(tmp_path, [{"unit": "src/deep/Hot.sol:f", "score": 8}])
    fr = rk.load_file_risk(tmp_path)
    out = rk.rank(["/other/place/Hot.sol", "/other/place/Cold.sol"], fr, tmp_path)
    assert out[0].endswith("Hot.sol")
