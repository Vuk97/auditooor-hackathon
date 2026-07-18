"""Regression: dataflow.py surfaces a LOUD silent-0 guard. An arm whose language
IS present but produced 0 records is almost always a compile/deps failure (e.g.
Solidity foundry roots whose deps are unresolved -> slither-compile fails -> 0
paths), NOT a genuine empty slice. Morpho Cantina 2026-06-26: step-1c produced 0
because deps were unresolved until step-2; the SAME command produced 475 once
forge-deps-checker --fix had run. The guard must flag present-but-zero arms."""
import importlib.util
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "dataflow.py"
_spec = importlib.util.spec_from_file_location("dataflow_router", _MOD)
df = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(df)


def test_present_but_zero_is_flagged():
    present = {"solidity": True, "rust": False, "go": False, "zk": False}
    out = df._zero_record_present_arms(present, {"solidity": 0}, ["solidity"])
    assert out == ["solidity"]


def test_present_with_records_not_flagged():
    present = {"solidity": True}
    out = df._zero_record_present_arms(present, {"solidity": 475}, ["solidity"])
    assert out == []


def test_absent_language_never_flagged():
    # solidity NOT present -> 0 records is expected, not a failure
    present = {"solidity": False, "go": True}
    out = df._zero_record_present_arms(present, {"go": 12}, ["go"])
    assert out == []


def test_missing_count_treated_as_zero():
    present = {"solidity": True}
    # records_by_language has no 'solidity' key at all -> treated as 0 -> flagged
    out = df._zero_record_present_arms(present, {}, ["solidity"])
    assert out == ["solidity"]


def test_mixed_only_zero_present_arms_flagged():
    present = {"solidity": True, "rust": True}
    out = df._zero_record_present_arms(
        present, {"solidity": 0, "rust": 30}, ["solidity", "rust"]
    )
    assert out == ["solidity"]
