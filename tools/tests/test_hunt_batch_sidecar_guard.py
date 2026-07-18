"""Tests for hunt-batch-sidecar-guard.py - sidecar count guard."""

import json
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

# The tool lives at tools/hunt-batch-sidecar-guard.py (hyphenated name).
# importlib handles hyphens via spec_from_file_location.
import importlib.util

_TOOL_PATH = Path(__file__).parent.parent / "hunt-batch-sidecar-guard.py"


def _load_guard_module():
    spec = importlib.util.spec_from_file_location(
        "hunt_batch_sidecar_guard", _TOOL_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


guard_mod = _load_guard_module()
count_sidecars = guard_mod.count_sidecars
run = guard_mod.run
build_parser = guard_mod.build_parser


# ---------------------------------------------------------------------------
# count_sidecars helper
# ---------------------------------------------------------------------------


def test_count_sidecars_empty_dir(tmp_path):
    assert count_sidecars(tmp_path) == 0


def test_count_sidecars_counts_json_files(tmp_path):
    for i in range(3):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    assert count_sidecars(tmp_path) == 3


def test_count_sidecars_excludes_manifest(tmp_path):
    (tmp_path / "manifest.json").write_text("{}")
    (tmp_path / "task_0001.json").write_text("{}")
    assert count_sidecars(tmp_path) == 1


def test_count_sidecars_excludes_agent_batch_plans(tmp_path):
    (tmp_path / "agent_batch_0000.json").write_text("{}")
    (tmp_path / "task_0001.json").write_text("{}")
    assert count_sidecars(tmp_path) == 1


def test_count_sidecars_ignores_non_json(tmp_path):
    (tmp_path / "task_0001.json").write_text("{}")
    (tmp_path / "task_0002.md").write_text("text")
    assert count_sidecars(tmp_path) == 1


def test_count_sidecars_missing_dir(tmp_path):
    missing = tmp_path / "no_such_dir"
    assert count_sidecars(missing) == 0


# ---------------------------------------------------------------------------
# Core gate: count == expected -> PASS (exit 0)
# ---------------------------------------------------------------------------


def test_pass_when_count_equals_expected(tmp_path):
    """PASS path: sidecar count equals expected -> rc 0."""
    for i in range(5):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "5", "--sidecar-dir", str(tmp_path)]
    )
    rc = run(args)
    assert rc == 0


def test_pass_when_count_exceeds_expected(tmp_path):
    """PASS path: more sidecars than expected is fine (bonus tasks)."""
    for i in range(7):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "5", "--sidecar-dir", str(tmp_path)]
    )
    rc = run(args)
    assert rc == 0


# ---------------------------------------------------------------------------
# Core gate: count < expected -> FAIL (exit 1, loud message)
# ---------------------------------------------------------------------------


def test_fail_when_count_less_than_expected(tmp_path, capsys):
    """FAIL path: sidecar count < expected -> rc 1 + loud error message."""
    for i in range(3):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    # Expected 5, only 3 written
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "5", "--sidecar-dir", str(tmp_path)]
    )
    rc = run(args)
    assert rc == 1

    captured = capsys.readouterr()
    # The FAIL status must appear in stdout or stderr
    combined = captured.out + captured.err
    assert "FAIL" in combined
    assert "COVERAGE HOLE" in combined or "missing" in combined.lower()


def test_fail_message_includes_counts(tmp_path, capsys):
    """FAIL message must include expected and actual counts."""
    for i in range(2):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "10", "--sidecar-dir", str(tmp_path)]
    )
    run(args)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "10" in combined  # expected
    assert "2" in combined   # actual


# ---------------------------------------------------------------------------
# warn-only: count < expected -> exit 0 but still emits WARN
# ---------------------------------------------------------------------------


def test_warn_only_exits_zero_on_mismatch(tmp_path, capsys):
    """--warn-only: mismatch exits 0 and emits warning to stderr."""
    for i in range(1):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "5", "--sidecar-dir", str(tmp_path), "--warn-only"]
    )
    rc = run(args)
    assert rc == 0

    captured = capsys.readouterr()
    # Warning must still appear
    assert "WARN" in captured.err or "warn" in (captured.out + captured.err).lower()


def test_warn_only_passes_when_count_matches(tmp_path):
    """--warn-only: matching count still exits 0."""
    for i in range(3):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "3", "--sidecar-dir", str(tmp_path), "--warn-only"]
    )
    rc = run(args)
    assert rc == 0


# ---------------------------------------------------------------------------
# --json output
# ---------------------------------------------------------------------------


def test_json_output_pass(tmp_path, capsys):
    """--json: emits valid JSON with status=PASS."""
    for i in range(4):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "4", "--sidecar-dir", str(tmp_path), "--json"]
    )
    rc = run(args)
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "PASS"
    assert data["expected"] == 4
    assert data["actual"] == 4


def test_json_output_fail(tmp_path, capsys):
    """--json: emits valid JSON with status=FAIL on mismatch."""
    for i in range(2):
        (tmp_path / f"task_{i:04d}.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "5", "--sidecar-dir", str(tmp_path), "--json"]
    )
    rc = run(args)
    assert rc == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "FAIL"
    assert data["expected"] == 5
    assert data["actual"] == 2


# ---------------------------------------------------------------------------
# Edge: missing directory
# ---------------------------------------------------------------------------


def test_missing_dir_treated_as_zero(tmp_path, capsys):
    """Missing sidecar dir without --strict-dir is treated as 0 sidecars."""
    missing = tmp_path / "not_created_yet"
    parser = build_parser()
    # expected=0 -> PASS even with missing dir
    args = parser.parse_args(
        ["--expected", "0", "--sidecar-dir", str(missing)]
    )
    rc = run(args)
    assert rc == 0


def test_missing_dir_fails_when_expected_gt_zero(tmp_path, capsys):
    """Missing dir with expected > 0 -> FAIL (0 < expected)."""
    missing = tmp_path / "not_created_yet"
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "3", "--sidecar-dir", str(missing)]
    )
    rc = run(args)
    assert rc == 1


def test_strict_dir_exits_2_on_missing(tmp_path):
    """--strict-dir: exits 2 if sidecar-dir does not exist."""
    missing = tmp_path / "not_created_yet"
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "0", "--sidecar-dir", str(missing), "--strict-dir"]
    )
    rc = run(args)
    assert rc == 2


# ---------------------------------------------------------------------------
# Edge: expected = 0 with empty dir -> PASS
# ---------------------------------------------------------------------------


def test_expected_zero_empty_dir_passes(tmp_path):
    """expected=0 + empty dir = trivial PASS (no tasks dispatched)."""
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "0", "--sidecar-dir", str(tmp_path)]
    )
    rc = run(args)
    assert rc == 0


# ---------------------------------------------------------------------------
# --receipt: writes a {status: pass|fail} receipt for the readme-conformance gate
# ---------------------------------------------------------------------------


def test_receipt_written_on_pass(tmp_path):
    """--receipt writes status=pass (lowercase) when count >= expected."""
    sc = tmp_path / "sc"
    sc.mkdir()
    for i in range(3):
        (sc / f"task_{i:04d}.json").write_text("{}")
    receipt = tmp_path / "receipt.json"
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "3", "--sidecar-dir", str(sc), "--receipt", str(receipt)]
    )
    rc = run(args)
    assert rc == 0
    data = json.loads(receipt.read_text())
    assert data["status"] == "pass"  # lowercase for the conformance ok_values
    assert data["expected"] == 3
    assert data["actual"] == 3


def test_receipt_written_on_fail(tmp_path):
    """--receipt writes status=fail (lowercase) when count < expected."""
    sc = tmp_path / "sc"
    sc.mkdir()
    (sc / "task_0000.json").write_text("{}")
    receipt = tmp_path / "receipt.json"
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "5", "--sidecar-dir", str(sc), "--receipt", str(receipt)]
    )
    rc = run(args)
    assert rc == 1
    data = json.loads(receipt.read_text())
    assert data["status"] == "fail"
    assert data["expected"] == 5
    assert data["actual"] == 1


def test_receipt_parent_dir_created(tmp_path):
    """--receipt creates missing parent directories."""
    sc = tmp_path / "sc"
    sc.mkdir()
    receipt = tmp_path / "nested" / "deep" / "receipt.json"
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "0", "--sidecar-dir", str(sc), "--receipt", str(receipt)]
    )
    rc = run(args)
    assert rc == 0
    assert receipt.is_file()
    assert json.loads(receipt.read_text())["status"] == "pass"


def test_no_receipt_when_flag_absent(tmp_path):
    """Without --receipt, no receipt file is written (back-compat)."""
    sc = tmp_path / "sc"
    sc.mkdir()
    (sc / "task_0000.json").write_text("{}")
    parser = build_parser()
    args = parser.parse_args(["--expected", "1", "--sidecar-dir", str(sc)])
    rc = run(args)
    assert rc == 0
    # No stray receipt.json anywhere under tmp
    assert not list(tmp_path.glob("**/receipt*.json"))


# ---------------------------------------------------------------------------
# Edge: negative expected -> argument error (exit 2)
# ---------------------------------------------------------------------------


def test_negative_expected_exits_2(tmp_path):
    """Negative --expected is invalid -> exit 2."""
    parser = build_parser()
    args = parser.parse_args(
        ["--expected", "-1", "--sidecar-dir", str(tmp_path)]
    )
    rc = run(args)
    assert rc == 2
