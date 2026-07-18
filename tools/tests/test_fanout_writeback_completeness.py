"""Guard: fan-out writeback completeness check (the "7/24 pattern").

Root cause: an agent dispatched a 24-unit worklist but only 7 sidecars were
ever written -> silent under-coverage credited as if it were a full hunt.
This suite proves the checker (tools/fanout-writeback-completeness-check.py):
  (a) N==N dispatched/written -> pass-writeback-complete
  (b) 7-of-24 partial batch -> fail-writeback-incomplete + 17 missing
  (c) a zero-byte sidecar file does NOT count as coverage (still missing)
  (d) no worklist files at all -> pass-no-worklist (never-false-pass)
  (e) both the flat {unit,file,function} schema and the nested
      {result:{function_anchor}} schema resolve identically
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "fanout-writeback-completeness-check.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


checker = _load_module("fanout_writeback_completeness_check", MODULE_PATH)


def _mk_workspace(tmp_root: Path) -> Path:
    ws = tmp_root / "ws"
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True, exist_ok=True)
    return ws


def _write_worklist(ws: Path, units, name="batch_part_1.txt"):
    lines = [f"{u}" for u in units]
    (ws / ".auditooor" / name).write_text("\n".join(lines) + "\n")


def _write_flat_sidecar(ws: Path, idx: int, file_name: str, function: str):
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True, exist_ok=True)
    row = {"unit": f"{file_name}::{function}", "file": file_name, "function": function, "lines": "1-10"}
    (d / f"sidecar_{idx}.json").write_text(json.dumps(row))


def _write_nested_sidecar(ws: Path, idx: int, file_name: str, function: str):
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True, exist_ok=True)
    row = {"result": {"function_anchor": {"file": file_name, "function": function}}}
    (d / f"sidecar_nested_{idx}.json").write_text(json.dumps(row))


class TestFanoutWritebackCompleteness(unittest.TestCase):
    def test_a_full_coverage_all_units_written(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_workspace(Path(td))
            units = [f"File{i}.sol::fn{i}" for i in range(5)]
            _write_worklist(ws, units)
            for i, u in enumerate(units):
                file_part, fn_part = u.split("::")
                _write_flat_sidecar(ws, i, file_part, fn_part)

            result = checker.run_check(ws, None, None)
            self.assertEqual(result["verdict"], "pass-writeback-complete")
            self.assertEqual(result["dispatched"], 5)
            self.assertEqual(result["written"], 5)
            self.assertEqual(result["missing"], [])

    def test_b_seven_of_24_partial_batch_reports_17_missing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_workspace(Path(td))
            units = [f"File{i}.sol::fn{i}" for i in range(24)]
            _write_worklist(ws, units)
            # Only write sidecars for the first 7 units.
            for i in range(7):
                file_part, fn_part = units[i].split("::")
                _write_flat_sidecar(ws, i, file_part, fn_part)

            result = checker.run_check(ws, None, None)
            self.assertEqual(result["verdict"], "fail-writeback-incomplete")
            self.assertEqual(result["dispatched"], 24)
            self.assertEqual(result["written"], 7)
            self.assertEqual(len(result["missing"]), 17)

    def test_c_zero_byte_sidecar_does_not_count_as_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_workspace(Path(td))
            units = ["File1.sol::fnOne", "File2.sol::fnTwo"]
            _write_worklist(ws, units)
            # File1 gets a real sidecar.
            _write_flat_sidecar(ws, 0, "File1.sol", "fnOne")
            # File2 gets a zero-byte sidecar -> must NOT count as written.
            zero_path = ws / ".auditooor" / "hunt_findings_sidecars" / "sidecar_zero.json"
            zero_path.write_text("")
            self.assertEqual(zero_path.stat().st_size, 0)

            result = checker.run_check(ws, None, None)
            self.assertEqual(result["verdict"], "fail-writeback-incomplete")
            self.assertEqual(result["dispatched"], 2)
            self.assertEqual(result["written"], 1)
            self.assertIn("File2.sol::fnTwo", result["missing"])

    def test_d_no_worklist_at_all_is_pass_no_worklist(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_workspace(Path(td))
            # No worklist files written at all; some unrelated sidecar exists.
            _write_flat_sidecar(ws, 0, "Irrelevant.sol", "fnX")

            result = checker.run_check(ws, None, None)
            self.assertEqual(result["verdict"], "pass-no-worklist")
            self.assertEqual(result["dispatched"], 0)
            self.assertEqual(result["missing"], [])

    def test_e_flat_and_nested_schemas_both_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_workspace(Path(td))
            units = ["FlatFile.sol::flatFn", "NestedFile.sol::nestedFn"]
            _write_worklist(ws, units)
            _write_flat_sidecar(ws, 0, "FlatFile.sol", "flatFn")
            _write_nested_sidecar(ws, 1, "NestedFile.sol", "nestedFn")

            result = checker.run_check(ws, None, None)
            self.assertEqual(result["verdict"], "pass-writeback-complete")
            self.assertEqual(result["dispatched"], 2)
            self.assertEqual(result["written"], 2)
            self.assertEqual(result["missing"], [])


if __name__ == "__main__":
    unittest.main()
