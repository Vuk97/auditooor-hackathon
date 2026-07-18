"""Focused tests for enumeration-universe-consistency-check.py.

Covers the 5 required cases from the BUILD-ENUM_CONSIST lane spec:
  (a) plan == gate -> pass-consistent
  (b) 1644-vs-57 balloon -> fail-plan-overballooned
  (c) gate unit absent from plan -> fail-gate-unit-unplanned
  (d) empty-function enumeration over a fn-defining source file ->
      fail-empty-function-enumeration
  (e) no inputs resolvable -> pass-insufficient-inputs
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "enumeration-universe-consistency-check.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("enumeration_universe_consistency_check", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_gate_result(ws: Path, queued_not_scanned: list) -> Path:
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / "g15_hunt_coverage_gate_last_result.json"
    path.write_text(json.dumps({"queued_not_scanned": queued_not_scanned}), encoding="utf-8")
    return path


def _write_plan_residual(ws: Path, units: list) -> Path:
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / "plan_residual.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for u in units:
            f.write(json.dumps(u) + "\n")
    return path


class EnumerationUniverseConsistencyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    # (a) plan == gate -> pass-consistent
    def test_plan_equals_gate_is_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            units = [f"src/File{i}.go::Func{i}" for i in range(10)]
            _write_plan_residual(ws, units)
            _write_gate_result(ws, units)

            result = self.t.run_check(ws)

            self.assertEqual(result["verdict"], "pass-consistent")
            self.assertEqual(result["plan_count"], 10)
            self.assertEqual(result["gate_residual_count"], 10)
            self.assertEqual(result["gate_unplanned"], [])
            self.assertEqual(result["empty_function_units"], [])

    # (b) 1644-vs-57 balloon -> fail-plan-overballooned
    def test_plan_overballooned_1644_vs_57(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            gate_units = [f"src/GateFile{i}.go::Fn{i}" for i in range(57)]
            # Plan is a strict superset containing the gate units plus a huge
            # amount of over-enumerated noise (the balloon).
            plan_units = list(gate_units) + [f"src/Noise{i}.go::N{i}" for i in range(1644 - 57)]

            _write_plan_residual(ws, plan_units)
            _write_gate_result(ws, gate_units)

            result = self.t.run_check(ws)

            self.assertEqual(result["verdict"], "fail-plan-overballooned")
            self.assertEqual(result["plan_count"], 1644)
            self.assertEqual(result["gate_residual_count"], 57)
            self.assertEqual(result["gate_unplanned"], [])

    # (c) gate unit absent from plan -> fail-gate-unit-unplanned
    def test_gate_unit_absent_from_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            plan_units = ["src/A.go::Foo", "src/B.go::Bar"]
            gate_units = ["src/A.go::Foo", "src/C.go::Baz"]  # C::Baz missing from plan

            _write_plan_residual(ws, plan_units)
            _write_gate_result(ws, gate_units)

            result = self.t.run_check(ws)

            self.assertEqual(result["verdict"], "fail-gate-unit-unplanned")
            self.assertIn("src/C.go::Baz", result["gate_unplanned"])

    # (d) empty-function enumeration over a fn-defining source file
    def test_empty_function_enumeration_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src_dir = ws / "src"
            src_dir.mkdir(parents=True)
            go_file = src_dir / "ValueMover.go"
            go_file.write_text(
                "package main\n\nfunc TransferValue(x int) int {\n\treturn x + 1\n}\n",
                encoding="utf-8",
            )

            plan_units = [
                {"file": "src/ValueMover.go", "function": ""},  # placeholder-unit bug
            ]
            gate_units = ["src/ValueMover.go::"]

            _write_plan_residual(ws, plan_units)
            _write_gate_result(ws, gate_units)

            result = self.t.run_check(ws)

            self.assertEqual(result["verdict"], "fail-empty-function-enumeration")
            self.assertTrue(len(result["empty_function_units"]) >= 1)

    # (e) no inputs resolvable -> pass-insufficient-inputs (never-false-pass)
    def test_no_inputs_resolvable_is_insufficient_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Deliberately create no .auditooor artifacts at all.
            result = self.t.run_check(ws)

            self.assertEqual(result["verdict"], "pass-insufficient-inputs")
            self.assertIsNone(result["plan_count"])
            self.assertIsNone(result["gate_residual_count"])

    # CLI-level smoke: --strict rc on fail vs rc=0 without --strict.
    def test_cli_strict_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            gate_units = ["src/A.go::Foo"]
            plan_units: list = []  # empty plan -> gate unit unplanned
            _write_plan_residual(ws, plan_units)
            _write_gate_result(ws, gate_units)

            rc_default = self.t.main(["--workspace", str(ws), "--json"])
            self.assertEqual(rc_default, 0)

            rc_strict = self.t.main(["--workspace", str(ws), "--json", "--strict"])
            self.assertEqual(rc_strict, 1)


if __name__ == "__main__":
    unittest.main()
