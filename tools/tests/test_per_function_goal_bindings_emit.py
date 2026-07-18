#!/usr/bin/env python3
"""Regression test for the --emit-goal-audit flag on per-function-invariant-gen.

Covers the new emit_goal_audit() helper (correct goal_bound_count + goal_unbound
per row) and the end-to-end flag wiring (writes
<ws>/.auditooor/per_function_goal_bindings.jsonl, default off / additive).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


def _load_module():
    tool = Path(__file__).resolve().parents[1] / "per-function-invariant-gen.py"
    spec = importlib.util.spec_from_file_location("pfig_under_test", str(tool))
    mod = importlib.util.module_from_spec(spec)
    # Register before exec_module so dataclass introspection (Python 3.12+/3.14)
    # can resolve the module by __module__ name during @dataclass processing.
    sys.modules["pfig_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


PFIG = _load_module()


class TestEmitGoalAudit(unittest.TestCase):
    def test_emit_goal_audit_row_shape_and_counts(self):
        rows = [
            # fully bound: 2 impacts, 2 bound -> goal_unbound == []
            {"function": "f_bound", "source": "src/A.sol:10",
             "goal_impact_ids": ["IMP-1", "IMP-2"], "goal_bound_count": 2},
            # fully unbound: matched impacts but 0 bound -> all impacts unbound
            {"function": "f_unbound", "source": "src/A.sol:20",
             "goal_impact_ids": ["IMP-3"], "goal_bound_count": 0},
            # no goals matched at all
            {"function": "f_none", "source": "src/A.sol:30",
             "goal_impact_ids": [], "goal_bound_count": 0},
        ]
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            out_path = PFIG.emit_goal_audit(ws, rows)
            self.assertEqual(
                out_path, ws / ".auditooor" / "per_function_goal_bindings.jsonl")
            self.assertTrue(out_path.is_file())
            parsed = [
                json.loads(line)
                for line in out_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        self.assertEqual(len(parsed), 3)
        by_fn = {r["function"]: r for r in parsed}

        self.assertEqual(by_fn["f_bound"]["goal_bound_count"], 2)
        self.assertEqual(by_fn["f_bound"]["goal_impact_ids"], ["IMP-1", "IMP-2"])
        self.assertEqual(by_fn["f_bound"]["goal_unbound"], [])

        self.assertEqual(by_fn["f_unbound"]["goal_bound_count"], 0)
        self.assertEqual(by_fn["f_unbound"]["goal_unbound"], ["IMP-3"])

        self.assertEqual(by_fn["f_none"]["goal_bound_count"], 0)
        self.assertEqual(by_fn["f_none"]["goal_unbound"], [])
        # every row carries the file (file:line) location for the operator
        for r in parsed:
            self.assertIn(":", r["file"])

    def test_flag_default_off_does_not_write(self):
        """Without --emit-goal-audit, the jsonl is never created (additive)."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Tiny.sol").write_text(
                "// SPDX-License-Identifier: UNLICENSED\n"
                "pragma solidity ^0.8.13;\n"
                "contract Tiny {\n"
                "    function setValue(uint256 v) external { }\n"
                "}\n",
                encoding="utf-8",
            )
            rc = PFIG.main([
                "--workspace", str(ws),
                "--output-dir", str(ws / "out"),
                "--dry-run",
            ])
            self.assertEqual(rc, 0)
            self.assertFalse(
                (ws / ".auditooor" / "per_function_goal_bindings.jsonl").exists())

    def test_flag_emits_jsonl_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Tiny.sol").write_text(
                "// SPDX-License-Identifier: UNLICENSED\n"
                "pragma solidity ^0.8.13;\n"
                "contract Tiny {\n"
                "    function setValue(uint256 v) external { }\n"
                "    function withdraw(uint256 amt) external { }\n"
                "}\n",
                encoding="utf-8",
            )
            rc = PFIG.main([
                "--workspace", str(ws),
                "--output-dir", str(ws / "out"),
                "--dry-run",
                "--emit-goal-audit",
            ])
            self.assertEqual(rc, 0)
            audit = ws / ".auditooor" / "per_function_goal_bindings.jsonl"
            self.assertTrue(audit.is_file())
            parsed = [
                json.loads(line)
                for line in audit.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            # one row per discovered external function
            fn_names = {r["function"] for r in parsed}
            self.assertIn("setValue", fn_names)
            self.assertIn("withdraw", fn_names)
            # every row carries the audit schema keys
            for r in parsed:
                self.assertIn("goal_impact_ids", r)
                self.assertIn("goal_bound_count", r)
                self.assertIn("goal_unbound", r)
                self.assertIsInstance(r["goal_bound_count"], int)


if __name__ == "__main__":
    unittest.main()
