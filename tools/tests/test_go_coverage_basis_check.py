#!/usr/bin/env python3
# <!-- r36-rebuttal: lane WIRE-GO-COVERAGE-ENFORCE registered via agent-pathspec-register.py -->
"""Guard tests for tools/go-coverage-basis-check.py - the fail-closed Cosmos/Go-L1
coverage-basis gate (wired into audit-complete as the go-coverage-basis signal).

NEVER-FALSE-PASS pins:
  - Cosmos-Go-L1 with fcc go_entry_surface.applied=True   -> pass-entry-point-basis
  - Cosmos-Go-L1 with fcc lacking that block (kill-switch  -> fail-wrong-basis
    left on / stale pre-capability artifact)                  (WARN advisory / FAIL strict)
  - Cosmos-Go-L1 with NO fcc result                        -> fail-fcc-missing
    (NEVER a silent pass - a missing input WARNs/FAILs)        (WARN advisory / FAIL strict)
  - non-Cosmos (Solidity/Rust) workspace                   -> pass-not-cosmos-go (N/A)
  - advisory (no L37 strict) never returns ok=False on a fail-* verdict
  - strict returns ok=False + a non-empty instruction on a fail-* verdict
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "go-coverage-basis-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("go_coverage_basis_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["go_coverage_basis_check"] = m
    spec.loader.exec_module(m)
    return m


_MOD = _load()

_COSMOS_GOMOD = (
    "module example.com/chain\n\ngo 1.21\n\n"
    "require github.com/cosmos/cosmos-sdk v0.50.1\n"
)


def _mk_ws(tmp: Path, *, cosmos: bool, fcc: dict | None) -> Path:
    ws = tmp
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    if cosmos:
        (ws / "go.mod").write_text(_COSMOS_GOMOD, encoding="utf-8")
        # a couple of go files so the ws is plausibly a Go tree
        (ws / "app.go").write_text("package app\n", encoding="utf-8")
    else:
        # a Solidity workspace: no cosmos go.mod
        (ws / "Contract.sol").write_text("// SPDX\npragma solidity ^0.8.20;\n",
                                         encoding="utf-8")
    if fcc is not None:
        (ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(fcc), encoding="utf-8")
    return ws


class TestGoCoverageBasis(unittest.TestCase):
    def test_cosmos_entry_point_basis_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=True, fcc={
                "schema": "auditooor.function_coverage_completeness.v1",
                "go_entry_surface": {"applied": True, "entry_points": 134,
                                     "internal_helpers_excluded": 9671}})
            r = _MOD.evaluate(ws)
            self.assertEqual(r["verdict"], "pass-entry-point-basis")
            self.assertTrue(r["ok"])
            self.assertTrue(r["is_cosmos_go"])
            self.assertTrue(r["go_entry_surface_applied"])

    def test_cosmos_wrong_basis_advisory_warns_not_fail(self):
        # fcc present but NO go_entry_surface block (stale pre-capability artifact)
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=True, fcc={
                "schema": "auditooor.function_coverage_completeness.v1",
                "counts": {"total": 11774}})
            r = _MOD.evaluate(ws)  # advisory (no strict env in this process)
            self.assertEqual(r["verdict"], "fail-wrong-basis")
            self.assertTrue(r["ok"])  # advisory: WARN, not a hard fail
            self.assertTrue(r["reason"].startswith("WARN:"))
            self.assertTrue(r["instruction"])

    def test_cosmos_wrong_basis_strict_fails_with_instruction(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=True, fcc={
                "go_entry_surface": {"applied": False}})
            old = os.environ.get("AUDITOOOR_L37_STRICT")
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = _MOD.evaluate(ws)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_L37_STRICT", None)
                else:
                    os.environ["AUDITOOOR_L37_STRICT"] = old
            self.assertEqual(r["verdict"], "fail-wrong-basis")
            self.assertFalse(r["ok"])  # strict: hard fail
            self.assertFalse(r["reason"].startswith("WARN:"))
            self.assertIn("entry-point", r["instruction"].lower())

    def test_cosmos_missing_fcc_never_silent_pass(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=True, fcc=None)
            r = _MOD.evaluate(ws)  # advisory
            self.assertEqual(r["verdict"], "fail-fcc-missing")
            self.assertTrue(r["ok"])          # advisory WARN
            self.assertTrue(r["reason"].startswith("WARN:"))
            self.assertFalse(r["fcc_present"])
            self.assertTrue(r["instruction"])

    def test_cosmos_missing_fcc_strict_fails(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=True, fcc=None)
            old = os.environ.get("AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT")
            os.environ["AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT"] = "1"
            try:
                r = _MOD.evaluate(ws)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT", None)
                else:
                    os.environ["AUDITOOOR_L37_GO_COVERAGE_BASIS_STRICT"] = old
            self.assertEqual(r["verdict"], "fail-fcc-missing")
            self.assertFalse(r["ok"])

    def test_non_cosmos_na_pass(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=False, fcc={"go_entry_surface": {"applied": False}})
            r = _MOD.evaluate(ws)
            self.assertEqual(r["verdict"], "pass-not-cosmos-go")
            self.assertTrue(r["ok"])
            self.assertFalse(r["is_cosmos_go"])

    def test_non_cosmos_na_pass_even_under_strict(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_ws(Path(td), cosmos=False, fcc=None)
            old = os.environ.get("AUDITOOOR_L37_STRICT")
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = _MOD.evaluate(ws)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_L37_STRICT", None)
                else:
                    os.environ["AUDITOOOR_L37_STRICT"] = old
            # a non-Cosmos ws is N/A - strict does not turn N/A into a fail
            self.assertEqual(r["verdict"], "pass-not-cosmos-go")
            self.assertTrue(r["ok"])


if __name__ == "__main__":
    unittest.main()
