#!/usr/bin/env python3
"""test_matrix_worklist_join_f1.py

F1 (enforcement id24,30, 2026-07-03): completeness-matrix verdict/worklist JOIN
false-green.

check_completeness_matrix keyed ONLY on m["verdict"]; a matrix can report
verdict=="complete" while its enumeration_worklist still lists VALUE-MOVING
not-enumerated cells (a serving-join / staleness / verdict-computation gap - NUVA
real: verdict=complete yet 14 value_moving worklist rows; NuvaVault 2/10,
CrossChainManager 3/10 invariant cells). This test pins the JOIN fix:

  - completeness-matrix-build.py tags each worklist row cell_kind=value_moving OR
    dropped_nonentry (the interface/library files _drop_nonentry_file legitimately
    drops - IFullERC20 / ECRecover);
  - under AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT, a verdict==complete that still
    carries >=1 VALUE-MOVING not-enumerated worklist cell hard-FAILs;
  - the INTERFACE-FILE TRAP is honored: dropped_nonentry rows NEVER force
    incomplete (no re-red of the 33 interface files);
  - env-unset is byte-identical (verdict==complete stays a pass).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_ACC_SRC = (_TOOLS / "audit-completeness-check.py").read_text(
    encoding="utf-8", errors="replace")
_CMB_SRC = (_TOOLS / "completeness-matrix-build.py").read_text(
    encoding="utf-8", errors="replace")
_ENV = "AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT"
_L37 = "AUDITOOOR_L37_STRICT"


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class TestF1MatrixWorklistJoin(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop(_ENV, None)
        self._saved_l37 = os.environ.pop(_L37, None)
        self.acc = _load("acc_f1", "audit-completeness-check.py")
        self.cmb = _load("cmb_f1", "completeness-matrix-build.py")

    def tearDown(self):
        for k, v in ((_ENV, self._saved), (_L37, self._saved_l37)):
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    # ---- cell_kind classifier (matrix-build side) ------------------------
    def test_interface_files_tagged_dropped_nonentry(self):
        for p in ("src/interfaces/IFullERC20.sol", "src/libraries/ECRecover.sol",
                  "contracts/IVault.sol", "src/TokenLib.sol"):
            self.assertEqual(self.cmb._worklist_function_cell_kind(p),
                             "dropped_nonentry", p)

    def test_value_movers_tagged_value_moving(self):
        for p in ("src/vault/NuvaVault.sol",
                  "src/vault/keeper/valuation_engine.go",
                  "src/CrossChainManager.sol"):
            self.assertEqual(self.cmb._worklist_function_cell_kind(p),
                             "value_moving", p)

    def test_worklist_rows_carry_cell_kind(self):
        # a matrix with a value-moving not-enumerated fn + an interface fn
        m = {
            "assets": [{
                "asset_id": "a",
                "functions": [
                    {"function": "transfer", "file": "src/Vault.sol",
                     "coverage_status": "not-enumerated"},
                    {"function": "balanceOf", "file": "src/interfaces/IFullERC20.sol",
                     "coverage_status": "not-enumerated"},
                ],
                "invariant_categories_not_enumerated": ["conservation"],
            }],
            "impact_enumeration": {"missing": False, "not_enumerated": []},
            "flows": {}, "mechanism_axis": {},
        }
        rows = self.cmb.build_enumeration_worklist(m)
        kinds = {(r["axis"], r.get("function"), r.get("invariant_category")):
                 r.get("cell_kind") for r in rows}
        self.assertEqual(kinds[("function", "transfer", None)], "value_moving")
        self.assertEqual(kinds[("function", "balanceOf", None)], "dropped_nonentry")
        self.assertEqual(kinds[("invariant", None, "conservation")], "value_moving")

    # ---- reader-side JOIN (audit-completeness-check side) ----------------
    def _drive_reader(self, ws, worklist):
        mod = self.acc._load_completeness_matrix_module()
        mod.build_matrix = lambda _ws: {
            "verdict": "complete", "denominators": {}, "cells": {}, "reasons": [],
            "not_enumerated_assets": [], "enumeration_worklist": worklist}
        self.acc._load_completeness_matrix_module = lambda: mod
        return self.acc.check_completeness_matrix(ws)

    # ---- 4-case default-ON-under-L37 matrix ------------------------------
    def test_case_non_strict_advisory_env_unset_no_l37(self):
        # env unset AND no L37 -> a complete matrix passes (byte-parity for a bare/
        # library caller). This is the ONLY advisory-by-absence case.
        wl = [{"axis": "function", "cell_kind": "value_moving",
               "status": "not-enumerated", "function": "transfer", "file": "src/V.sol"}]
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir()
            os.environ.pop(_ENV, None)
            os.environ.pop(_L37, None)
            r = self._drive_reader(ws, wl)
            self.assertTrue(r.ok, "env-unset + no L37: a complete matrix must pass")
            self.assertEqual(r.detail.get("verdict"), "complete")

    def test_case_default_under_l37_enforced(self):
        # env UNSET but AUDITOOOR_L37_STRICT=1 -> NEW default: the JOIN ENFORCES,
        # so a complete matrix with a value-moving unenumerated cell hard-FAILs.
        wl = [{"axis": "function", "cell_kind": "value_moving",
               "status": "not-enumerated", "function": "transfer", "file": "src/V.sol"}]
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir()
            os.environ.pop(_ENV, None)
            os.environ[_L37] = "1"
            r = self._drive_reader(ws, wl)
            self.assertFalse(r.ok, "env-unset under L37 must ENFORCE the JOIN (default-ON)")
            self.assertEqual(r.detail.get("verdict"), "join-false-green")
            self.assertEqual(r.detail.get("worklist_value_moving_unenumerated"), 1)

    def test_case_opt_out_env_zero_even_under_l37(self):
        # explicit AUDITOOOR_MATRIX_WORKLIST_JOIN_STRICT=0 -> DISABLED escape hatch
        # even when L37 is set: the complete matrix passes.
        wl = [{"axis": "function", "cell_kind": "value_moving",
               "status": "not-enumerated", "function": "transfer", "file": "src/V.sol"}]
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir()
            os.environ[_ENV] = "0"
            os.environ[_L37] = "1"
            r = self._drive_reader(ws, wl)
            self.assertTrue(r.ok, "env=0 is an explicit opt-out even under L37")
            self.assertEqual(r.detail.get("verdict"), "complete")

    def test_case_explicit_on_env_one(self):
        # explicit opt-in: complete+value_moving-unenum must FAIL (no L37 needed).
        wl = [{"axis": "function", "cell_kind": "value_moving",
               "status": "not-enumerated", "function": "transfer", "file": "src/V.sol"}]
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir()
            os.environ[_ENV] = "1"
            os.environ.pop(_L37, None)
            r = self._drive_reader(ws, wl)
            self.assertFalse(r.ok, "env-set: complete+value_moving-unenum must FAIL")
            self.assertEqual(r.detail.get("verdict"), "join-false-green")
            self.assertEqual(r.detail.get("worklist_value_moving_unenumerated"), 1)

    def test_interface_trap_never_reds(self):
        # a worklist of ONLY dropped_nonentry interface rows must NOT force incomplete
        wl = [
            {"axis": "function", "cell_kind": "dropped_nonentry",
             "status": "not-enumerated", "function": "balanceOf",
             "file": "src/interfaces/IFullERC20.sol"},
            {"axis": "function", "cell_kind": "dropped_nonentry",
             "status": "not-enumerated", "function": "recover",
             "file": "src/libraries/ECRecover.sol"},
        ]
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir()
            os.environ[_ENV] = "1"
            r = self._drive_reader(ws, wl)
            self.assertTrue(r.ok, "interface-only worklist must NOT re-red under the JOIN")
            self.assertEqual(r.detail.get("verdict"), "complete")

    def test_mixed_worklist_counts_only_value_moving(self):
        wl = [
            {"axis": "function", "cell_kind": "value_moving",
             "status": "not-enumerated", "function": "transfer", "file": "src/V.sol"},
            {"axis": "function", "cell_kind": "dropped_nonentry",
             "status": "not-enumerated", "function": "balanceOf",
             "file": "src/interfaces/IFullERC20.sol"},
        ]
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir()
            os.environ[_ENV] = "1"
            r = self._drive_reader(ws, wl)
            self.assertFalse(r.ok)
            # only the 1 value-moving row counts; the interface row is excluded
            self.assertEqual(r.detail.get("worklist_value_moving_unenumerated"), 1)

    # ---- wiring pins -----------------------------------------------------
    def test_default_on_predicate_wiring(self):
        # DEFAULT-ON graduation: the F1 JOIN predicate now delegates to the shared
        # _gate_default_on_strict() over the dedicated env, default-ON under L37
        # with a per-gate opt-out.
        i = _ACC_SRC.find("_worklist_join_strict = _gate_default_on_strict")
        self.assertGreater(i, 0, "F1 must call the shared default-ON helper")
        seg = _ACC_SRC[i:i + 120]
        self.assertIn(_ENV, seg)
        # the shared helper reads L37 as the default umbrella + honors the opt-out
        h = _ACC_SRC.find("def _gate_default_on_strict")
        self.assertGreater(h, 0)
        hseg = _ACC_SRC[h:h + 1400]
        self.assertIn("AUDITOOOR_L37_STRICT", hseg)
        self.assertIn('("0", "false", "no")', hseg)

    def test_build_tags_all_axes(self):
        # every axis in build_enumeration_worklist must set cell_kind
        self.assertIn('"cell_kind": _worklist_function_cell_kind', _CMB_SRC)
        self.assertIn('"cell_kind": "value_moving"', _CMB_SRC)

    def test_syntax_ok(self):
        import ast
        ast.parse(_ACC_SRC)
        ast.parse(_CMB_SRC)


if __name__ == "__main__":
    unittest.main()
