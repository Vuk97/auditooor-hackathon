#!/usr/bin/env python3
"""test_prehunt_matrix_enumerate_only.py

Regression for the A1 pre-hunt rewire (enumerate BEFORE the hunt):

  1. completeness-matrix-build.py --enumerate-only is a PURE PRODUCER: it writes
     completeness_matrix.json + COMPLETENESS_MATRIX.md +
     completeness_enumeration_worklist.jsonl and ALWAYS returns rc 0, computing
     NO terminal verdict / enforce (so wiring it into a pre-hunt step can never
     brick a pipeline). --check still WINS if both are passed (enforcement is
     never silently dropped by also asking to enumerate).

  2. audit-completeness-check.check_completeness_matrix PREFERS an on-disk matrix
     produced by that pre-hunt step, but ONLY under the dedicated DEFAULT-OFF env
     AUDITOOOR_PREHUNT_MATRIX. With the env UNSET the reader rebuilds via
     build_matrix exactly as before (byte-identical behavior).
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_CMB = REPO / "tools" / "completeness-matrix-build.py"
_ACC = REPO / "tools" / "audit-completeness-check.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestEnumerateOnlyProducer(unittest.TestCase):
    def _run(self, ws: Path, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(_CMB), "--workspace", str(ws), *extra],
            capture_output=True, text=True)

    def test_enumerate_only_produces_artifacts_rc0(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            r = self._run(ws, "--enumerate-only", "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["signal"], "enumerate-only-produced")
            self.assertEqual(out.get("mode"), "enumerate-only")
            self.assertFalse(out["enforce"], "producer mode never enforces")
            # both load-bearing artifacts on disk
            self.assertTrue((ws / ".auditooor" / "completeness_matrix.json").is_file())
            self.assertTrue(
                (ws / ".auditooor" / "completeness_enumeration_worklist.jsonl").is_file(),
                "the enumeration worklist must be written for a downstream hunt")

    def test_enumerate_only_rc0_even_when_incomplete(self) -> None:
        """A workspace whose matrix is INCOMPLETE must STILL exit 0 under
        --enumerate-only (producer contract: artifacts on disk, never a verdict).
        Contrast with --check, which fails-closed on the same input."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            # an in-scope unit with no dossier/invariant => not-enumerated cells
            (ws / ".auditooor" / "inscope_units.jsonl").write_text(
                json.dumps({"file": "src/A.sol", "function": "f"}) + "\n",
                encoding="utf-8")
            r_enum = self._run(ws, "--enumerate-only", "--json")
            self.assertEqual(r_enum.returncode, 0,
                             "--enumerate-only must be rc 0 even on an incomplete matrix")
            out = json.loads(r_enum.stdout)
            self.assertEqual(out["signal"], "enumerate-only-produced")
            # sanity: --check on the SAME workspace fails-closed (proves the
            # producer really did skip the terminal verdict, not that the ws was
            # trivially complete).
            r_check = self._run(ws, "--check")
            self.assertEqual(r_check.returncode, 1,
                             "--check must fail-close on the same incomplete matrix "
                             "(so --enumerate-only genuinely bypasses enforcement)")

    def test_check_wins_when_both_flags_passed(self) -> None:
        """Enforcement must never be silently dropped: passing BOTH --enumerate-only
        and --check keeps the terminal --check verdict (rc 1 on incomplete)."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            (ws / ".auditooor" / "inscope_units.jsonl").write_text(
                json.dumps({"file": "src/A.sol", "function": "f"}) + "\n",
                encoding="utf-8")
            r = self._run(ws, "--enumerate-only", "--check")
            self.assertEqual(r.returncode, 1,
                             "--check must win over --enumerate-only (no silent enforcement drop)")


class TestCheckPrefersOnDiskMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.acc = _load(_ACC, "_acc_prehunt_test")

    def _make_ws_with_disk_matrix(self, ws: Path, verdict: str) -> None:
        (ws / ".auditooor").mkdir(parents=True)
        # A hand-crafted on-disk matrix with a DISTINCTIVE verdict + minimal shape.
        disk = {
            "schema": "auditooor.completeness_matrix.v1",
            "ws": str(ws),
            "verdict": verdict,
            "denominators": {"assets": 0, "functions": 0,
                             "invariant_categories": 10, "impact_classes": 0},
            "cells": {"total": 0, "terminal": 0, "open": 0, "not_enumerated": 0},
            "assets": [],
            "not_enumerated_assets": [],
            "reasons": ["SENTINEL-ON-DISK-MATRIX"],
            "enumeration_worklist": [],
        }
        (ws / ".auditooor" / "completeness_matrix.json").write_text(
            json.dumps(disk, indent=2) + "\n", encoding="utf-8")

    def test_env_unset_rebuilds_ignores_disk(self) -> None:
        """DEFAULT (env unset): the reader must rebuild via build_matrix and NOT
        adopt the on-disk sentinel matrix (byte-identical to pre-A1 behavior)."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._make_ws_with_disk_matrix(ws, verdict="complete")
            os.environ.pop("AUDITOOOR_PREHUNT_MATRIX", None)
            res = self.acc.check_completeness_matrix(ws)
            # The rebuilt matrix overwrites the sentinel: the sentinel reason must
            # be gone from the persisted file (proof the reader rebuilt).
            persisted = json.loads(
                (ws / ".auditooor" / "completeness_matrix.json").read_text())
            self.assertNotIn("SENTINEL-ON-DISK-MATRIX", persisted.get("reasons", []),
                             "env-unset must rebuild (not adopt) the on-disk matrix")

    def test_env_set_prefers_on_disk_matrix(self) -> None:
        """Opt-in (AUDITOOOR_PREHUNT_MATRIX=1): the reader must adopt the on-disk
        matrix the pre-hunt step produced instead of rebuilding it."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Use a verdict that build_matrix would NOT naturally produce here so
            # adoption is observable. An empty ws builds to "complete"; craft the
            # on-disk verdict to a distinct incomplete value + a value-moving
            # unenumerated worklist row so preference is detectable via the detail.
            (ws / ".auditooor").mkdir(parents=True)
            disk = {
                "schema": "auditooor.completeness_matrix.v1",
                "ws": str(ws), "verdict": "incomplete",
                "denominators": {"assets": 1, "functions": 1,
                                 "invariant_categories": 10, "impact_classes": 1},
                "cells": {"total": 1, "terminal": 0, "open": 0, "not_enumerated": 1},
                "assets": [], "not_enumerated_assets": [],
                "reasons": ["SENTINEL-ON-DISK-MATRIX"],
                "enumeration_worklist": [
                    {"axis": "function", "asset": "Z", "function": "z",
                     "file": "src/Z.sol", "impact_category": "value-movement",
                     "status": "not-enumerated", "cell_kind": "value_moving",
                     "action": "x", "reason": "y"}],
            }
            (ws / ".auditooor" / "completeness_matrix.json").write_text(
                json.dumps(disk, indent=2) + "\n", encoding="utf-8")
            os.environ["AUDITOOOR_PREHUNT_MATRIX"] = "1"
            try:
                res = self.acc.check_completeness_matrix(ws)
            finally:
                os.environ.pop("AUDITOOOR_PREHUNT_MATRIX", None)
            # Adoption is observable: the on-disk file is UNCHANGED (the reader did
            # not overwrite it with a fresh build), so the sentinel survives.
            persisted = json.loads(
                (ws / ".auditooor" / "completeness_matrix.json").read_text())
            self.assertIn("SENTINEL-ON-DISK-MATRIX", persisted.get("reasons", []),
                          "env-set must adopt the on-disk matrix (not rebuild it)")

    def test_env_set_but_missing_file_falls_back_to_build(self) -> None:
        """Opt-in but NO on-disk matrix: the reader must fall back to a fresh
        build (never crash)."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            os.environ["AUDITOOOR_PREHUNT_MATRIX"] = "1"
            try:
                res = self.acc.check_completeness_matrix(ws)
            finally:
                os.environ.pop("AUDITOOOR_PREHUNT_MATRIX", None)
            self.assertTrue((ws / ".auditooor" / "completeness_matrix.json").is_file(),
                            "fallback build must still persist a matrix")


if __name__ == "__main__":
    unittest.main()
