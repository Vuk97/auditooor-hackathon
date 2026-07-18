#!/usr/bin/env python3
"""Regression G1 (2026-06-27): invariant-fuzz-completeness must not fail-open to
honest-0. Before: any Solidity ws with no RECON-NAMED harness got
pass-no-invariant-harness (a clean PASS), and core-coverage defers the 'must
fuzz' obligation here -> honest-0 with ZERO coverage-guided fuzzing. Fix: (1)
detect harnesses by CONTENT (any .sol with a property_/echidna_/invariant_ fn),
not just CryticTester/Properties/CryticToFoundry filenames; (2) no-harness +
in-scope Solidity source = a GAP (fail under AUDITOOOR_INVARIANT_FUZZ_ENFORCE=1,
loud-WARN pass by default); no Solidity source = genuine advisory pass."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "invariant-fuzz-completeness.py"
_s = importlib.util.spec_from_file_location("ifc_sg", _T)
ifc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(ifc)


class InvariantFuzzSourceGuardTest(unittest.TestCase):
    def test_content_based_harness_discovery(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            h = w / "chimera_harnesses" / "X"
            h.mkdir(parents=True)
            # non-Recon filename, but has an invariant_ fn -> must be detected
            (h / "MyEconomicInvariant.t.sol").write_text(
                "contract T{function invariant_conservation() public {}}", encoding="utf-8")
            dirs = ifc._find_harness_dirs(w)
            self.assertEqual(len(dirs), 1)
            self.assertEqual(dirs[0].name, "X")

    def test_no_solidity_source_is_advisory_pass(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            w.mkdir()
            self.assertEqual(ifc.evaluate(w)["verdict"], "pass-no-solidity-source")

    def test_source_no_harness_warns_by_default(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            (w / "src").mkdir(parents=True)
            (w / "src" / "A.sol").write_text("contract A{function f() external{}}", encoding="utf-8")
            r = ifc.evaluate(w)
            self.assertEqual(r["verdict"], "pass-no-invariant-harness")
            self.assertIn("WARN", r["reason"])

    def test_source_no_harness_fails_under_enforce(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            (w / "src").mkdir(parents=True)
            (w / "src" / "A.sol").write_text("contract A{function f() external{}}", encoding="utf-8")
            os.environ["AUDITOOOR_INVARIANT_FUZZ_ENFORCE"] = "1"
            try:
                self.assertEqual(ifc.evaluate(w)["verdict"], "fail-invariant-fuzz-incomplete")
            finally:
                del os.environ["AUDITOOOR_INVARIANT_FUZZ_ENFORCE"]

    def test_rebuttal_greens_no_harness(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            (w / "src").mkdir(parents=True)
            (w / "src" / "A.sol").write_text("contract A{function f() external{}}", encoding="utf-8")
            (w / ".auditooor").mkdir()
            (w / ".auditooor" / "invariant_fuzz_rebuttal.md").write_text(
                "<!-- invariant-fuzz-rebuttal: pure factory ws, no stateful invariants -->", encoding="utf-8")
            os.environ["AUDITOOOR_INVARIANT_FUZZ_ENFORCE"] = "1"
            try:
                self.assertEqual(ifc.evaluate(w)["verdict"], "pass-no-invariant-harness")
            finally:
                del os.environ["AUDITOOOR_INVARIANT_FUZZ_ENFORCE"]


if __name__ == "__main__":
    unittest.main()
