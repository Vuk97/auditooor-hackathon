#!/usr/bin/env python3
"""test_mech_detectors_reentrancy_storage.py

Enforcement-gap G-4 + G-15 (2026-07-03): the reentrancy/callback surface and the
upgradeable storage-collision surface were never surfaced as mechanism obligations,
so an entire vuln class each could be silently un-hunted while audit-complete reported
0 findings. Two new mechanism detectors make the class APPLICABILITY visible (fire ->
OPEN mechanism cell -> must be dispositioned). Registered ADVISORY-FIRST: skipped
unless AUDITOOOR_MECH_ADVISORY_DETECTORS=1, so no parked audit is retroactively re-opened
until the completeness-matrix mechanism axis is taught to consume them.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / rel)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class TestReentrancyDetector(unittest.TestCase):
    def setUp(self):
        self.d = _load("d_reentr", "detectors/sol_reentrancy_callback_surface.py")

    def _ws(self, sol):
        t = Path(tempfile.mkdtemp())
        (t / "A.sol").write_text(sol, encoding="utf-8")
        return str(t)

    def test_external_call_fires(self):
        r = self.d.scan_root(self._ws('contract A { function f() external { payable(msg.sender).call{value:1}(""); } }'))
        self.assertEqual(len(r["findings"]), 1)

    def test_callback_fires(self):
        r = self.d.scan_root(self._ws('contract A { function onFlashLoan() external returns (bytes32) {} }'))
        self.assertGreaterEqual(len(r["findings"]), 1)

    def test_no_surface_clean(self):
        r = self.d.scan_root(self._ws('contract A { uint x; function g() external { x = 1; } }'))
        self.assertEqual(len(r["findings"]), 0)


class TestStorageCollisionDetector(unittest.TestCase):
    def setUp(self):
        self.d = _load("d_stor", "detectors/sol_upgradeable_storage_collision_surface.py")

    def _ws(self, sol):
        t = Path(tempfile.mkdtemp())
        (t / "B.sol").write_text(sol, encoding="utf-8")
        return str(t)

    def test_upgradeable_fires(self):
        r = self.d.scan_root(self._ws('contract B is UUPSUpgradeable { function _authorizeUpgrade(address) internal override {} }'))
        self.assertEqual(len(r["findings"]), 1)

    def test_non_upgradeable_clean(self):
        r = self.d.scan_root(self._ws('contract B { uint x; }'))
        self.assertEqual(len(r["findings"]), 0)


class TestAdvisoryGating(unittest.TestCase):
    def setUp(self):
        self.m = _load("msr_gate", "mechanism-scan-run.py")

    def test_registered_advisory_first(self):
        names = {row[0]: (row[4] if len(row) > 4 else False) for row in self.m._REGISTRY}
        self.assertIn("sol_reentrancy_callback_surface", names)
        self.assertIn("sol_upgradeable_storage_collision_surface", names)
        self.assertTrue(names["sol_reentrancy_callback_surface"], "must be advisory=True (advisory-first)")
        self.assertTrue(names["sol_upgradeable_storage_collision_surface"], "must be advisory=True")

    def test_default_skips_advisory_detectors(self):
        os.environ.pop("AUDITOOOR_MECH_ADVISORY_DETECTORS", None)
        # a solidity ws with both surfaces present
        t = Path(tempfile.mkdtemp())
        (t / "src").mkdir()
        (t / "src" / "A.sol").write_text(
            'contract A is UUPSUpgradeable { function f() external { payable(msg.sender).call{value:1}(""); } '
            'function _authorizeUpgrade(address) internal override {} }', encoding="utf-8")
        (t / ".auditooor").mkdir()
        r = self.m.run(t)
        skipped_adv = [s for s in r["skipped"] if s["reason"] == "advisory-detector-not-promoted"]
        self.assertEqual(len(skipped_adv), 2, "both advisory detectors skipped by default (zero blast radius)")
        fired = {f["mechanism"] for f in r["fired"]}
        self.assertNotIn("reentrancy-callback-surface", fired)
        self.assertNotIn("storage-collision-upgradeable", fired)

    def test_promoted_runs_advisory_detectors(self):
        os.environ["AUDITOOOR_MECH_ADVISORY_DETECTORS"] = "1"
        try:
            t = Path(tempfile.mkdtemp())
            (t / "src").mkdir()
            (t / "src" / "A.sol").write_text(
                'contract A is UUPSUpgradeable { function f() external { payable(msg.sender).call{value:1}(""); } '
                'function _authorizeUpgrade(address) internal override {} }', encoding="utf-8")
            (t / ".auditooor").mkdir()
            r = self.m.run(t)
            fired = {f["mechanism"] for f in r["fired"]}
            self.assertIn("reentrancy-callback-surface", fired)
            self.assertIn("storage-collision-upgradeable", fired)
        finally:
            os.environ.pop("AUDITOOOR_MECH_ADVISORY_DETECTORS", None)


if __name__ == "__main__":
    unittest.main()
