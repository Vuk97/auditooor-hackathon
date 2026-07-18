#!/usr/bin/env python3
"""Tests for tools/pr9-novel-vector-0day-demo.py.

These cover the pure stages (parse real surface, author real-wired harness,
parse forge output, 0-day adjudication, headline) without requiring forge so
the suite is fast + deterministic. An optional end-to-end test runs only when
forge + a forge-std lib are resolvable.
"""
import importlib.util
import json
import shutil
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = REPO_ROOT / "tools" / "pr9-novel-vector-0day-demo.py"

spec = importlib.util.spec_from_file_location("pr9_demo", TOOL)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


CONTRACT_SRC = """// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;
contract MidnightBundles {
    uint256 public totalPulled;
    uint256 public totalPushed;
    uint256 public feesAccrued;
    uint256 public residual;
    uint256 public custodyHeld;
    uint256 public userBalanceSum;
    function approveBundler(address s, uint256 a) external { }
    function erc20TransferFrom(address o, uint256 a) external { }
    function balanceOfBundle() external view returns (uint256) { return 0; }
}
"""


class TestParseRealSurface(unittest.TestCase):
    def setUp(self):
        self.tmp = REPO_ROOT / "tools" / "tests" / "_pr9_tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.cpath = self.tmp / "MidnightBundles.sol"
        self.cpath.write_text(CONTRACT_SRC)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parses_name_views_scalars(self):
        surf = mod.parse_real_surface(self.cpath)
        self.assertEqual(surf["name"], "MidnightBundles")
        self.assertIn("balanceOfBundle", surf["views"])
        for s in ("totalPulled", "totalPushed", "feesAccrued", "custodyHeld", "userBalanceSum", "residual"):
            self.assertIn(s, surf["public_scalars"])

    def test_mutating_external_excludes_view(self):
        surf = mod.parse_real_surface(self.cpath)
        self.assertIn("approveBundler", surf["mutating_external"])
        self.assertIn("erc20TransferFrom", surf["mutating_external"])
        self.assertNotIn("balanceOfBundle", surf["mutating_external"])


class TestAuthorRealWiredHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = REPO_ROOT / "tools" / "tests" / "_pr9_tmp2"
        self.cpath = self.tmp / "MidnightBundles.sol"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.cpath.write_text(CONTRACT_SRC)
        self.out = self.tmp / "out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_emits_wireable_families_only(self):
        surf = mod.parse_real_surface(self.cpath)
        fams = {"conservation", "custody", "bounds", "soundness", "authorization"}
        h = mod.author_real_wired_harness(self.out, self.cpath, surf, fams)
        emitted_fams = {e["family"] for e in h["emitted"]}
        # all four real-view families wire because the scalars exist
        self.assertEqual(emitted_fams, {"conservation", "custody", "bounds", "soundness"})
        # authorization has no real-view assertion template -> not emitted, not asserted-true
        self.assertNotIn("authorization", emitted_fams)

    def test_unwireable_reported_when_view_missing(self):
        # contract lacking custody scalars
        src = CONTRACT_SRC.replace("    uint256 public custodyHeld;\n", "").replace(
            "    uint256 public userBalanceSum;\n", ""
        )
        self.cpath.write_text(src)
        surf = mod.parse_real_surface(self.cpath)
        h = mod.author_real_wired_harness(self.out, self.cpath, surf, {"custody"})
        self.assertEqual(h["emitted"], [])
        self.assertEqual(len(h["unwireable"]), 1)
        self.assertEqual(h["unwireable"][0]["family"], "custody")

    def test_real_contract_copied_and_imported(self):
        surf = mod.parse_real_surface(self.cpath)
        h = mod.author_real_wired_harness(self.out, self.cpath, surf, {"conservation"})
        test_txt = Path(h["test_path"]).read_text()
        # the harness imports + instantiates the REAL contract (not a model)
        self.assertIn('import "../src/MidnightBundles.sol"', test_txt)
        self.assertIn("new MidnightBundles()", test_txt)
        self.assertIn("c.totalPulled()", test_txt)
        # real contract source copied verbatim
        self.assertTrue(Path(h["contract_copy"]).exists())


class TestParseForge(unittest.TestCase):
    def test_pass_and_fail(self):
        out = (
            "[PASS] invariant_bounds() (runs: 256)\n"
            "[FAIL: custody: REAL-contract spec violated]\n"
            "[PASS] invariant_conservation() (runs: 256)\n"
            "[FAIL] invariant_custody() (runs: 256)\n"
        )
        res = mod._parse_forge_invariants(out)
        self.assertEqual(res["invariant_bounds"], "PASS")
        self.assertEqual(res["invariant_conservation"], "PASS")
        self.assertEqual(res["invariant_custody"], "VIOLATED")

    def test_fail_bracket_reason_form(self):
        # the real forge invariant-failure shape with NO fn in [FAIL] brackets
        out = (
            "[PASS] invariant_bounds() (runs: 128, calls: 4096, reverts: 0)\n"
            "[FAIL: custody: REAL-contract spec violated]\n"
            "[PASS] invariant_soundness() (runs: 128, calls: 4096, reverts: 0)\n"
        )
        res = mod._parse_forge_invariants(out)
        self.assertEqual(res["invariant_bounds"], "PASS")
        self.assertEqual(res["invariant_soundness"], "PASS")
        self.assertEqual(res["invariant_custody"], "VIOLATED")

    def test_json_failure_event_form(self):
        out = '{"timestamp":1,"event":"failure","invariant":"invariant_custody","reason":"x"}\n'
        res = mod._parse_forge_invariants(out)
        self.assertEqual(res["invariant_custody"], "VIOLATED")


class TestAdjudicate0Day(unittest.TestCase):
    def test_violation_with_no_detector_is_0day(self):
        forge = {"invariant_custody": "VIOLATED", "invariant_bounds": "PASS"}
        dets = {"detector_count": 0, "detector_checks": [], "scanned_files": []}
        adj = mod.adjudicate_0day(forge, dets)
        self.assertEqual(len(adj), 1)
        self.assertTrue(adj[0]["true_0day_candidate"])
        self.assertFalse(adj[0]["pre_existing_detector_match"])

    def test_violation_with_detectors_present_not_flagged_0day(self):
        forge = {"invariant_custody": "VIOLATED"}
        dets = {"detector_count": 3, "detector_checks": ["reentrancy-eth"], "scanned_files": ["x"]}
        adj = mod.adjudicate_0day(forge, dets)
        self.assertFalse(adj[0]["true_0day_candidate"])
        self.assertTrue(adj[0]["pre_existing_detector_match"])

    def test_no_violations_empty_adjudication(self):
        forge = {"invariant_custody": "PASS", "invariant_bounds": "PASS"}
        dets = {"detector_count": 0, "detector_checks": [], "scanned_files": []}
        self.assertEqual(mod.adjudicate_0day(forge, dets), [])


class TestHeadline(unittest.TestCase):
    def test_no_invariants(self):
        self.assertIn("no invariants derived", mod._headline(0, False, False, 0, 0))

    def test_honest_negative(self):
        h = mod._headline(15, True, True, 0, 0)
        self.assertIn("0 counterexamples", h)
        self.assertIn("HELD", h)

    def test_0day_found(self):
        h = mod._headline(15, True, True, 1, 1)
        self.assertIn("VIOLATED", h)
        self.assertIn("true-0-day", h)


class TestLoadDetectors(unittest.TestCase):
    def setUp(self):
        self.tmp = REPO_ROOT / "tools" / "tests" / "_pr9_dets"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_detector_set(self):
        (self.tmp / "slither_results.json").write_text(json.dumps({"results": {"detectors": []}}))
        d = mod.load_pre_existing_detectors(self.tmp, None)
        self.assertEqual(d["detector_count"], 0)

    def test_counts_detectors(self):
        (self.tmp / "slither_results.json").write_text(
            json.dumps({"results": {"detectors": [{"check": "reentrancy-eth"}, {"check": "arbitrary-send"}]}})
        )
        d = mod.load_pre_existing_detectors(self.tmp, None)
        self.assertEqual(d["detector_count"], 2)
        self.assertIn("reentrancy-eth", d["detector_checks"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
