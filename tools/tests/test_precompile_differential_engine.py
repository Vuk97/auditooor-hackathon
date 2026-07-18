#!/usr/bin/env python3
"""Tests for tools/audit/precompile-differential-engine.py (W4.11).

Stdlib-only. Builds a synthetic two-tree fixture in a tempdir: an upstream
`revm`-shaped Rust tree and a Base/Azul fork that:
  - adds a secp256r1 / p256 precompile at 0x100 (precompile-added),
  - changes the gas marker of the modexp precompile (security-relevant),
  - changes the hardfork activation gate of the clz path (security-relevant),
  - leaves the ecrecover precompile identical.
Also stages two differential test input fixtures (one base_specific row that
SHOULD diverge, one positive_control row that should NOT) and asserts the
input cross-check produces correct verdicts.

Coverage:
  1.  Schema is auditooor.precompile_differential_report.v1.
  2.  upstream/fork precompile counts are reported.
  3.  Fork-added precompile is classified precompile-added.
  4.  Gas-marker change is classified security-relevant.
  5.  Hardfork-gate change is classified security-relevant.
  6.  Identical precompile is counted but NOT in divergences list.
  7.  divergences sorted security-relevant first.
  8.  summary.security_relevant_count matches.
  9.  diverged_delta_targets resolves secp256r1 + clz.
  10. base_specific input row whose target diverged -> CONSISTENT.
  11. base_specific input row whose target did NOT diverge -> MISSING-DIVERGENCE.
  12. positive_control input row with no divergence -> CONSISTENT.
  13. --strict exits 2 when a security-relevant divergence exists.
  14. non-strict exits 0.
  15. --out writes a JSON file.
  16. bad --upstream path exits 1.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_ENGINE = _TOOLS / "audit" / "precompile-differential-engine.py"


def _load_engine():
    spec = importlib.util.spec_from_file_location("_pc_diff_engine", _ENGINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# Synthetic two-tree fixture (upstream revm-shaped vs Base/Azul fork).
# --------------------------------------------------------------------------
UPSTREAM_RS = """\
// upstream revm precompile registry
pub fn register_precompiles() {
    let ecrecover_precompile = (0x01, "ecrecover", GAS 3000, SpecId::HOMESTEAD);
    let modexp_precompile = (0x05, "modexp", GAS 200, SpecId::BYZANTIUM);
    let clz_precompile_verify = (0x0b, "clz", GAS 500, OSAKA);
}
"""

# Fork: adds secp256r1 @ 0x100, modexp gas 200 -> 850, clz gate OSAKA -> AZUL.
FORK_RS = """\
// base-azul fork precompile registry
pub fn register_precompiles() {
    let ecrecover_precompile = (0x01, "ecrecover", GAS 3000, SpecId::HOMESTEAD);
    let modexp_precompile = (0x05, "modexp", GAS 850, SpecId::BYZANTIUM);
    let clz_precompile_verify = (0x0b, "clz", GAS 500, AZUL);
    let secp256r1_verify = (0x100, "p256_verify", GAS 3450, AZUL);
}
"""

# Staged differential test inputs.
INPUT_BS_SECP = {
    "row_id": "bs_03_secp256r1_active",
    "category": "base_specific",
    "delta_target": "secp256r1",
    "expected_same_across_revm_and_base": False,
    "notes": "secp256r1 precompile add -> divergence expected.",
}
INPUT_BS_ABR = {
    "row_id": "bs_05_account_balances_root",
    "category": "base_specific",
    "delta_target": "abr",
    "expected_same_across_revm_and_base": False,
    "notes": "ABR removal -> divergence expected but fixture trees lack it.",
}
INPUT_PC_ADD = {
    "row_id": "pc_01_arith_add",
    "category": "positive_control",
    "delta_target": "shared",
    "expected_same_across_revm_and_base": True,
    "notes": "Pure arithmetic positive control.",
}


class TestPrecompileDifferentialEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = _load_engine()
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.upstream = root / "revm"
        cls.fork = root / "base-azul"
        (cls.upstream / "src").mkdir(parents=True)
        (cls.fork / "src").mkdir(parents=True)
        (cls.upstream / "src" / "precompile.rs").write_text(UPSTREAM_RS)
        (cls.fork / "src" / "precompile.rs").write_text(FORK_RS)
        cls.inputs = root / "inputs"
        cls.inputs.mkdir()
        (cls.inputs / "bs_03.json").write_text(json.dumps(INPUT_BS_SECP))
        (cls.inputs / "bs_05.json").write_text(json.dumps(INPUT_BS_ABR))
        (cls.inputs / "pc_01.json").write_text(json.dumps(INPUT_PC_ADD))
        cls.report = cls.engine.build_report(
            cls.upstream, cls.fork, cls.inputs, "deadbeef")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _verdict_for(self, key_substr):
        for d in self.report["divergences"]:
            if key_substr in d["registry_key"]:
                return d["verdict"]
        return None

    def test_01_schema(self):
        self.assertEqual(self.report["schema"],
                         "auditooor.precompile_differential_report.v1")

    def test_02_counts_reported(self):
        s = self.report["summary"]
        self.assertEqual(s["upstream_precompiles"], 3)
        self.assertEqual(s["fork_precompiles"], 4)

    def test_03_added_precompile(self):
        self.assertEqual(self._verdict_for("0x100"), "precompile-added")

    def test_04_gas_change_security_relevant(self):
        self.assertEqual(self._verdict_for("0x05"), "security-relevant")

    def test_05_hardfork_gate_change_security_relevant(self):
        self.assertEqual(self._verdict_for("0x0b"), "security-relevant")

    def test_06_identical_not_in_divergences(self):
        self.assertIsNone(self._verdict_for("0x01"))
        self.assertGreaterEqual(self.report["summary"]["counts"]["identical"], 1)

    def test_07_sorted_security_relevant_first(self):
        verdicts = [d["verdict"] for d in self.report["divergences"]]
        ranks = [self.engine._rank(v) for v in verdicts]
        self.assertEqual(ranks, sorted(ranks))

    def test_08_security_relevant_count(self):
        self.assertEqual(self.report["summary"]["security_relevant_count"], 2)

    def test_09_diverged_targets(self):
        targets = set(self.report["summary"]["diverged_delta_targets"])
        self.assertIn("secp256r1", targets)
        self.assertIn("clz", targets)
        self.assertNotIn("abr", targets)

    def test_10_base_specific_diverged_consistent(self):
        rows = {r["row_id"]: r for r in self.report["input_crosscheck"]}
        self.assertEqual(rows["bs_03_secp256r1_active"]["verdict"], "CONSISTENT")

    def test_11_base_specific_missing_divergence(self):
        rows = {r["row_id"]: r for r in self.report["input_crosscheck"]}
        self.assertEqual(rows["bs_05_account_balances_root"]["verdict"],
                         "MISSING-DIVERGENCE")

    def test_12_positive_control_consistent(self):
        rows = {r["row_id"]: r for r in self.report["input_crosscheck"]}
        self.assertEqual(rows["pc_01_arith_add"]["verdict"], "CONSISTENT")

    def test_13_strict_exits_2(self):
        r = subprocess.run(
            [sys.executable, str(_ENGINE),
             "--upstream", str(self.upstream), "--fork", str(self.fork),
             "--inputs", str(self.inputs), "--strict"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_14_non_strict_exits_0(self):
        r = subprocess.run(
            [sys.executable, str(_ENGINE),
             "--upstream", str(self.upstream), "--fork", str(self.fork),
             "--inputs", str(self.inputs)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)

    def test_15_out_writes_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "nested" / "report.json"
            r = subprocess.run(
                [sys.executable, str(_ENGINE),
                 "--upstream", str(self.upstream), "--fork", str(self.fork),
                 "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertTrue(out.is_file())
            doc = json.loads(out.read_text())
            self.assertEqual(doc["schema"],
                             "auditooor.precompile_differential_report.v1")

    def test_16_bad_upstream_exits_1(self):
        r = subprocess.run(
            [sys.executable, str(_ENGINE),
             "--upstream", "/nonexistent/path/xyz", "--fork", str(self.fork)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
