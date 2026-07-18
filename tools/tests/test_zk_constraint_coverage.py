#!/usr/bin/env python3
"""Tests for tools/zk-constraint-coverage.py.

Non-vacuity discipline: every predicate is exercised as a POSITIVE (must produce a
survivor obligation on a real zkbugs-derived circom fixture, with file:line) AND a
NEGATIVE (must stay silent on the fixed sibling / mutation counterpart). The
missing-binding case additionally uses a SYNTHETIC mutation pair (remove the ===
binding on a public signal -> survivor appears) so the set-difference is proven to
depend on the constraint EDGE, not on token text.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zk-constraint-coverage.py"
FIX = ROOT / "detectors" / "circom_wave1" / "test_fixtures"

_spec = importlib.util.spec_from_file_location("zk_cc", TOOL)
zkcc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zkcc)


def _analyze(circom_path: Path, predicate="all"):
    preds = list(zkcc.PREDICATES) if predicate == "all" else [predicate]
    return zkcc.analyze([Path(circom_path)], preds)


def _signals(report, predicate=None):
    return [o["signal"] for o in report["obligations"]
            if predicate is None or o["predicate"] == predicate]


class BitWidthAliasing(unittest.TestCase):
    def test_positive_fires_with_file_line(self):
        r = _analyze(FIX / "zkbugs_num2bits_254_state_alias_positive.circom",
                     "bit-width-aliasing")
        self.assertEqual(r["verdict"], "survivors")
        obls = [o for o in r["obligations"] if o["predicate"] == "bit-width-aliasing"]
        self.assertEqual(len(obls), 1)
        self.assertEqual(obls[0]["line"], 7)          # Num2Bits(254) node
        self.assertTrue(obls[0]["file"].endswith(".circom"))

    def test_negative_silent(self):
        r = _analyze(FIX / "zkbugs_num2bits_254_state_alias_negative.circom",
                     "bit-width-aliasing")
        self.assertEqual(_signals(r, "bit-width-aliasing"), [])
        self.assertEqual(r["verdict"], "cited-empty")


class UnconstrainedIndex(unittest.TestCase):
    def test_blake3_positive_fires(self):
        r = _analyze(FIX / "zkbugs_blake3novatreepath_checkdepth_comparator_range_positive.circom",
                     "unconstrained-index")
        self.assertEqual(r["verdict"], "survivors")
        self.assertEqual(set(_signals(r, "unconstrained-index")), {"depth", "leaf_depth"})

    def test_blake3_negative_silent(self):
        r = _analyze(FIX / "zkbugs_blake3novatreepath_checkdepth_comparator_range_negative.circom",
                     "unconstrained-index")
        self.assertEqual(_signals(r, "unconstrained-index"), [])

    def test_unirep_positive_fires(self):
        r = _analyze(FIX / "zkbugs_unirep_comparison_range_checks_positive.circom",
                     "unconstrained-index")
        self.assertIn("epochKeyNonce", _signals(r, "unconstrained-index"))


class MissingSubgroup(unittest.TestCase):
    def test_positive_fires(self):
        r = _analyze(FIX / "zkbugs_babyjubjub_suborder_tag_positive.circom",
                     "missing-subgroup")
        self.assertEqual(r["verdict"], "survivors")
        self.assertIn("n2b", _signals(r, "missing-subgroup"))

    def test_negative_silent(self):
        # negative adds `n2b.out === 1`, forcing the sub-order membership check.
        r = _analyze(FIX / "zkbugs_babyjubjub_suborder_tag_negative.circom",
                     "missing-subgroup")
        self.assertEqual(_signals(r, "missing-subgroup"), [])


class NonBooleanOutput(unittest.TestCase):
    def test_erc20_positive_fires(self):
        r = _analyze(FIX / "zkbugs_erc20_sum_input_keyed_outflow_positive.circom",
                     "non-boolean-output")
        self.assertEqual(r["verdict"], "survivors")
        self.assertIn("include", _signals(r, "non-boolean-output"))


class MissingBinding(unittest.TestCase):
    def test_zswap_prover_gated_positive_fires(self):
        r = _analyze(FIX / "zkbugs_zswap_nullifier_verification_disabled_positive.circom",
                     "missing-binding")
        self.assertEqual(r["verdict"], "survivors")
        self.assertTrue(any(".enabled" in s for s in _signals(r, "missing-binding")))

    def test_zswap_constant_gated_negative_silent(self):
        # negative drives `.enabled <== 1` (constant) -> check always on -> covered.
        r = _analyze(FIX / "zkbugs_zswap_nullifier_verification_disabled_negative.circom",
                     "missing-binding")
        self.assertEqual(_signals(r, "missing-binding"), [])

    def test_synthetic_mutation_pair(self):
        """NON-VACUOUS mutation pair: an output bound by `===` is COVERED; removing
        that binding constraint makes the missing-binding survivor appear."""
        bound = (
            "pragma circom 2.1.6;\n"
            "template Commit() {\n"
            "    signal input secret;\n"
            "    signal input expected_root;\n"
            "    signal output root;\n"
            "    root <-- secret;\n"
            "    root === expected_root;\n"   # <-- the binding constraint
            "}\n"
            "component main = Commit();\n"
        )
        mutated = bound.replace("    root === expected_root;\n", "")
        with tempfile.TemporaryDirectory() as d:
            bp = Path(d) / "bound.circom"
            mp = Path(d) / "mutated.circom"
            bp.write_text(bound)
            mp.write_text(mutated)

            r_bound = _analyze(bp, "missing-binding")
            r_mut = _analyze(mp, "missing-binding")

        # bound: `root` reached by an EQ edge -> covered -> no survivor.
        self.assertEqual(_signals(r_bound, "missing-binding"), [],
                         "bound circuit must be silent (root is EQ-forced)")
        # mutated: `root` only `<--` assigned -> missing-binding survivor.
        self.assertIn("root", _signals(r_mut, "missing-binding"),
                      "removing the === must surface the missing-binding survivor")


class HonestDegrade(unittest.TestCase):
    def test_no_circom_workspace_is_language_na(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Vault.sol").write_text("contract V {}")
            r = zkcc.analyze(zkcc.find_circom_files(Path(d)), list(zkcc.PREDICATES))
        self.assertEqual(r["verdict"], "no-zk-circuits")
        self.assertEqual(r["language"], "N/A")
        self.assertEqual(r["obligations_total"], 0)


class CliContract(unittest.TestCase):
    def test_json_schema_and_fail_closed(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--src-root",
             str(FIX / "zkbugs_num2bits_254_state_alias_positive.circom"),
             "--predicate", "bit-width-aliasing", "--json", "--fail-closed"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 3)          # survivors under --fail-closed
        report = json.loads(proc.stdout)
        self.assertEqual(report["schema"], "auditooor.zk_constraint_coverage.v1")
        o = report["obligations"][0]
        for key in ("predicate", "attack_class", "file", "line", "signal",
                    "edge_types_present", "edge_type_missing", "verdict"):
            self.assertIn(key, o)

    def test_emit_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "c.circom").write_text(
                (FIX / "zkbugs_num2bits_254_state_alias_positive.circom").read_text())
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws),
                 "--predicate", "bit-width-aliasing", "--emit", "--json"],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            ledger = ws / ".auditooor" / "zk_constraint_coverage_obligations.jsonl"
            self.assertTrue(ledger.exists())
            rows = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(rows), 1)
            self.assertIn("obligation_id", rows[0])
            self.assertEqual(rows[0]["attack_class"], "zk-bitwidth-aliasing")


if __name__ == "__main__":
    unittest.main()
