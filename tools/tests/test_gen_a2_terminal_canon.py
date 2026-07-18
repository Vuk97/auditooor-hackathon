#!/usr/bin/env python3
"""Non-vacuous tests for GEN-A2 traversal terminal-state canonicalization screen.

Every positive case has a paired negative (the SAME walk-verify WITH the terminal-
condition assertion) that must NOT fire - proving the terminal-guard predicate is
load-bearing, not a shape match. Includes the real-fleet mutation witness on the
fx-portal Merkle.checkMembership loop (bounded `computedHash == rootHash` original
silent, root-comparison-dropped copy fires).
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL = TOOLS / "traversal-terminal-canonicalization-screen.py"

_spec = importlib.util.spec_from_file_location("tc_screen", TOOL)
tc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tc)


def _scan(text, name):
    return tc.scan_file(Path(name), name, file_text=text)


def _kinds(rows):
    return {r["pattern_id"] for r in rows}


class SolidityMerkleAcceptTests(unittest.TestCase):
    def test_merkle_verify_no_root_check_fires(self):
        # walk over proof, return true, NO `== root` terminal comparison.
        src = """
        library L {
            function verify(bytes32[] memory proof, bytes32 leaf) internal pure returns (bool) {
                bytes32 computed = leaf;
                for (uint256 i = 0; i < proof.length; i++) {
                    computed = keccak256(abi.encodePacked(computed, proof[i]));
                }
                return true;
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertIn("S_WALK_ACCEPT_NO_TERMINAL", _kinds(rows))
        r = [x for x in rows if x["pattern_id"] == "S_WALK_ACCEPT_NO_TERMINAL"][0]
        self.assertEqual(r["missing_assertion"], "canonical-terminal")

    def test_merkle_verify_with_root_check_silent(self):
        # SAME walk WITH the `computed == root` terminal comparison - must NOT fire.
        src = """
        library L {
            function verify(bytes32[] memory proof, bytes32 leaf, bytes32 root) internal pure returns (bool) {
                bytes32 computed = leaf;
                for (uint256 i = 0; i < proof.length; i++) {
                    computed = keccak256(abi.encodePacked(computed, proof[i]));
                }
                return computed == root;
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertNotIn("S_WALK_ACCEPT_NO_TERMINAL", _kinds(rows))

    def test_return_true_after_root_require_silent(self):
        # a `return true` still guarded by a root require dominating - must NOT fire.
        src = """
        library L {
            function verify(bytes32[] memory proof, bytes32 leaf, bytes32 root) internal pure returns (bool ok) {
                bytes32 computed = leaf;
                for (uint256 i = 0; i < proof.length; i++) {
                    computed = keccak256(abi.encodePacked(computed, proof[i]));
                }
                require(computed == root, "bad proof");
                return true;
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertNotIn("S_WALK_ACCEPT_NO_TERMINAL", _kinds(rows))

    def test_non_walk_loop_returning_true_silent(self):
        # a plain loop with no proof/signer walk-noun must NOT be treated as a
        # walk-verify even though it returns true.
        src = """
        contract C {
            function anyZero(uint256[] memory xs) internal pure returns (bool) {
                for (uint256 i = 0; i < xs.length; i++) {
                    if (xs[i] == 0) return true;
                }
                return false;
            }
        }
        """
        rows = _scan(src, "C.sol")
        self.assertEqual(rows, [])


class SolidityMidwalkValueTests(unittest.TestCase):
    def test_midwalk_node_return_fires(self):
        # a verify-intent fn that surfaces a per-iteration proof element as the
        # trusted result with no terminal guard.
        src = """
        library L {
            function verifyPath(bytes[] memory parentNodes, uint256 idx) internal pure returns (bytes memory) {
                for (uint256 i = 0; i < parentNodes.length; i++) {
                    if (i == idx) {
                        return parentNodes[i];
                    }
                }
                return parentNodes[0];
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertIn("S_MIDWALK_VALUE_RETURN", _kinds(rows))

    def test_midwalk_return_with_leaf_flag_silent(self):
        # SAME walk WITH an isLeaf terminal flag - must NOT fire.
        src = """
        library L {
            function verifyPath(bytes[] memory parentNodes, uint256 idx) internal pure returns (bytes memory) {
                for (uint256 i = 0; i < parentNodes.length; i++) {
                    if (isLeaf(parentNodes[i])) {
                        return parentNodes[i];
                    }
                }
                return parentNodes[0];
            }
        }
        """
        rows = _scan(src, "L.sol")
        self.assertNotIn("S_MIDWALK_VALUE_RETURN", _kinds(rows))


class GoValidatorThresholdTests(unittest.TestCase):
    def test_validator_accumulation_no_threshold_fires(self):
        # accumulate over validators, return true, NO quorum/threshold check.
        src = """
        package p
        func verifyCommit(validators []Validator, sigs []Signature) bool {
            for i := 0; i < len(validators); i++ {
                if !validators[i].Verify(sigs[i]) {
                    return false
                }
            }
            return true
        }
        """
        rows = _scan(src, "commit.go")
        self.assertIn("G_WALK_ACCEPT_NO_TERMINAL", _kinds(rows))

    def test_validator_accumulation_with_threshold_silent(self):
        # SAME accumulation WITH a voting-power >= threshold terminal - must NOT fire.
        src = """
        package p
        func verifyCommit(validators []Validator, sigs []Signature) bool {
            var tallied int64
            for i := 0; i < len(validators); i++ {
                if validators[i].Verify(sigs[i]) {
                    tallied += validators[i].VotingPower
                }
            }
            return tallied >= threshold
        }
        """
        rows = _scan(src, "commit.go")
        self.assertNotIn("G_WALK_ACCEPT_NO_TERMINAL", _kinds(rows))

    def test_error_return_over_signers_not_midwalk(self):
        # an error return referencing a walk-noun must NOT be a mid-walk value trust.
        src = """
        package p
        func verifySigners(signers []Addr) error {
            for i := 0; i < len(signers); i++ {
                if signers[i].Bad() {
                    return fmt.Errorf("bad signer %d: %v", i, signers[i])
                }
            }
            return nil
        }
        """
        rows = _scan(src, "s.go")
        self.assertNotIn("G_MIDWALK_VALUE_RETURN", _kinds(rows))


class ExclusionTests(unittest.TestCase):
    def test_codegen_marker_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "src"
            root.mkdir()
            gen = root / "x.pb.go"
            gen.write_text(
                "// Code generated by protoc. DO NOT EDIT.\n"
                "package p\n"
                "func verifyProof(proof [][]byte) bool {\n"
                "  for i := 0; i < len(proof); i++ { _ = proof[i] }\n"
                "  return true\n}\n")
            rows = tc.scan_tree(root, workspace=Path(td))
            self.assertEqual(rows, [])


class MutationWitnessTests(unittest.TestCase):
    """Real-fleet non-vacuity witness on the fx-portal Merkle.checkMembership loop.

    The benign original walks the proof and accepts via `computedHash == rootHash`
    (the canonical-terminal assertion) -> must stay SILENT. Weakening the accept
    to an unconditional `return true` (dropping the root comparison) -> the screen
    must newly flag it.
    """

    MERKLE = Path(
        "/Users/wolf/audits/lido/src/aave-delivery-infrastructure/lib/"
        "fx-portal/contracts/lib/Merkle.sol")

    def test_real_bounded_original_silent_weakened_fires(self):
        if not self.MERKLE.exists():
            self.skipTest("fx-portal Merkle.sol not present")
        orig = self.MERKLE.read_text()
        rows0 = tc.scan_file(self.MERKLE, self.MERKLE.name, file_text=orig)
        self.assertNotIn("S_WALK_ACCEPT_NO_TERMINAL", _kinds(rows0),
                         "benign original (== rootHash) should stay silent")
        weak = orig.replace("return computedHash == rootHash;", "return true;")
        self.assertNotEqual(weak, orig, "mutation did not change source")
        rows1 = tc.scan_file(self.MERKLE, self.MERKLE.name, file_text=weak)
        fired = [r for r in rows1
                 if r["pattern_id"] == "S_WALK_ACCEPT_NO_TERMINAL"]
        self.assertTrue(fired, "weakened Merkle.checkMembership did not fire")


class CliTests(unittest.TestCase):
    _SRC = (
        "library L {\n"
        "    function verify(bytes32[] memory proof, bytes32 leaf) internal pure returns (bool) {\n"
        "        bytes32 c = leaf;\n"
        "        for (uint256 i = 0; i < proof.length; i++) { c = keccak256(abi.encodePacked(c, proof[i])); }\n"
        "        return true;\n"
        "    }\n"
        "}\n")

    def test_cli_source_mode_and_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(self._SRC)
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            summ = json.loads(r.stdout)
            self.assertEqual(summ["schema"], tc.HYP_SCHEMA)
            self.assertGreaterEqual(summ["fired"], 1)
            side = (Path(td) / ".auditooor"
                    / "terminal_canonicalization_hypotheses.jsonl")
            self.assertTrue(side.exists())

    def test_cli_strict_exit1_on_fire(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            src.mkdir()
            (src / "a.sol").write_text(self._SRC)
            r = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", td, "--strict"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
