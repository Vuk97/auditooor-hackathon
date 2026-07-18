#!/usr/bin/env python3
"""E12 inclusion-proof positional-soundness screen - regression + non-vacuity.

Pins tools/inclusion-proof-positional-soundness.py, a GENERAL invariant screen
for non-ZK Merkle/MPT inclusion proofs (north-star w8mv5mpcw): the delegated
trust "recomputed_root == stored_root => membership at the CLAIMED position and
node-type" must UNIQUELY BIND (a) the leaf index and (b) the leaf-vs-internal-
node domain, else a valid proof replays at a forged position / node type.

Two advisory axes: `unbound-index` (per-level ordering not selected by a
position bit) and `node-type-ambiguity` (unbounded depth + no leaf/node domain
tag). Advisory-first: every row verdict == "needs-fuzz"; off-by-default.

Synthetic matrix (embedded Solidity strings - no new fixture files):
  - CLEAN            -> 0 rows  (index-bit ordering + fixed depth).
  - UNBOUND_INDEX    -> 1 row   (fixed depth so domain-bound; NO position bit).
  - NODE_TYPE        -> 1 row   (position-bound; dynamic depth + no domain tag).
  - COMMUTATIVE      -> 0 rows  (sorted-pair SET membership - order-free BY
                                 DESIGN; positional soundness N/A, FP guard).

Mutation-verify (WS=polygon, real agglayer DepositContract.sol, READ-ONLY): the
real position-bound verifier is SILENT; weakening the index-ordering branch on a
mkdtemp COPY (always fold node||sibling) flips it to 1 `unbound-index` row. The
shared workspace file is never mutated in place (asserted byte-identical).

Non-vacuity:
  - neutralise check_position_binding -> True : UNBOUND_INDEX positive 1 -> 0.
  - neutralise check_domain_separation -> True: NODE_TYPE positive 1 -> 0.
  - neutralise _folds_proof_through_hash -> False: EVERY verifier unrecognised,
    the whole matrix collapses to 0 (the enumerator predicate is load-bearing).
"""
from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "inclusion-proof-positional-soundness.py"
POLYGON_TGT = pathlib.Path(
    "/Users/wolf/audits/polygon/src/agglayer-contracts/contracts/lib/"
    "DepositContract.sol")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "e12_inclusion_proof_positional", TOOL_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- embedded fixtures ----------------------------------------------------
CLEAN = """
contract C {
    function verify(bytes32 leaf, bytes32[32] calldata proof, uint256 index, bytes32 root)
        internal pure returns (bool) {
        bytes32 node = leaf;
        for (uint256 h = 0; h < 32; h++) {
            if (((index >> h) & 1) == 1)
                node = keccak256(abi.encodePacked(proof[h], node));
            else
                node = keccak256(abi.encodePacked(node, proof[h]));
        }
        return node == root;
    }
}
"""

UNBOUND_INDEX = """
contract C {
    function verifyInclusion(bytes32 leaf, bytes32[32] calldata proof, bytes32 root)
        internal pure returns (bool) {
        bytes32 node = leaf;
        for (uint256 h = 0; h < 32; h++) {
            node = keccak256(abi.encodePacked(node, proof[h]));
        }
        return node == root;
    }
}
"""

NODE_TYPE = """
contract C {
    function verifyDynamic(bytes32 leaf, bytes32[] calldata proof, uint256 index, bytes32 root)
        internal pure returns (bool) {
        bytes32 node = leaf;
        for (uint256 h = 0; h < proof.length; h++) {
            if (((index >> h) & 1) == 1)
                node = keccak256(abi.encodePacked(proof[h], node));
            else
                node = keccak256(abi.encodePacked(node, proof[h]));
        }
        return node == root;
    }
}
"""

COMMUTATIVE = """
contract C {
    function verifySet(bytes32 leaf, bytes32[] calldata proof, bytes32 root)
        internal pure returns (bool) {
        bytes32 node = leaf;
        for (uint256 h = 0; h < proof.length; h++) {
            bytes32 s = proof[h];
            node = node < s
                ? keccak256(abi.encodePacked(node, s))
                : keccak256(abi.encodePacked(s, node));
        }
        return node == root;
    }
}
"""


class E12ScanMatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def _scan(self, src):
        return self.tool.screen_source(src, "fixture.sol")

    def _axes(self, src):
        return sorted(r["axis"] for r in self._scan(src))

    def test_clean_control_silent(self):
        self.assertEqual(self._scan(CLEAN), [])

    def test_clean_is_recognised_as_a_verifier(self):
        # the control is silent because it is BOUND, not because it was skipped
        for _n, body, _l in self.tool._extract_functions(CLEAN):
            if self.tool.is_inclusion_verifier(body):
                self.assertTrue(self.tool.check_position_binding(body))
                self.assertTrue(self.tool.check_domain_separation(body))
                break
        else:
            self.fail("clean control not recognised as an inclusion verifier")

    def test_unbound_index_fires_single_axis(self):
        rows = self._scan(UNBOUND_INDEX)
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual(r["axis"], "unbound-index")
        self.assertEqual(r["function"], "verifyInclusion")
        self.assertFalse(r["evidence"]["position_bound"])
        self.assertTrue(r["evidence"]["domain_bound"])

    def test_node_type_ambiguity_fires_single_axis(self):
        rows = self._scan(NODE_TYPE)
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual(r["axis"], "node-type-ambiguity")
        self.assertTrue(r["evidence"]["position_bound"])
        self.assertFalse(r["evidence"]["domain_bound"])

    def test_commutative_set_proof_excluded(self):
        # order-free set membership is not a positional proof: FP guard
        self.assertEqual(self._scan(COMMUTATIVE), [])
        for _n, body, _l in self.tool._extract_functions(COMMUTATIVE):
            if self.tool._HASH_CALL.search(body):
                self.assertTrue(self.tool.is_commutative_set_proof(body))

    def test_advisory_first_verdict(self):
        for src in (UNBOUND_INDEX, NODE_TYPE):
            for r in self._scan(src):
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertEqual(r["capability"], "E12")
                self.assertIn("private_invariant", r)
                self.assertIn("attack", r)

    def test_dedup_axes_recorded(self):
        r = self._scan(UNBOUND_INDEX)[0]
        self.assertIn("E3", r["dedup"])
        self.assertIn("E10", r["dedup"])


class E12NonVacuityTest(unittest.TestCase):
    """Neutralising a core predicate must collapse the matching positive."""

    def setUp(self):
        self.tool = _load_tool()

    def test_neutralise_position_predicate_kills_unbound_index(self):
        self.assertEqual(
            len(self.tool.screen_source(UNBOUND_INDEX, "f.sol")), 1)
        self.tool.check_position_binding = lambda body: True
        self.assertEqual(self.tool.screen_source(UNBOUND_INDEX, "f.sol"), [])

    def test_neutralise_domain_predicate_kills_node_type(self):
        self.assertEqual(
            len(self.tool.screen_source(NODE_TYPE, "f.sol")), 1)
        self.tool.check_domain_separation = lambda body: True
        self.assertEqual(self.tool.screen_source(NODE_TYPE, "f.sol"), [])

    def test_neutralise_enumerator_collapses_whole_matrix(self):
        # the fold-through-hash enumerator predicate is load-bearing
        self.assertEqual(
            len(self.tool.screen_source(UNBOUND_INDEX, "f.sol")), 1)
        self.tool._folds_proof_through_hash = lambda body: False
        for src in (CLEAN, UNBOUND_INDEX, NODE_TYPE, COMMUTATIVE):
            self.assertEqual(self.tool.screen_source(src, "f.sol"), [])


@unittest.skipUnless(POLYGON_TGT.is_file(),
                     "polygon fleet source not present")
class E12FleetMutationVerifyTest(unittest.TestCase):
    """SILENT on the real guarded verifier; FIRES only when the position guard
    is weakened on a TEMP COPY. The shared workspace file is never mutated."""

    def setUp(self):
        self.tool = _load_tool()
        self.real = POLYGON_TGT.read_text()

    def test_real_verifier_is_silent(self):
        self.assertEqual(self.tool.screen_source(self.real, str(POLYGON_TGT)),
                         [])

    def test_weakened_copy_fires_unbound_index(self):
        pre = hashlib.sha256(POLYGON_TGT.read_bytes()).hexdigest()
        weakened = self.real.replace(
            "            if (((index >> height) & 1) == 1)\n"
            "                node = keccak256(abi.encodePacked(smtProof[height], node));\n"
            "            else node = keccak256(abi.encodePacked(node, smtProof[height]));",
            "            node = keccak256(abi.encodePacked(node, smtProof[height]));")
        self.assertNotEqual(weakened, self.real,
                            "mutation anchor not found - fixture drifted")
        tmp = pathlib.Path(tempfile.mkdtemp()) / "DepositContract.sol"
        try:
            tmp.write_text(weakened)
            rows = self.tool.screen_source(tmp.read_text(), str(tmp))
            axes = [r["axis"] for r in rows]
            self.assertIn("unbound-index", axes, rows)
            self.assertTrue(any(
                r["axis"] == "unbound-index"
                and r["function"] == "verifyMerkleProof"
                and r["evidence"]["position_bound"] is False for r in rows))
        finally:
            shutil.rmtree(tmp.parent, ignore_errors=True)
        # the shared workspace file must be untouched
        self.assertEqual(hashlib.sha256(POLYGON_TGT.read_bytes()).hexdigest(),
                         pre)


if __name__ == "__main__":
    unittest.main()
