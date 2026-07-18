#!/usr/bin/env python3
"""Tests for tools/zk-verifier-bugclass-checklist.py.

Calibration fixtures use real lines from:
  /Users/wolf/audits/aztec/external/aztec-packages/barretenberg/sol/src/honk/BaseHonkVerifier.sol
  /Users/wolf/audits/aztec/external/aztec-packages/barretenberg/sol/src/honk/BaseZKHonkVerifier.sol
  /Users/wolf/audits/aztec/external/aztec-packages/barretenberg/sol/src/honk/CommitmentScheme.sol
  /Users/wolf/audits/aztec/external/aztec-packages/barretenberg/sol/src/honk/Transcript.sol
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "zk-verifier-bugclass-checklist.py"


def _load():
    spec = importlib.util.spec_from_file_location("zk_vbc_test_mod", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkVerifierBugclassChecklistTest(unittest.TestCase):
    """Unit tests covering the 8 bug-class predicates and CLI behaviour."""

    def setUp(self):
        self.mod = _load()

    # ------------------------------------------------------------------
    # Positive fixture: BaseHonkVerifier-like file triggers multiple classes
    # ------------------------------------------------------------------
    HONK_VERIFIER_FIXTURE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./Transcript.sol";
import "./CommitmentScheme.sol";
contract BaseHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        HonkTranscript memory transcript;
        transcript = transcriptInit(publicInputs);
        Fr eta = transcript.getChallenge();
        (bool valid,) = batchMul(proof);
        require(valid);
        return true;
    }
    function batchMul(bytes calldata proof) internal view returns (bool, Fr) {
        // staticcall(gas(), 7, ...)
        (bool ok,) = address(0x7).staticcall(abi.encode(proof));
        return (ok, Fr.wrap(0));
    }
    function getChallenge() internal pure returns (Fr) {
        return Fr.wrap(1);
    }
    function publicInputDelta(Fr[] memory inputs) internal pure returns (Fr) {
        return inputs[0];
    }
    function verifySumcheck(Fr[] memory rounds) internal pure returns (bool) {
        return rounds.length > 0;
    }
    function verifyShplemini(Fr r, Fr[] memory evals) internal pure returns (bool) {
        return evals.length > 0;
    }
}
"""

    # Negative fixture: a plain ERC20 contract that should NOT trigger
    NEGATIVE_FIXTURE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amt) external returns (bool) {
        balances[msg.sender] -= amt;
        balances[to] += amt;
        return true;
    }
}
"""

    def _write_sol(self, tmp: Path, name: str, content: str) -> Path:
        p = tmp / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_honk_verifier_triggers_multiple_classes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write_sol(tmp, "BaseHonkVerifier.sol", self.HONK_VERIFIER_FIXTURE)
            queue = self.mod.build_queue(tmp)
            self.assertGreater(len(queue), 3,
                "Expected multiple bug-class predicates from BaseHonkVerifier fixture")
            classes_found = {item["bug_class"] for item in queue}
            # At minimum these three must fire
            for expected in [
                "curve-membership-check",
                "public-input-delta-fiat-shamir-binding",
                "shplemini-opening-proof-binding",
            ]:
                self.assertIn(expected, classes_found,
                    f"{expected} should be in queue for BaseHonkVerifier fixture")

    def test_negative_erc20_produces_empty_queue(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write_sol(tmp, "Token.sol", self.NEGATIVE_FIXTURE)
            queue = self.mod.build_queue(tmp)
            self.assertEqual(len(queue), 0,
                "Plain ERC20 should not trigger any verifier predicates")

    def test_test_vendor_verifier_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vendor = tmp / "test" / "vendor"
            vendor.mkdir(parents=True)
            self._write_sol(vendor, "Permit2.sol", self.HONK_VERIFIER_FIXTURE)
            queue = self.mod.build_queue(tmp)
            self.assertEqual(queue, [])

    def test_surface_file_entries_are_filtered_to_audit_source(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vendor = tmp / "test" / "vendor"
            vendor.mkdir(parents=True)
            sol = self._write_sol(vendor, "Permit2.sol", self.HONK_VERIFIER_FIXTURE)
            surface = tmp / ".auditooor" / "zk_surface.json"
            surface.parent.mkdir()
            surface.write_text(json.dumps({"verifier_files": [{"path": str(sol), "hits": 3}]}), encoding="utf-8")
            queue = self.mod.build_queue(tmp, surface)
            self.assertEqual(queue, [])

    def test_deduplication(self):
        """Two identical .sol files should not double-count the same file:line + bug_class."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # Write same content twice with different names
            self._write_sol(tmp, "A.sol", self.HONK_VERIFIER_FIXTURE)
            self._write_sol(tmp, "B.sol", self.HONK_VERIFIER_FIXTURE)
            queue = self.mod.build_queue(tmp)
            # Deduplicated by (file_line, bug_class) - two different files may still
            # produce separate items (different file_line prefix), but within one file
            # the same (file_line, bug_class) must not repeat
            keys = [(item["file_line"], item["bug_class"]) for item in queue]
            self.assertEqual(len(keys), len(set(keys)), "No duplicate (file_line, bug_class) pairs")

    def test_schema_field_present(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write_sol(tmp, "V.sol", self.HONK_VERIFIER_FIXTURE)
            queue = self.mod.build_queue(tmp)
            self.assertGreater(len(queue), 0)
            for item in queue:
                self.assertIn("bug_class", item)
                self.assertIn("fn", item)
                self.assertIn("file_line", item)
                self.assertIn("question", item)
                self.assertIn("oracle_check", item)
                self.assertIn("severity_hint", item)
                self.assertIn("framework", item)
                self.assertEqual(item["framework"], "solidity-honk")

    def test_cli_dry_run_exits_0(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write_sol(tmp, "V.sol", self.HONK_VERIFIER_FIXTURE)
            rc = self.mod.main(["--workspace", str(tmp), "--dry-run"])
            self.assertEqual(rc, 0)

    def test_cli_writes_queue_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write_sol(tmp, "V.sol", self.HONK_VERIFIER_FIXTURE)
            rc = self.mod.main(["--workspace", str(tmp)])
            self.assertEqual(rc, 0)
            queue_path = tmp / ".auditooor" / "zk_hunt_queue.jsonl"
            self.assertTrue(queue_path.is_file(), "zk_hunt_queue.jsonl should be written")
            lines = [l for l in queue_path.read_text().splitlines() if l.strip()]
            self.assertGreater(len(lines), 0)
            # Validate each line is valid JSON with required fields
            for line in lines:
                obj = json.loads(line)
                self.assertIn("bug_class", obj)
                self.assertIn("file_line", obj)

    def test_cli_negative_workspace_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # No .sol files
            (tmp / "README.md").write_text("no solidity here\n")
            rc = self.mod.main(["--workspace", str(tmp)])
            self.assertEqual(rc, 1)
            self.assertTrue((tmp / ".auditooor" / "zk_hunt_queue.jsonl").is_file())
            self.assertEqual((tmp / ".auditooor" / "zk_hunt_queue.jsonl").read_text(), "")

    def test_cli_invalid_workspace_exits_2(self):
        rc = self.mod.main(["--workspace", "/nonexistent/path/xyz"])
        self.assertEqual(rc, 2)

    # ------------------------------------------------------------------
    # BaseZKHonkVerifier fixture - negative control (DOES have the check)
    # The ZK path has explicit aggregation handling; checklist still fires
    # for recursion-aggregation-object-skip to note the asymmetry with
    # the non-ZK path, but the oracle_check helps disambiguate.
    # ------------------------------------------------------------------
    BASE_ZK_VERIFIER_FIXTURE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BaseZKHonkVerifier {
    struct AggregationObject { uint256 x; }
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        AggregationObject memory agg;
        agg = processAggregation(proof);
        return agg.x > 0;
    }
    function processAggregation(bytes calldata proof) internal pure returns (AggregationObject memory) {
        return AggregationObject(1);
    }
}
"""

    def test_basezkhonk_triggers_recursion_predicate(self):
        """BaseZKHonkVerifier.sol should trigger recursion-aggregation-object-skip predicate."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write_sol(tmp, "BaseZKHonkVerifier.sol", self.BASE_ZK_VERIFIER_FIXTURE)
            queue = self.mod.build_queue(tmp)
            classes_found = {item["bug_class"] for item in queue}
            self.assertIn("recursion-aggregation-object-skip", classes_found)

    def test_all_8_predicates_defined(self):
        """Sanity: confirm exactly 8 bug-class predicates are wired."""
        self.assertEqual(len(self.mod.BUG_CLASS_PREDICATES), 8)
        ids = {p["bug_class"] for p in self.mod.BUG_CLASS_PREDICATES}
        expected = {
            "transcript-absorb-completeness",
            "fs-challenge-domain-separation",
            "curve-membership-check",
            "field-inversion-zero-check",
            "public-input-delta-fiat-shamir-binding",
            "sumcheck-round-count-enforcement",
            "recursion-aggregation-object-skip",
            "shplemini-opening-proof-binding",
        }
        self.assertEqual(ids, expected)


if __name__ == "__main__":
    unittest.main()
