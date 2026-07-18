#!/usr/bin/env python3
"""Tests for tools/zk-hacker-questions.py (>=4 cases)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL_PATH = TOOLS / "zk-hacker-questions.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("zk_hacker_questions", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


zkhq = _load_module()

SOLIDITY_VERIFIER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BaseHonkVerifier {
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) public returns (bool) {
        Transcript memory t = generateTranscript(proof, publicInputs);
        Fr challenge = t.getChallenge("alpha");
        require(verifySumcheck(proof, challenge), "sumcheck failed");
        return verifyShplemini(proof, t);
    }

    function inverseElement(Fr a) internal pure returns (Fr) {
        return a.invert();
    }

    function plainHelper(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }
}
"""

CIRCOM_CIRCUIT = """pragma circom 2.0.0;

template RangeCheck(n) {
    signal input in;
    signal output out;
    component lt = LessThan(n);
    out <== lt.out;
}

template LookupTable() {
    signal input val;
    signal lookup[16];
}
"""


class TestZkHackerQuestions(unittest.TestCase):
    def test_case1_solidity_verifier_emits_questions(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Verifier.sol"
            f.write_text(SOLIDITY_VERIFIER)
            result = zkhq.analyze(f)
            self.assertEqual(result["schema"], "auditooor.zk_hacker_questions.v1")
            self.assertGreater(result["total_questions"], 0)
            fns = {r["function"] for r in result["records"]}
            self.assertIn("verifyProof", fns)
            # verifyProof should match transcript + public-input + shplemini classes
            vp = next(r for r in result["records"] if r["function"] == "verifyProof")
            classes = {q["bug_class"] for q in vp["questions"]}
            self.assertIn("public-input-constraint", classes)
            self.assertIn("malformed-proof-skip", classes)

    def test_case2_field_inversion_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Verifier.sol"
            f.write_text(SOLIDITY_VERIFIER)
            result = zkhq.analyze(f)
            inv = next(r for r in result["records"] if r["function"] == "inverseElement")
            classes = {q["bug_class"] for q in inv["questions"]}
            self.assertIn("field-op-mod-p", classes)

    def test_case3_plain_helper_no_questions(self):
        # plainHelper has no ZK keywords -> should not appear in records
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Verifier.sol"
            f.write_text(SOLIDITY_VERIFIER)
            result = zkhq.analyze(f)
            fns = {r["function"] for r in result["records"]}
            self.assertNotIn("plainHelper", fns)

    def test_case4_circom_lookup_class(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "circuit.circom"
            f.write_text(CIRCOM_CIRCUIT)
            result = zkhq.analyze(f)
            self.assertGreater(result["functions_with_questions"], 0)
            all_classes = set(result["bug_classes"])
            self.assertIn("lookup-databus-constraint", all_classes)
            # circom template detected as a function-like def
            langs = {r["language"] for r in result["records"]}
            self.assertIn("circom", langs)

    def test_case5_directory_scan(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Verifier.sol").write_text(SOLIDITY_VERIFIER)
            (Path(td) / "circuit.circom").write_text(CIRCOM_CIRCUIT)
            result = zkhq.analyze(Path(td))
            self.assertEqual(result["files_scanned"], 2)
            self.assertGreater(result["total_questions"], 0)

    def test_case6_cli_json_and_exit_code(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "Verifier.sol"
            f.write_text(SOLIDITY_VERIFIER)
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), str(f), "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.zk_hacker_questions.v1")
            self.assertGreater(payload["total_questions"], 0)

    def test_case7_missing_path_exit2(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL_PATH), "/no/such/path/xyz", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)

    def test_case8_empty_file_exit1(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "empty.sol"
            f.write_text("// nothing here\n")
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), str(f)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
