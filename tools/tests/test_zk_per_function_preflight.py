#!/usr/bin/env python3
"""Tests for tools/zk-per-function-preflight.py.

Uses a tmp honk-like fixture (no network; --no-mcp) plus the brace-matching
extractor and the per-step-invariant / chain-candidate / bug-class logic.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "zk-per-function-preflight.py"


def _load():
    spec = importlib.util.spec_from_file_location("zk_pfp_test_mod", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# A honk-like verifier fixture with multiple verifier functions, one plain
# getter that should be skipped, and a declaration-only (virtual) function.
HONK_FIXTURE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./Transcript.sol";
import "./CommitmentScheme.sol";
contract BaseHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        HonkTranscript memory transcript;
        transcript = transcriptInit(publicInputs);
        Fr eta = transcript.getChallenge();
        bool ok = verifySumcheck(proof, transcript);
        return ok && verifyShplemini(proof, transcript);
    }
    function verifySumcheck(bytes calldata proof, Transcript memory tp) internal view returns (bool) {
        // round loop bound CONST_PROOF_SIZE_LOG_N
        return tp.numRounds > 0;
    }
    function verifyShplemini(bytes calldata proof, Transcript memory tp) internal view returns (bool) {
        Fr r = tp.getChallenge();
        (bool valid, Fr acc) = batchMul(proof);
        return valid;
    }
    function batchMul(bytes calldata proof) internal view returns (bool, Fr) {
        (bool ok,) = address(0x7).staticcall(abi.encode(proof));
        return (ok, Fr.wrap(0));
    }
    function justAGetter() external pure returns (uint256) {
        return 42;
    }
    function loadVerificationKey() internal pure virtual returns (Honk.VerificationKey memory);
}
"""

# A plain ERC20 - should produce no verifier files at all.
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


class ZkPerFunctionPreflightTest(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def _write(self, tmp: Path, name: str, content: str) -> Path:
        p = tmp / name
        p.write_text(content, encoding="utf-8")
        return p

    # ------------------------------------------------------------------
    # Case 1: extractor finds all functions incl. declaration-only.
    # ------------------------------------------------------------------
    def test_extractor_finds_functions_and_declaration_only(self):
        fns = self.mod._extract_function_with_lines(HONK_FIXTURE)
        names = {f["fn"] for f in fns}
        self.assertIn("verify", names)
        self.assertIn("verifySumcheck", names)
        self.assertIn("verifyShplemini", names)
        self.assertIn("batchMul", names)
        # declaration-only (virtual) function is still captured
        self.assertIn("loadVerificationKey", names)
        # verify body is brace-matched (contains the verifyShplemini call)
        verify_rec = next(f for f in fns if f["fn"] == "verify")
        self.assertIn("verifyShplemini", verify_rec["body"])
        self.assertNotIn("contract BaseHonkVerifier", verify_rec["body"])

    # ------------------------------------------------------------------
    # Case 2: per-function packs are emitted with all three sections, and
    # the plain getter is skipped.
    # ------------------------------------------------------------------
    def test_cli_emits_per_function_packs_with_three_sections(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            honk = tmp / "honk"
            honk.mkdir()
            self._write(honk, "BaseHonkVerifier.sol", HONK_FIXTURE)
            rc = self.mod.main([
                "--workspace", str(tmp), "--honk-dir", str(honk), "--no-mcp",
            ])
            self.assertEqual(rc, 0)
            out_dir = tmp / ".auditooor" / "zk_preflight_packs"
            self.assertTrue(out_dir.is_dir())
            packs = sorted(out_dir.glob("zk_preflight_pack_*.json"))
            self.assertGreater(len(packs), 0)
            # The plain getter must NOT have a pack (no verifier signal).
            getter_packs = [p for p in packs if "justAGetter" in p.name]
            self.assertEqual(getter_packs, [], "justAGetter should be skipped")
            # Inspect the verifySumcheck pack for the three sections.
            sumcheck_pack = next(
                (p for p in packs if "verifySumcheck" in p.name), None)
            self.assertIsNotNone(sumcheck_pack)
            obj = json.loads(sumcheck_pack.read_text())
            self.assertEqual(obj["schema"], "auditooor.zk_pre_flight_pack.v1")
            # (a) per-step invariants
            self.assertIn("step_invariants", obj)
            inv_ids = {i["invariant_id"] for i in obj["step_invariants"]}
            self.assertIn("ZK-INV-SUMCHECK-ROUND-COUNT", inv_ids)
            # (c) bug-class checklist hits
            self.assertIn("bug_class_checklist_hits", obj)
            self.assertIn("sumcheck-round-count-enforcement", obj["bug_classes"])
            # (b) chain candidates present (sumcheck -> shplemini edge)
            self.assertIn("chain_candidates", obj)
            edges = {(e["from_bug_class"], e["to_bug_class"])
                     for e in obj["chain_candidates"]}
            self.assertIn(
                ("sumcheck-round-count-enforcement", "shplemini-opening-proof-binding"),
                edges,
            )
            # prior-finding lookup block present + skipped (--no-mcp)
            self.assertEqual(obj["prior_finding_lookup"]["status"], "skipped")

    # ------------------------------------------------------------------
    # Case 3: manifest is written with a pack_count matching pack files.
    # ------------------------------------------------------------------
    def test_manifest_written_and_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            honk = tmp / "honk"
            honk.mkdir()
            self._write(honk, "BaseHonkVerifier.sol", HONK_FIXTURE)
            rc = self.mod.main([
                "--workspace", str(tmp), "--honk-dir", str(honk), "--no-mcp",
            ])
            self.assertEqual(rc, 0)
            out_dir = tmp / ".auditooor" / "zk_preflight_packs"
            manifest_path = out_dir / "manifest.json"
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["schema"],
                             "auditooor.zk_pre_flight_pack_manifest.v1")
            pack_files = list(out_dir.glob("zk_preflight_pack_*.json"))
            self.assertEqual(manifest["pack_count"], len(pack_files))
            self.assertGreaterEqual(manifest["verifier_file_count"], 1)
            for row in manifest["packs"]:
                self.assertIn("source_ref", row)
                self.assertIn("bug_classes", row)
                self.assertIn("step_invariant_count", row)
                self.assertIn("chain_candidate_count", row)

    # ------------------------------------------------------------------
    # Case 4: negative workspace (no verifier files) exits 1.
    # ------------------------------------------------------------------
    def test_negative_workspace_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._write(tmp, "Token.sol", NEGATIVE_FIXTURE)
            rc = self.mod.main(["--workspace", str(tmp), "--no-mcp"])
            self.assertEqual(rc, 1)

    # ------------------------------------------------------------------
    # Case 5: invalid workspace exits 2; dry-run writes nothing.
    # ------------------------------------------------------------------
    def test_invalid_workspace_exits_2(self):
        rc = self.mod.main(["--workspace", "/nonexistent/path/xyz", "--no-mcp"])
        self.assertEqual(rc, 2)

    def test_dry_run_writes_no_packs(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            honk = tmp / "honk"
            honk.mkdir()
            self._write(honk, "BaseHonkVerifier.sol", HONK_FIXTURE)
            rc = self.mod.main([
                "--workspace", str(tmp), "--honk-dir", str(honk),
                "--no-mcp", "--dry-run",
            ])
            self.assertEqual(rc, 0)
            out_dir = tmp / ".auditooor" / "zk_preflight_packs"
            # dry-run must not create the output dir / pack files
            self.assertFalse(
                out_dir.exists() and list(out_dir.glob("zk_preflight_pack_*.json")),
                "dry-run should not write pack files",
            )

    # ------------------------------------------------------------------
    # Case 6: step-invariant + chain-candidate builders are correct in isolation.
    # ------------------------------------------------------------------
    def test_builders_in_isolation(self):
        invs = self.mod.build_step_invariants(
            "verifyShplemini", "Fr r = tp.getChallenge(); batchMul(proof);")
        ids = {i["invariant_id"] for i in invs}
        self.assertIn("ZK-INV-OPENING-PROOF-BINDING", ids)
        self.assertIn("ZK-INV-CURVE-MEMBERSHIP", ids)  # batchMul keyword
        chains = self.mod.build_chain_candidates({"curve-membership-check"})
        self.assertTrue(any(
            c["to_bug_class"] == "shplemini-opening-proof-binding" for c in chains))
        # empty bug-class set -> no chain candidates
        self.assertEqual(self.mod.build_chain_candidates(set()), [])


if __name__ == "__main__":
    unittest.main()
