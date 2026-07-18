#!/usr/bin/env python3
"""test_orphan_producer_wiring.py - regression test for the 3 orphan-producer
wirings into tools/audit-deep.sh.

Three producer tools were referenced by gates but never invoked:
  FIX 1: tools/novel-vector-invariant-miner.py
         -> audit-completeness-check.py signal (l) expects
            <ws>/.auditooor/novel_vector_invariants*.json
  FIX 2: tools/chain-synthesizer-hunt-time.py
         -> r73-chain-derived-check.py requires drafts cite its
            schema auditooor.chain_synthesized.v1
  FIX 3: tools/fork-divergence-hunt-stage.py
         -> audit-completeness-check.py signal (k) expects a
            fork-divergence artifact on fork / vendored targets

Asserts per fix: (a) named Step present in audit-deep.sh body,
(b) producer invoked from that body, (c) `make -pn audit-deep` parses,
(d) each producer emits the gate-shaped artifact on a tiny synthetic ws.
Skips cleanly if bash/make/python3 unavailable. No network.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
AUDIT_DEEP = REPO / "tools" / "audit-deep.sh"
NOVEL_VECTOR = REPO / "tools" / "novel-vector-invariant-miner.py"
CHAIN_SYNTH = REPO / "tools" / "chain-synthesizer-hunt-time.py"
FORK_DIVERGENCE = REPO / "tools" / "fork-divergence-hunt-stage.py"


class TestStagePresentInBody(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = AUDIT_DEEP.read_text(encoding="utf-8")

    def test_bash_syntax_ok(self):
        if not shutil.which("bash"):
            self.skipTest("bash not on PATH")
        rc = subprocess.run(["bash", "-n", str(AUDIT_DEEP)],
                            capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, f"bash -n failed: {rc.stderr}")

    def test_fix1_novel_vector_stage_present(self):
        self.assertIn("Step 13 - Novel-vector invariant mining", self.body)
        self.assertIn("novel-vector-invariant-miner.py", self.body)
        self.assertIn("NOVEL_VECTOR_TOOL", self.body)
        self.assertRegex(self.body, r'--contract["\s]')
        self.assertIn("novel_vector_invariants.json", self.body)
        self.assertIn("auditooor.novel_vector_invariants.v1", self.body)

    def test_fix2_chain_synth_stage_present(self):
        self.assertIn("Step 14 - Chain-synthesis hunt-time stage", self.body)
        self.assertIn("chain-synthesizer-hunt-time.py", self.body)
        self.assertRegex(
            self.body,
            r'python3 "\$CHAIN_SYNTH_TOOL" --workspace "\$WORKSPACE" --output')
        self.assertIn("auditooor.chain_synthesized.v1", self.body)

    def test_fix3_fork_divergence_stage_present(self):
        self.assertIn("Step 15 - Fork-divergence hunt stage", self.body)
        self.assertIn("fork-divergence-hunt-stage.py", self.body)
        self.assertIn("AUDIT_DEEP_IS_FORK", self.body)
        self.assertRegex(
            self.body,
            r'python3 "\$FORK_DIVERGENCE_TOOL" --workspace "\$WORKSPACE" --emit-queue')
        self.assertIn("go.mod replace/pseudo-version", self.body)
        self.assertIn("vendored upstream tree", self.body)


class TestMakePnReachable(unittest.TestCase):
    def test_make_pn_audit_deep_parses(self):
        if not shutil.which("make"):
            self.skipTest("make not on PATH")
        rc = subprocess.run(["make", "-pn", "audit-deep"],
                            cwd=str(REPO), capture_output=True, text=True)
        combined = rc.stdout + rc.stderr
        self.assertIn("audit-deep", combined)
        self.assertTrue("audit-deep.sh" in combined,
                        "make -pn audit-deep did not reference tools/audit-deep.sh")


class TestProducersEmitGateArtifacts(unittest.TestCase):
    def setUp(self):
        if not shutil.which("python3"):
            self.skipTest("python3 not on PATH")
        self.tmp = Path(tempfile.mkdtemp())
        self.ws = self.tmp / "ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / ".auditooor").mkdir(parents=True)
        (self.ws / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Vault {\n"
            "    uint256 public totalShares;\n"
            "    mapping(address=>uint256) public balanceOf;\n"
            "    function deposit(uint256 a) external { totalShares += a; balanceOf[msg.sender]+=a; }\n"
            "    function withdraw(uint256 a) external { totalShares -= a; balanceOf[msg.sender]-=a; }\n"
            "}\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fix1_novel_vector_producer_runs(self):
        if not NOVEL_VECTOR.exists():
            self.skipTest("novel-vector-invariant-miner.py absent")
        out = self.ws / ".auditooor" / "nv.jsonl"
        rc = subprocess.run(
            [sys.executable, str(NOVEL_VECTOR), "--workspace", str(self.ws),
             "--contract", str(self.ws / "src" / "Vault.sol"),
             "--lang", "solidity", "--output", str(out)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(rc.returncode, 0, rc.stderr[:600])
        self.assertTrue(out.exists(), "miner did not emit JSONL")
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        self.assertGreater(len(lines), 0, "miner derived zero invariants")

    def test_fix2_chain_synth_producer_emits_schema(self):
        if not CHAIN_SYNTH.exists():
            self.skipTest("chain-synthesizer-hunt-time.py absent")
        out = self.ws / ".auditooor" / "chain_synthesized.jsonl"
        rc = subprocess.run(
            [sys.executable, str(CHAIN_SYNTH), "--workspace", str(self.ws),
             "--output", str(out)], capture_output=True, text=True, timeout=60)
        self.assertEqual(rc.returncode, 0, rc.stderr[:600])
        self.assertTrue(out.exists())
        first = json.loads(out.read_text().splitlines()[0])
        self.assertEqual(first.get("schema_id"), "auditooor.chain_synthesized.v1")

    def test_fix3_fork_divergence_producer_runs_on_fork(self):
        if not FORK_DIVERGENCE.exists():
            self.skipTest("fork-divergence-hunt-stage.py absent")
        (self.ws / "go.mod").write_text(
            "module example.com/fork\ngo 1.21\n"
            "replace github.com/cometbft/cometbft => "
            "github.com/dydxprotocol/cometbft v0.0.0-20240101000000-abcdef123456\n",
            encoding="utf-8")
        rc = subprocess.run(
            [sys.executable, str(FORK_DIVERGENCE), "--workspace", str(self.ws),
             "--emit-queue"], capture_output=True, text=True, timeout=120)
        self.assertEqual(rc.returncode, 0, rc.stderr[:600])
        combined = rc.stdout + rc.stderr
        self.assertIn("FORK-DIVERGENCE-HUNT-STAGE", combined)
        self.assertNotIn("verdict=not-a-fork", combined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
