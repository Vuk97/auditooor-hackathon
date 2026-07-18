#!/usr/bin/env python3
"""Tests for tools/zk-engagement-probe.py.

Wave-5 Track K-zkBugs Step 9 (stub).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "zk-engagement-probe.py"


def _load():
    spec = importlib.util.spec_from_file_location("zep_test_mod", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkEngagementProbeTest(unittest.TestCase):
    def test_negative_workspace_writes_artifact_and_rc_1(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "a.go").write_text("package main\nfunc main() {}\n")
            (ws / "b.md").write_text("# README — no ZK content here\n")
            rc = mod.main([str(ws)])
            self.assertEqual(rc, 1)
            self.assertTrue((ws / "NEGATIVE_zk_engagement_probe.md").is_file())

    def test_positive_workspace_rc_0(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "a.rs").write_text("use halo2_proofs::plonk::Circuit;\n")
            (ws / "b.circom").write_text("pragma circom 2.0.0;\ntemplate T() {}\n")
            rc = mod.main([str(ws)])
            self.assertEqual(rc, 0)
            self.assertFalse((ws / "NEGATIVE_zk_engagement_probe.md").exists())

    def test_probe_function_counts_hits(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "x.rs").write_text("// halo2 here, plonk and groth16 too\n")
            total, per_file = mod.probe(ws)
            self.assertGreaterEqual(total, 3)
            self.assertEqual(len(per_file), 1)

    def test_test_vendor_zk_tokens_are_excluded(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            vendor = ws / "test" / "vendor"
            vendor.mkdir(parents=True)
            (vendor / "Permit2.sol").write_text(
                "contract Permit2 { function verify(bytes calldata proof) external returns (bool) { return true; } }\n",
                encoding="utf-8",
            )
            self.assertEqual(mod.probe(ws)[0], 0)
            self.assertEqual(mod._probe_verifier(ws), [])


if __name__ == "__main__":
    unittest.main()
