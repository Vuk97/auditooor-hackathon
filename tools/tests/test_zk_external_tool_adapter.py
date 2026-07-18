#!/usr/bin/env python3
# r36-rebuttal: lane zk-external-tool-adapter registered in .auditooor/agent_pathspec.json
"""Tests for tools/zk-external-tool-adapter.py.

Covers:
  - tool-not-installed graceful path (binary absent -> verdict, no fabrication)
  - tool-not-applicable path (Solidity .sol honk verifier, circom-only tool)
  - findings-emitted path (mocked tool stdout produces MIMO-sidecar findings)
  - clean-no-findings path (mocked clean run)
  - result field is a JSON STRING (MIMO sidecar contract), round-trips
  - r76-hallucination-guard.scan_mimo_dir can read the emitted sidecar dir
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

adapter = importlib.import_module("zk-external-tool-adapter")  # type: ignore


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class ZkExternalToolAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- (a) graceful tool-not-installed path -----------------------------
    def test_tool_not_installed(self) -> None:
        circom = self.base / "circuit.circom"
        circom.write_text("template Main() { signal input a; }\n")
        with mock.patch.object(adapter, "tool_available", return_value=False):
            sc = adapter.adapt("circomspect", circom, timeout=5, workspace="ws")
        self.assertEqual(sc["verdict"], "tool-not-installed")
        self.assertEqual(sc["status"], "ok")
        # No fabrication: result payload says not-applies, no findings.
        payload = json.loads(sc["result"])
        self.assertEqual(payload["applies_to_target"], "no")
        self.assertEqual(payload["tool_findings"], [])
        self.assertIn("not installed", payload["notes"].lower())

    # --- (c) not-applicable for a Solidity honk verifier ------------------
    def test_solidity_verifier_not_applicable(self) -> None:
        sol = self.base / "HonkVerifier.sol"
        sol.write_text("contract HonkVerifier { function verify() public {} }\n")
        # Pretend the binary IS installed so we exercise the applicability gate.
        with mock.patch.object(adapter, "tool_available", return_value=True):
            sc = adapter.adapt("circomspect", sol, timeout=5, workspace="ws")
        self.assertEqual(sc["verdict"], "tool-not-applicable")
        payload = json.loads(sc["result"])
        self.assertEqual(payload["tool_findings"], [])
        self.assertIn("circom", payload["notes"].lower())

    # --- (b) findings-emitted: mocked tool flags an underconstrained signal
    def test_findings_emitted_maps_to_sidecar(self) -> None:
        circom = self.base / "vuln.circom"
        circom.write_text("template T() { signal input x; }\n")
        fake_exec = {
            "argv": ["circomspect", str(circom)],
            "returncode": 1,
            "stdout": "warning: signal `x` is underconstrained at vuln.circom:1\n",
            "stderr": "",
            "timed_out": False,
            "started_at_utc": "2026-05-29T00:00:00Z",
            "ended_at_utc": "2026-05-29T00:00:01Z",
            "exec_error": None,
        }
        with mock.patch.object(adapter, "tool_available", return_value=True), \
                mock.patch.object(adapter, "run_tool", return_value=fake_exec):
            sc = adapter.adapt("circomspect", circom, timeout=5, workspace="zkws")
        self.assertEqual(sc["verdict"], "findings-emitted")
        self.assertEqual(sc["verification_tier"], "tier-2-verified-public-archive")
        payload = json.loads(sc["result"])
        self.assertEqual(payload["applies_to_target"], "yes")
        self.assertEqual(len(payload["tool_findings"]), 1)
        # raw_line is verbatim tool output - no fabricated file:line.
        self.assertIn("underconstrained", payload["tool_findings"][0]["raw_line"])

    # --- clean-no-findings path -------------------------------------------
    def test_clean_no_findings(self) -> None:
        circom = self.base / "clean.circom"
        circom.write_text("template T() { signal input x; x === x; }\n")
        fake_exec = {
            "argv": ["circomspect", str(circom)], "returncode": 0,
            "stdout": "No issues found.\n", "stderr": "", "timed_out": False,
            "started_at_utc": "2026-05-29T00:00:00Z",
            "ended_at_utc": "2026-05-29T00:00:01Z", "exec_error": None,
        }
        with mock.patch.object(adapter, "tool_available", return_value=True), \
                mock.patch.object(adapter, "run_tool", return_value=fake_exec):
            sc = adapter.adapt("circomspect", circom, timeout=5, workspace=None)
        self.assertEqual(sc["verdict"], "clean-no-findings")
        self.assertEqual(json.loads(sc["result"])["tool_findings"], [])

    # --- MIMO-sidecar contract: result is a JSON STRING -------------------
    def test_result_is_json_string(self) -> None:
        circom = self.base / "x.circom"
        circom.write_text("template T() {}\n")
        with mock.patch.object(adapter, "tool_available", return_value=False):
            sc = adapter.adapt("picus", circom, timeout=5, workspace="ws")
        self.assertIsInstance(sc["result"], str)
        # Round-trips to a dict.
        self.assertIsInstance(json.loads(sc["result"]), dict)
        # Canonical MIMO-sidecar fields present.
        for field in ("provider", "result", "status", "task_id",
                      "attack_class", "verification_tier", "workspace"):
            self.assertIn(field, sc)

    # --- downstream learning loop can read the emitted sidecar dir --------
    def test_r76_scan_mimo_dir_reads_emitted_sidecar(self) -> None:
        circom = self.base / "vuln.circom"
        circom.write_text("template T() { signal input x; }\n")
        fake_exec = {
            "argv": ["zkhydra", "analyze", str(circom)], "returncode": 1,
            "stdout": "counterexample found: constraint violated\n", "stderr": "",
            "timed_out": False, "started_at_utc": "2026-05-29T00:00:00Z",
            "ended_at_utc": "2026-05-29T00:00:01Z", "exec_error": None,
        }
        out_dir = self.base / "sidecars"
        out_dir.mkdir()
        with mock.patch.object(adapter, "tool_available", return_value=True), \
                mock.patch.object(adapter, "run_tool", return_value=fake_exec):
            sc = adapter.adapt("zkhydra", circom, timeout=5, workspace="zkws")
        (out_dir / "zk_ext_0001.json").write_text(json.dumps(sc))

        r76 = _load("r76_guard", "tools/r76-hallucination-guard.py")
        results = r76.scan_mimo_dir(out_dir, None)
        # Should parse without raising and return a per-task verdict list.
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertIn("verdict", results[0])

    # --- unknown tool guarded by argparse choices; adapt() is defensive ----
    def test_target_missing(self) -> None:
        missing = self.base / "nope.circom"
        with mock.patch.object(adapter, "tool_available", return_value=True):
            sc = adapter.adapt("picus", missing, timeout=5, workspace="ws")
        self.assertEqual(sc["verdict"], "error-target-missing")
        self.assertEqual(sc["status"], "error")


if __name__ == "__main__":
    unittest.main()
