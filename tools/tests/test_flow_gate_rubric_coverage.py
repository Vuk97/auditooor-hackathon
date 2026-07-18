#!/usr/bin/env python3
"""Focused tests for flow-gate RUBRIC_COVERAGE row detection."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FLOW_GATE = ROOT / "tools" / "flow-gate.sh"


def _run_rubric_only(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td) / "ws"
        ws.mkdir()
        (ws / "RUBRIC_COVERAGE.md").write_text(text, encoding="utf-8")
        env = os.environ.copy()
        env["FLOW_GATE_RUBRIC_ONLY"] = "1"
        return subprocess.run(
            ["bash", str(FLOW_GATE), str(ws)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )


def _run_flow_gate_minimal(ws: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(FLOW_GATE), str(ws)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )


class FlowGateRubricCoverageTests(unittest.TestCase):
    def test_legacy_severity_rows_still_count(self) -> None:
        proc = _run_rubric_only(
            """
| Critical | Direct theft of funds | 📋 NOT CHECKED | — |
"""
        )

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_curated_checklist_id_rows_with_verdicts_count(self) -> None:
        proc = _run_rubric_only(
            """
| Row | Class | Status | Justification |
|---|---|---|---|
| BA-C1 (Forge/bypass TEE or ZK verification) | Critical | ⚠️ PARTIAL | Covered by FN-2. |
| BDL-M3 | Layer 0/1/2 code bug causing unintended SC behavior | 🚀 SUBMITTED | FN-2. |
| SC-M2 | Block stuffing | ❌ N/A | No Solidity block-stuffing surface. |
"""
        )

        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_headers_without_populated_rows_do_not_count(self) -> None:
        proc = _run_rubric_only(
            """
| Row | Class | Status | Justification |
|---|---|---|---|
| Tier | Total | ✅ PASS | 🚀 Submitted |
"""
        )

        self.assertNotEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def test_nested_external_contracts_src_satisfies_source_tree_check(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            src = ws / "external" / "contracts" / "src"
            src.mkdir(parents=True)
            (src / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            (ws / "SESSION_LOG.md").write_text("started\n", encoding="utf-8")
            (ws / "FINDINGS.md").write_text("# Findings\n", encoding="utf-8")
            (ws / "AUDIT.md").write_text("# Audit\n", encoding="utf-8")
            (ws / "SCOPE.md").write_text("\n".join(["scope"] * 32) + "\n", encoding="utf-8")
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "| Row | Class | Status | Justification |\n"
                "|---|---|---|---|\n"
                "| BA-C1 | Critical | ⚠️ PARTIAL | checked |\n",
                encoding="utf-8",
            )
            (ws / "targets.tsv").write_text(
                "https://example.invalid/repo.git\tdeadbeef\trepo\n",
                encoding="utf-8",
            )

            proc = _run_flow_gate_minimal(ws)

            self.assertNotIn("[✗] source tree has Solidity", proc.stdout)

    def test_targets_tsv_contract_paths_satisfy_source_tree_check(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            contracts = ws / "external" / "reserve-governor" / "contracts"
            contracts.mkdir(parents=True)
            (contracts / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            (ws / "SESSION_LOG.md").write_text("started\n", encoding="utf-8")
            (ws / "FINDINGS.md").write_text("# Findings\n", encoding="utf-8")
            (ws / "AUDIT.md").write_text("# Audit\n", encoding="utf-8")
            (ws / "SCOPE.md").write_text("\n".join(["scope"] * 31), encoding="utf-8")
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "| Row | Class | Status | Justification |\n"
                "|---|---|---|---|\n"
                "| H1 | High | 📋 NOT CHECKED | checked |\n",
                encoding="utf-8",
            )
            (ws / "targets.tsv").write_text(
                "external/reserve-governor/contracts/A.sol\tcontract\tin scope\n",
                encoding="utf-8",
            )

            proc = _run_flow_gate_minimal(ws)

            self.assertNotIn("[✗] source tree has Solidity", proc.stdout)

    def test_go_only_targets_satisfy_source_tree_and_skip_solidity_harnesses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            source = ws / "external" / "spark" / "spark" / "so" / "chain"
            source.mkdir(parents=True)
            (source / "watch_chain.go").write_text("package chain\n", encoding="utf-8")
            (ws / "SESSION_LOG.md").write_text("started\n", encoding="utf-8")
            (ws / "FINDINGS.md").write_text("# Findings\n", encoding="utf-8")
            (ws / "AUDIT.md").write_text("# Audit\n", encoding="utf-8")
            (ws / "SCOPE.md").write_text("\n".join(["scope"] * 31), encoding="utf-8")
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "| Row | Class | Status | Justification |\n"
                "|---|---|---|---|\n"
                "| C1 | Critical | 📋 NOT CHECKED | checked |\n",
                encoding="utf-8",
            )
            (ws / "targets.tsv").write_text(
                "external/spark/spark/so/chain\tgo\tin scope\n",
                encoding="utf-8",
            )
            (ws / "OOS_CHECKLIST.md").write_text("- [ ] **OOS-1** none\n", encoding="utf-8")
            (ws / "SEVERITY_CAPS.md").write_text("# Severity\nCritical\n", encoding="utf-8")
            (ws / ".auditooor-state.yaml").write_text(
                "workspace: ws\n"
                "initialized_at: 2026-01-01T00:00:00Z\n"
                "open_submissions: []\n"
                "closed_submissions: []\n"
                "last_ledger_sync: never\n"
                "last_classifier_retrain: never\n",
                encoding="utf-8",
            )
            old_ts = time.time() - 601
            os.utime(ws, (old_ts, old_ts))

            proc = _run_flow_gate_minimal(ws)

            self.assertNotIn("[✗] source tree has Solidity", proc.stdout)
            self.assertIn("no Solidity source detected; Forge Invariant_*.t.sol generation is not applicable", proc.stdout)
            self.assertIn("no Solidity source detected; composition-fuzz Forge harness is not applicable", proc.stdout)


if __name__ == "__main__":
    unittest.main()
