#!/usr/bin/env python3
"""Tests for tools/high-impact-execution-bridge.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "high-impact-execution-bridge.py"


def _row(
    rid: str,
    family: str,
    statement: str,
    *,
    status: str = "missing_harness",
    production_path: str = "",
    harness_target: str = "",
    negative_test: str = "",
    required_engine: str = "manual",
    severity: str = "High",
) -> dict:
    return {
        "id": rid,
        "scope_asset": "synthetic",
        "invariant_family": family,
        "statement": statement,
        "source_citations": ["docs/test.md"],
        "attacker_capability": "user input",
        "trusted_boundary": "none",
        "oos_boundary": "in scope",
        "production_path": production_path or f"src/{rid.lower()}.rs",
        "harness_target": harness_target,
        "required_engine": required_engine,
        "negative_test": negative_test,
        "status": status,
        "artifacts": [],
        "owner": "Codex",
        "severity": severity,
        "notes": "",
    }


def _write_ledger(ws: Path, rows: list[dict]) -> None:
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    (auditooor_dir / "invariant_ledger.json").write_text(
        json.dumps(
            {
                "schema_version": "auditooor.invariant_ledger.v1",
                "schema_source": "test",
                "workspace": str(ws),
                "generated_by": "test_high_impact_execution_bridge",
                "generated_at": "2026-05-02T00:00:00Z",
                "rows": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_impact_contracts(ws: Path, contracts: list[dict]) -> None:
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    (auditooor_dir / "impact_contracts.json").write_text(
        json.dumps({"contracts": contracts}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class HighImpactExecutionBridgeTests(unittest.TestCase):
    def test_emits_scaffold_handoff_and_execution_record_command(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_bridge_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-DLT-I01",
                        "BASE-DLT-WITHDRAWALS-ROOT",
                        "withdrawals root divergence must be rejected",
                        required_engine="cargo",
                        production_path="crates/engine/tree/src/tree/mod.rs:88",
                    )
                ],
            )
            _write_impact_contracts(
                ws,
                [
                    {
                        "impact_contract_id": "impact-contract-base-dlt-i01",
                        "candidate_id": "BASE-DLT-I01",
                        "selected_impact": "Temporary freezing of user funds (recoverable within a finalization window)",
                        "severity_tier": "High",
                        "exact_impact_row": True,
                        "listed_impact_proven": True,
                        "evidence_class": "executed_with_manifest",
                        "oos_traps": ["admin-only path"],
                        "stop_condition": "Stop if the negative control is not rejected.",
                    }
                ],
            )
            (ws / "SEVERITY.md").write_text(
                "# Test Severity\n\n"
                "## High-tier listed impacts\n"
                "- Temporary freezing of user funds (recoverable within a finalization window)\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema_version"], "auditooor.high_impact_execution_bridge.v1")
            self.assertEqual(payload["processed_rows"], 1)
            self.assertEqual(payload["summary"]["runnable_harness_rows"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["bridge_status"], "scaffolded_ready_for_execution_record")
            self.assertTrue(row["runnable_harness"])
            self.assertEqual(row["attempt_status"], "scaffolded_unverified")
            self.assertIn("make poc-execution-record", row["poc_execution_record_command"])
            self.assertIn("BRIDGE_ROW=BASE-DLT-I01", row["poc_execution_record_command"])
            self.assertNotIn("<brief", row["poc_execution_record_command"])
            self.assertEqual(row["poc_execution_record_status"], "expected_missing")
            self.assertTrue(row["poc_execution_record_path"].endswith("poc_execution/base-dlt-i01/execution_manifest.json"))
            self.assertEqual(row["poc_execution_record_blocked_reason"], "")
            brief_path = Path(row["handoff_brief"])
            self.assertTrue(brief_path.is_file())
            self.assertIn("make poc-execution-record", brief_path.read_text(encoding="utf-8"))
            attempt_manifest = Path(row["attempt_manifest"])
            self.assertTrue(attempt_manifest.is_file())
            attempt_payload = json.loads(attempt_manifest.read_text(encoding="utf-8"))
            self.assertEqual(attempt_payload["status"], "scaffolded_unverified")
            cargo_toml = Path(row["scaffold_dir"]) / "Cargo.toml"
            self.assertTrue(cargo_toml.is_file())

    def test_impact_contract_blocked_rows_never_get_runnable_scaffolds(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_bridge_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-SC-I01",
                        "BASE-SC-PROOF-DOMAIN",
                        "proof domain mismatch must not drain funds",
                        required_engine="forge",
                        production_path="external/contracts/src/AggregateVerifier.sol:12",
                    )
                ],
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["summary"]["blocked_missing_impact_contract"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["bridge_status"], "blocked_missing_impact_contract")
            self.assertFalse(row["runnable_harness"])
            self.assertEqual(row["attempt_status"], "")
            self.assertEqual(row["poc_execution_record_command"], "")
            self.assertEqual(row["poc_execution_record_status"], "blocked")
            self.assertEqual(row["poc_execution_record_path"], "")
            self.assertEqual(row["poc_execution_record_blocked_reason"], "missing_exact_impact_contract")
            self.assertIn("make impact-contract-check", row["impact_contract_command"])
            self.assertIn("make high-impact-impact-contract-skeletons", row["impact_contract_skeleton_command"])
            self.assertTrue(row["impact_contract_skeleton_path"].endswith("base-sc-i01.json"))
            self.assertFalse((ws / "poc-tests-base_sc_i01" / "foundry.toml").exists())
            self.assertFalse((ws / "poc-tests" / "base_sc_i01" / "Cargo.toml").exists())

    def test_incomplete_mapped_contract_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_bridge_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-DLT-I02",
                        "BASE-DLT-WITHDRAWALS-ROOT",
                        "withdrawals root divergence must be rejected",
                        required_engine="cargo",
                        production_path="crates/engine/tree/src/tree/mod.rs:88",
                    )
                ],
            )
            _write_impact_contracts(
                ws,
                [
                    {
                        "impact_contract_id": "impact-contract-base-dlt-i02",
                        "candidate_id": "BASE-DLT-I02",
                        "selected_impact": "Temporary freezing of user funds (recoverable within a finalization window)",
                        "severity_tier": "High",
                        "exact_impact_row": True,
                        "listed_impact_proven": True,
                        "evidence_class": "",
                        "oos_traps": [],
                        "stop_condition": "",
                    }
                ],
            )
            (ws / "SEVERITY.md").write_text(
                "# Test Severity\n\n"
                "## High-tier listed impacts\n"
                "- Temporary freezing of user funds (recoverable within a finalization window)\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["rows"][0]
            self.assertEqual(row["bridge_status"], "blocked_missing_impact_contract")
            self.assertFalse(row["runnable_harness"])
            self.assertEqual(row["attempt_status"], "")
            self.assertEqual(row["poc_execution_record_status"], "blocked")
            self.assertEqual(row["poc_execution_record_blocked_reason"], "missing_exact_impact_contract")
            self.assertIn("make impact-contract-check", row["impact_contract_command"])
            self.assertIn("make high-impact-impact-contract-skeletons", row["impact_contract_skeleton_command"])
            self.assertFalse((ws / "poc-tests" / "base_dlt_i02" / "Cargo.toml").exists())

    def test_existing_execution_manifest_is_linked_as_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_bridge_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-DLT-I01",
                        "BASE-DLT-WITHDRAWALS-ROOT",
                        "withdrawals root divergence must be rejected",
                        required_engine="cargo",
                        production_path="crates/engine/tree/src/tree/mod.rs:88",
                    )
                ],
            )
            _write_impact_contracts(
                ws,
                [
                    {
                        "impact_contract_id": "impact-contract-base-dlt-i01",
                        "candidate_id": "BASE-DLT-I01",
                        "selected_impact": "Temporary freezing of user funds (recoverable within a finalization window)",
                        "severity_tier": "High",
                        "exact_impact_row": True,
                        "listed_impact_proven": True,
                        "evidence_class": "executed_with_manifest",
                        "oos_traps": ["admin-only path"],
                        "stop_condition": "Stop if the negative control is not rejected.",
                    }
                ],
            )
            (ws / "SEVERITY.md").write_text(
                "# Test Severity\n\n"
                "## High-tier listed impacts\n"
                "- Temporary freezing of user funds (recoverable within a finalization window)\n",
                encoding="utf-8",
            )
            manifest = ws / "poc_execution" / "base-dlt-i01" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text('{"schema_version":"auditooor.poc_execution_manifest.v1"}\n', encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            row = payload["rows"][0]
            self.assertEqual(row["poc_execution_record_status"], "present")
            self.assertEqual(Path(row["poc_execution_record_path"]).resolve(), manifest.resolve())
            self.assertEqual(payload["summary"]["poc_execution_records_present"], 1)


if __name__ == "__main__":
    unittest.main()
