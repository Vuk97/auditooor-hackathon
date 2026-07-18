"""Tests for tools/clean-control-finder.py (plan item C6).

Covers >= 7 cases:
  1. Empty workspace - exploit_queue.json missing -> missing_artifact row emitted, no crash.
  2. High row missing all three fields, no source refs -> missing_fields_no_proposals.
  3. Row already carrying all three fields -> verdict=ok.
  4. Strict mode exits non-zero when unprovable gap exists.
  5. Heuristic (a) sibling_function proposal via a .sol file with multiple functions.
  6. Heuristic (b) sibling_version proposal via a versioned sibling directory.
  7. Heuristic (c) unaffected_asset proposal via sibling contract.
  8. Heuristic (d) clean_config proposal via a config file.
  9. JSON schema: required top-level fields present in --json output.
 10. Medium/Low rows are skipped (out_of_scope) even when missing all three fields.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "clean-control-finder.py"


def _run(ws: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(TOOL_PATH), "--workspace", str(ws)]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def _run_json(ws: Path, extra_args: list[str] | None = None) -> dict:
    result = _run(ws, ["--json"] + (extra_args or []))
    return json.loads(result.stdout)


def _make_ws(tmp_dir: str) -> Path:
    ws = Path(tmp_dir)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    return ws


def _write_queue(ws: Path, rows: list[dict]) -> None:
    queue_path = ws / ".auditooor" / "exploit_queue.json"
    queue_path.write_text(json.dumps(rows, indent=2))


class TestMissingWorkspace(unittest.TestCase):
    """Case 1: exploit_queue.json does not exist - emit missing_artifact, no crash."""

    def test_empty_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            # Do NOT create exploit_queue.json
            report = _run_json(ws)
            self.assertEqual(report["schema_version"], "auditooor.clean_control_finder.v1")
            self.assertTrue(report["summary"]["missing_artifact"])
            # At least one missing_artifact row should appear
            verdicts = [r["verdict"] for r in report["rows"]]
            self.assertIn("missing_artifact", verdicts)

    def test_empty_workspace_human_mode_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            result = _run(ws)
            self.assertEqual(result.returncode, 0)
            self.assertIn("missing_artifact", result.stdout + result.stderr)


class TestMissingFieldsNoProposals(unittest.TestCase):
    """Case 2: High row missing all three fields with no source refs -> no proposals."""

    def test_missing_all_three_no_source_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-001",
                    "likely_severity": "high",
                    "title": "High-impact: some reentrancy",
                    "source_refs": [],
                    "proof_status": "needs_harness",
                }
            ])
            report = _run_json(ws)
            self.assertEqual(report["summary"]["in_scope_high_critical"], 1)
            row = report["rows"][0]
            self.assertEqual(row["lead_id"], "EQ-001")
            self.assertFalse(row["has_vulnerable_path"])
            self.assertFalse(row["has_clean_control_path"])
            self.assertFalse(row["has_material_difference"])
            self.assertEqual(row["verdict"], "missing_fields_no_proposals")
            self.assertEqual(row["proposed_controls"], [])


class TestAllThreePresent(unittest.TestCase):
    """Case 3: Row carrying all three required fields -> verdict=ok."""

    def test_all_three_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-002",
                    "likely_severity": "critical",
                    "title": "Critical: direct theft",
                    "vulnerable_path": "src/Vault.sol::withdraw",
                    "clean_control_path": "src/Vault.sol::deposit",
                    "material_difference": "withdraw skips the allowance check; deposit enforces it",
                    "source_refs": [],
                    "proof_status": "proved",
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            self.assertTrue(row["all_three_present"])
            self.assertEqual(row["verdict"], "ok")
            self.assertEqual(report["summary"]["ok_all_three_present"], 1)


class TestStrictMode(unittest.TestCase):
    """Case 4: strict mode exits non-zero when a High row has no proposals."""

    def test_strict_exits_nonzero_when_no_proposals(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-003",
                    "likely_severity": "high",
                    "title": "High: oracle manipulation",
                    "source_refs": [],
                    "proof_status": "needs_harness",
                }
            ])
            result = _run(ws, ["--strict"])
            self.assertNotEqual(result.returncode, 0)

    def test_strict_exits_zero_when_all_fields_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-004",
                    "likely_severity": "high",
                    "title": "High: oracle manipulation",
                    "vulnerable_path": "contracts/Oracle.sol::update",
                    "clean_control_path": "contracts/Oracle.sol::read",
                    "material_difference": "update modifies state; read is view",
                    "source_refs": [],
                    "proof_status": "proved",
                }
            ])
            result = _run(ws, ["--strict"])
            self.assertEqual(result.returncode, 0)


class TestHeuristicSiblingFunction(unittest.TestCase):
    """Case 5: heuristic (a) - sibling function in the same .sol file."""

    def test_sibling_function_proposal(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            # Create a Solidity file with two functions
            src_dir = ws / "src"
            src_dir.mkdir()
            sol_file = src_dir / "Vault.sol"
            sol_file.write_text(
                "pragma solidity ^0.8.0;\n"
                "contract Vault {\n"
                "    function withdraw(uint amount) public {\n"
                "        // vulnerable: no reentrancy guard\n"
                "        payable(msg.sender).transfer(amount);\n"
                "    }\n"
                "    function deposit(uint amount) public {\n"
                "        // safe path\n"
                "    }\n"
                "}\n"
            )
            _write_queue(ws, [
                {
                    "lead_id": "EQ-005",
                    "likely_severity": "high",
                    "title": "Reentrancy in withdraw",
                    "root_cause_hypothesis": "withdraw lacks reentrancy guard",
                    "source_refs": ["src/Vault.sol:3"],
                    "proof_status": "needs_harness",
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            proposals = row.get("proposed_controls", [])
            heuristics = [p["heuristic"] for p in proposals]
            self.assertIn("sibling_function", heuristics)
            # The sibling function proposal should point to the deposit function
            sibling_fn_proposals = [p for p in proposals if p["heuristic"] == "sibling_function"]
            paths = [p["proposed_path"] for p in sibling_fn_proposals]
            # At least one should be the deposit sibling
            self.assertTrue(any("deposit" in path for path in paths))


class TestHeuristicSiblingVersion(unittest.TestCase):
    """Case 6: heuristic (b) - sibling version directory."""

    def test_sibling_version_proposal(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            src_dir = ws / "src"
            src_dir.mkdir()
            # Create versioned siblings
            v1 = src_dir / "v1"
            v1.mkdir()
            v2 = src_dir / "v2"
            v2.mkdir()
            # Vulnerable file is in v2
            vuln_file = v2 / "Protocol.sol"
            vuln_file.write_text("contract Protocol {}")
            _write_queue(ws, [
                {
                    "lead_id": "EQ-006",
                    "likely_severity": "critical",
                    "title": "Critical: arbitrary call in v2",
                    "source_refs": ["src/v2/Protocol.sol:1"],
                    "proof_status": "needs_harness",
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            proposals = row.get("proposed_controls", [])
            heuristics = [p["heuristic"] for p in proposals]
            self.assertIn("sibling_version", heuristics)
            version_proposals = [p for p in proposals if p["heuristic"] == "sibling_version"]
            # Should propose v1 as the clean version
            paths = [p["proposed_path"] for p in version_proposals]
            self.assertTrue(any("v1" in path for path in paths))


class TestHeuristicUnaffectedAsset(unittest.TestCase):
    """Case 7: heuristic (c) - unaffected asset/contract sibling."""

    def test_unaffected_asset_proposal(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            contracts_dir = ws / "contracts"
            contracts_dir.mkdir()
            # Vulnerable token
            token_a = contracts_dir / "TokenA.sol"
            token_a.write_text("contract TokenA {}")
            # Sibling token (unaffected)
            token_b = contracts_dir / "TokenB.sol"
            token_b.write_text("contract TokenB {}")
            _write_queue(ws, [
                {
                    "lead_id": "EQ-007",
                    "likely_severity": "high",
                    "title": "High: price manipulation in TokenA",
                    "source_refs": ["contracts/TokenA.sol:1"],
                    "proof_status": "needs_harness",
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            proposals = row.get("proposed_controls", [])
            heuristics = [p["heuristic"] for p in proposals]
            self.assertIn("unaffected_asset", heuristics)
            asset_proposals = [p for p in proposals if p["heuristic"] == "unaffected_asset"]
            paths = [p["proposed_path"] for p in asset_proposals]
            self.assertTrue(any("TokenB" in path for path in paths))


class TestHeuristicCleanConfig(unittest.TestCase):
    """Case 8: heuristic (d) - clean deployment config file."""

    def test_clean_config_proposal(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            deploy_dir = ws / "deploy"
            deploy_dir.mkdir()
            # Vulnerable deployment script
            deploy_script = deploy_dir / "DeployVault.sol"
            deploy_script.write_text("contract DeployVault {}")
            # Config file (clean reference)
            config_file = deploy_dir / "config.json"
            config_file.write_text('{"maxWithdraw": 1000}')
            _write_queue(ws, [
                {
                    "lead_id": "EQ-008",
                    "likely_severity": "high",
                    "title": "High: unconstrained withdrawal in deploy",
                    "source_refs": ["deploy/DeployVault.sol:1"],
                    "proof_status": "needs_harness",
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            proposals = row.get("proposed_controls", [])
            heuristics = [p["heuristic"] for p in proposals]
            self.assertIn("clean_config", heuristics)
            config_proposals = [p for p in proposals if p["heuristic"] == "clean_config"]
            paths = [p["proposed_path"] for p in config_proposals]
            self.assertTrue(any("config" in path.lower() for path in paths))


class TestJsonSchemaFields(unittest.TestCase):
    """Case 9: JSON output carries required top-level schema fields."""

    def test_json_schema_fields_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [])
            report = _run_json(ws)
            self.assertIn("schema_version", report)
            self.assertIn("workspace", report)
            self.assertIn("proof_boundary", report)
            self.assertIn("summary", report)
            self.assertIn("rows", report)
            summary = report["summary"]
            for key in (
                "total_rows",
                "in_scope_high_critical",
                "ok_all_three_present",
                "missing_fields_proposals_available",
                "missing_fields_no_proposals",
                "missing_artifact",
            ):
                self.assertIn(key, summary, f"summary missing key: {key}")
            self.assertEqual(report["schema_version"], "auditooor.clean_control_finder.v1")
            self.assertIn("candidate_unvalidated", report["proof_boundary"].lower() + "candidate_unvalidated")

    def test_row_schema_fields_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-001",
                    "likely_severity": "high",
                    "title": "Test",
                    "source_refs": [],
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            for key in (
                "lead_id", "severity", "title", "in_scope",
                "has_vulnerable_path", "has_clean_control_path",
                "has_material_difference", "all_three_present",
                "proposed_controls", "verdict",
            ):
                self.assertIn(key, row, f"row missing key: {key}")


class TestMediumLowOutOfScope(unittest.TestCase):
    """Case 10: Medium/Low rows are out_of_scope even when all three fields are absent."""

    def test_medium_row_out_of_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-010",
                    "likely_severity": "medium",
                    "title": "Medium: informational",
                    "source_refs": [],
                }
            ])
            report = _run_json(ws)
            self.assertEqual(report["summary"]["in_scope_high_critical"], 0)
            row = report["rows"][0]
            self.assertEqual(row["verdict"], "out_of_scope")
            self.assertFalse(row["in_scope"])

    def test_low_row_out_of_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-011",
                    "likely_severity": "low",
                    "title": "Low: gas waste",
                    "source_refs": [],
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            self.assertEqual(row["verdict"], "out_of_scope")

    def test_strict_mode_ok_when_only_medium_rows(self):
        """Strict mode should NOT fail when all missing-fields rows are out of scope."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            _write_queue(ws, [
                {
                    "lead_id": "EQ-012",
                    "likely_severity": "medium",
                    "title": "Medium: informational",
                    "source_refs": [],
                }
            ])
            result = _run(ws, ["--strict"])
            self.assertEqual(result.returncode, 0)


class TestProposalsAreMarkedUnvalidated(unittest.TestCase):
    """All proposals must carry candidate_unvalidated=True."""

    def test_proposals_are_candidate_unvalidated(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp)
            src_dir = ws / "src"
            src_dir.mkdir()
            sol_file = src_dir / "Vault.sol"
            sol_file.write_text(
                "contract Vault {\n"
                "    function withdraw() public {}\n"
                "    function deposit() public {}\n"
                "}\n"
            )
            _write_queue(ws, [
                {
                    "lead_id": "EQ-020",
                    "likely_severity": "high",
                    "title": "Reentrancy in withdraw",
                    "source_refs": ["src/Vault.sol:2"],
                    "proof_status": "needs_harness",
                }
            ])
            report = _run_json(ws)
            row = report["rows"][0]
            for p in row.get("proposed_controls", []):
                self.assertTrue(
                    p.get("candidate_unvalidated"),
                    f"Proposal not marked candidate_unvalidated: {p}",
                )


if __name__ == "__main__":
    unittest.main()
