from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "base-scan-preflight.py"


def _import():
    spec = importlib.util.spec_from_file_location("base_scan_preflight_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, text: str = "populated non-placeholder content for test coverage\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _make_ready_workspace(ws: Path) -> None:
    _write(ws / "SCOPE.md", "# Scope\nBase smart contracts and Base/reth DLT components are in scope.\n")
    _write(ws / "SEVERITY_SMART_CONTRACTS.md", "# Smart severity\nHigh impact includes loss of funds and state corruption.\n")
    _write(ws / "SEVERITY_BLOCKCHAIN_DLT.md", "# DLT severity\nHigh impact includes consensus safety and liveness failures.\n")
    _write(ws / "RUBRIC_COVERAGE.md", "# Rubric coverage\nEvery smart-contract and Blockchain/DLT severity row is mapped.\n")
    _write(ws / "OOS_PASTED.md", "# OOS\nKnown exclusions pasted from the bounty program.\n")

    _write_json(
        ws / ".auditooor" / "project_source_root_readiness.json",
        {
            "declared_root_count": 2,
            "ready_root_count": 2,
            "roots": [
                {"label": "base-contracts", "usable": True, "language_presence": {"solidity": 3, "rust": 0}},
                {"label": "base-reth", "usable": True, "language_presence": {"solidity": 0, "rust": 5}},
            ],
        },
    )

    _write_json(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", {"status": "ok", "roots": ["external/base-reth"]})
    _write(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md", "# Rust scan summary\nRan successfully.\n")
    _write_json(ws / ".auditooor" / "semantic_graph.json", {"entrypoints": [{"file": "src/Bridge.sol"}]})
    _write(ws / ".auditooor" / "semantic_graph.md", "# Semantic graph\nEntrypoints present.\n")
    _write_json(ws / "live_topology_checks.json", {"rows": [{"id": "L1", "status": "executed"}]})
    _write(ws / "LIVE_TOPOLOGY.md", "# Live topology\nExecuted row L1.\n")

    _write_json(
        ws / ".auditooor" / "rust_corpus_validation.json",
        {
            "acceptance": {"detectorization_unblocked": True},
            "summary": {"found_total": 151, "expected_total": 151, "blocker_count": 0},
            "blockers": [],
        },
    )
    _write_json(
        ws / ".auditooor" / "rust_swival_route_evidence.json",
        {
            "summary": {"row_count": 151, "blocker_count": 0},
            "blockers": [],
            "rows": [{"item_id": "H-001"}],
        },
    )

    _write_json(ws / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json", {"summary": {"total": 10}})
    _write_json(
        ws / ".audit_logs" / "zkbugs_farming" / "provider_queue" / "zkbugs_provider_queue.json",
        {"rows": [{"id": "zk-1"}]},
    )
    _write(ws / ".auditooor" / "zkbugs_last_pull", "2026-05-01T00:00:00Z\n")

    _write_json(
        ws / ".auditooor" / "rust_runtime_semantic_blockers.json",
        {"runtime_component_family_counts": {"consensus": 1}},
    )
    _write_json(
        ws / ".auditooor" / "runtime_dlt_execution_evidence_validator.json",
        {"dlt_row_count": 2, "closure_candidate_count": 1, "rows": [{"id": "dlt-1"}]},
    )


class BaseScanPreflightTests(unittest.TestCase):
    def test_blocked_workspace_emits_ordered_next_commands_and_artifacts(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            payload = mod.build_payload(ws)
            rc = mod.main(["--workspace", str(ws)])
            artifact = json.loads((ws / ".auditooor" / "base_scan_preflight.json").read_text(encoding="utf-8"))
            md = (ws / ".auditooor" / "base_scan_preflight.md").read_text(encoding="utf-8")

        self.assertEqual(rc, 0)
        self.assertEqual(payload["status"], "BLOCKED")
        self.assertFalse(payload["can_start_base_scan"])
        self.assertGreater(payload["blocker_count"], 0)
        self.assertEqual(payload["next_commands"][0], "pbpaste > <base_ws>/SCOPE.md")
        gate_statuses = {gate["id"]: gate["status"] for gate in payload["gates"]}
        self.assertEqual(gate_statuses["scope_impact_oos"], "BLOCKED")
        self.assertEqual(gate_statuses["source_roots"], "BLOCKED")
        self.assertEqual(artifact["status"], "BLOCKED")
        self.assertIn("# Base Scan Preflight", md)
        self.assertIn("Status: `BLOCKED`", md)

    def test_ready_workspace_passes_and_points_to_scan_chain(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_ready_workspace(ws)
            payload = mod.build_payload(ws)
            rc = mod.main(["--workspace", str(ws)])
            artifact = json.loads((ws / ".auditooor" / "base_scan_preflight.json").read_text(encoding="utf-8"))
            md = (ws / ".auditooor" / "base_scan_preflight.md").read_text(encoding="utf-8")

        self.assertEqual(rc, 0)
        self.assertEqual(payload["status"], "PASS")
        self.assertTrue(payload["can_start_base_scan"])
        self.assertEqual(payload["blocker_count"], 0)
        self.assertTrue(payload["next_commands"][0].startswith("python3 tools/engage.py --workspace <base_ws> --stages"))
        self.assertTrue(all(gate["status"] in {"PASS", "SKIPPED"} for gate in payload["gates"]))
        gate_statuses = {gate["id"]: gate["status"] for gate in payload["gates"]}
        self.assertEqual(gate_statuses["zkbugs_corpus"], "SKIPPED")
        self.assertEqual(artifact["status"], "PASS")
        self.assertIn("Status: `PASS`", md)

    def test_solidity_only_workspace_skips_rust_dlt_and_zk_corpus_blockers(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "SCOPE.md", "# Scope\nOnly Solidity contracts under contracts/ are in scope.\n")
            _write(ws / "SEVERITY.md", "# Severity\nMedium and High smart-contract impacts only.\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Rubric\nSmart-contract impact rows are mapped.\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nOut-of-scope text pasted.\n")
            _write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {
                    "roots": [
                        {"label": "contracts", "usable": True, "language_presence": {"solidity": 2, "rust": 0}},
                    ],
                },
            )
            _write_json(ws / ".auditooor" / "semantic_graph.json", {"entrypoints": [{"file": "contracts/Vault.sol"}]})
            _write(ws / ".auditooor" / "semantic_graph.md", "# Semantic graph\nEntrypoints present.\n")
            _write_json(ws / "live_topology_checks.json", {"rows": [{"id": "L1"}]})
            _write(ws / "LIVE_TOPOLOGY.md", "# Live topology\nRows present.\n")

            payload = mod.build_payload(ws)

        gate_statuses = {gate["id"]: gate["status"] for gate in payload["gates"]}
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(gate_statuses["scan_rust_summary"], "SKIPPED")
        self.assertEqual(gate_statuses["swival_corpus"], "SKIPPED")
        self.assertEqual(gate_statuses["zkbugs_corpus"], "SKIPPED")
        self.assertEqual(gate_statuses["runtime_dlt_evidence"], "SKIPPED")
        self.assertFalse(any("Rust/DLT" in blocker or "Swival" in blocker or "zkBugs" in blocker for blocker in payload["blockers"]))

    def test_empty_live_topology_requirements_skip_live_topology_gate(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "SCOPE.md", "# Scope\nOnly Solidity contracts under contracts/ are in scope.\n")
            _write(ws / "SEVERITY.md", "# Severity\nMedium and High smart-contract impacts only.\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Rubric\nSmart-contract impact rows are mapped.\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nOut-of-scope text pasted.\n")
            _write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {
                    "roots": [
                        {"label": "contracts", "usable": True, "language_presence": {"solidity": 2, "rust": 0}},
                    ],
                },
            )
            _write_json(ws / ".auditooor" / "semantic_graph.json", {"entrypoints": [{"file": "contracts/Vault.sol"}]})
            _write(ws / ".auditooor" / "semantic_graph.md", "# Semantic graph\nEntrypoints present.\n")
            _write_json(ws / ".auditooor" / "live_topology_proof_requirements.json", {"requirements": []})
            _write_json(
                ws / "monitoring" / "live_topology_proof_requirements.generated.json",
                {"schema": "auditooor.live_check_spec.v1", "checks": []},
            )

            payload = mod.build_payload(ws)

        gate_statuses = {gate["id"]: gate["status"] for gate in payload["gates"]}
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(gate_statuses["live_topology"], "SKIPPED")

    def test_rust_dlt_scope_keeps_rust_runtime_blockers(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "SCOPE.md", "# Scope\nSolidity contracts and Blockchain/DLT runtime components are in scope.\n")
            _write(ws / "SEVERITY.md", "# Severity\nSmart-contract and runtime impacts are in scope.\n")
            _write(ws / "SEVERITY_BLOCKCHAIN_DLT.md", "# DLT severity\nConsensus and liveness failures are in scope.\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Rubric\nAll rows mapped.\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nPasted.\n")
            _write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {
                    "roots": [
                        {"label": "contracts", "usable": True, "language_presence": {"solidity": 2, "rust": 0}},
                    ],
                },
            )

            payload = mod.build_payload(ws)

        self.assertEqual(payload["status"], "BLOCKED")
        self.assertIn("no Rust/DLT source root declared", payload["blockers"])
        self.assertIn("scanners/rust/SCAN_RUST_SUMMARY.json missing", payload["blockers"])
        self.assertIn("rust runtime semantic blockers artifact missing", payload["blockers"])


if __name__ == "__main__":
    unittest.main()
