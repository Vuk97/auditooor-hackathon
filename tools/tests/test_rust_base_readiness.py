from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-base-readiness.py"


def _import():
    spec = importlib.util.spec_from_file_location("rust_base_readiness_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class RustBaseReadinessTests(unittest.TestCase):
    def test_reports_missing_corpus_and_base_inputs_without_network(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(
                ws / ".auditooor" / "rust_runtime_semantic_blockers.json",
                {
                    "summary": {"crate_count": 2},
                    "runtime_component_family_counts": {"execution_client": 1},
                },
            )
            write_json(
                ws / ".auditooor" / "runtime_dlt_execution_evidence_validator.json",
                {
                    "dlt_row_count": 3,
                    "closure_candidate_count": 0,
                    "summary": {"blocker_counts": {"execution_manifest_not_proved": 3}},
                },
            )
            write_json(ws / ".auditooor" / "rust_source_graph.json", {"_meta": {"crate_count": 2}})
            write_json(ws / ".auditooor" / "rust_cross_crate_graph.json", {"_meta": {"edge_count": 4}})
            write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {"declared_root_count": 0, "ready_root_count": 0, "source_file_count": 0},
            )

            payload = mod.build_payload(ws)

        self.assertFalse(payload["operator_answer"]["mined_all_rustbugs"])
        self.assertFalse(payload["operator_answer"]["mined_all_zkbugs"])
        self.assertFalse(payload["operator_answer"]["rust_scans_fetch_all_code"])
        self.assertFalse(payload["operator_answer"]["scope_impact_oos_ready"])
        self.assertFalse(payload["operator_answer"]["smart_contract_roots_ready"])
        self.assertFalse(payload["operator_answer"]["rust_dlt_roots_ready"])
        self.assertTrue(payload["rust_scan"]["rust_source_graph_present"])
        self.assertFalse(payload["operator_answer"]["can_run_base_now"])
        self.assertIn("rustbugs_corpus_not_supported_or_not_ingested", payload["blockers"])
        self.assertIn("project_source_roots_missing", payload["blockers"])
        self.assertIn("fresh_base_root_not_declared", payload["blockers"])
        self.assertIn("scope_input_missing_or_placeholder", payload["blockers"])
        self.assertIn("impact_rubric_missing_or_placeholder", payload["blockers"])
        self.assertIn("operator_oos_missing", payload["blockers"])

    def test_positive_base_scan_readiness_requires_scan_summary_and_base_root(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            base = ws / "external" / "base"
            contracts = ws / "external" / "base-contracts"
            (base / "crates" / "node" / "src").mkdir(parents=True)
            (contracts / "src").mkdir(parents=True)
            (base / "Cargo.toml").write_text("[workspace]\nmembers = [\"crates/node\"]\n", encoding="utf-8")
            (base / "crates" / "node" / "src" / "lib.rs").write_text("pub fn run() {}\n", encoding="utf-8")
            (contracts / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n", encoding="utf-8")
            (contracts / "src" / "Bridge.sol").write_text("contract Bridge {}\n", encoding="utf-8")
            (ws / "SCOPE.md").write_text("Smart contracts and Blockchain/DLT components are in scope.\n", encoding="utf-8")
            (ws / "OOS_PASTED.md").write_text("- Social engineering\n", encoding="utf-8")
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text("Critical: direct theft of user funds.\n", encoding="utf-8")
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text("Critical: consensus safety failure.\n", encoding="utf-8")
            write_json(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", {"root_count": 1})
            write_json(ws / ".auditooor" / "rust_source_graph.json", {"_meta": {"crate_count": 1}})
            write_json(ws / ".auditooor" / "rust_cross_crate_graph.json", {"_meta": {"edge_count": 1}})
            write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {"declared_root_count": 1, "ready_root_count": 1, "source_file_count": 1},
            )

            payload = mod.build_payload(ws, base_root=base, smart_contract_roots=[contracts])

        self.assertTrue(payload["operator_answer"]["can_run_base_now"])
        self.assertTrue(payload["operator_answer"]["scope_impact_oos_ready"])
        self.assertTrue(payload["operator_answer"]["smart_contract_roots_ready"])
        self.assertTrue(payload["operator_answer"]["rust_dlt_roots_ready"])
        self.assertEqual(payload["base_refresh"]["cargo_manifest_count"], 1)
        self.assertEqual(payload["base_refresh"]["rust_source_file_count"], 1)
        self.assertNotIn("scan_rust_summary_missing", payload["blockers"])
        self.assertNotIn("project_source_roots_missing", payload["blockers"])
        self.assertNotIn("fresh_base_root_not_declared", payload["blockers"])
        self.assertNotIn("smart_contract_roots_missing", payload["blockers"])
        self.assertNotIn("rust_dlt_roots_missing", payload["blockers"])

    def test_missing_smart_contract_root_blocks_even_when_rust_dlt_root_is_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            reth = ws / "external" / "base-reth"
            (reth / "crates" / "node" / "src").mkdir(parents=True)
            (reth / "Cargo.toml").write_text("[workspace]\nmembers = [\"crates/node\"]\n", encoding="utf-8")
            (reth / "crates" / "node" / "src" / "lib.rs").write_text("pub fn run() {}\n", encoding="utf-8")
            (ws / "SCOPE.md").write_text("Smart contracts and Blockchain/DLT components are in scope.\n", encoding="utf-8")
            (ws / "OOS_PASTED.md").write_text("- Social engineering\n", encoding="utf-8")
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text("Critical: direct theft of user funds.\n", encoding="utf-8")
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text("Critical: consensus safety failure.\n", encoding="utf-8")
            write_json(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", {"root_count": 1})
            write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {
                    "declared_root_count": 1,
                    "ready_root_count": 1,
                    "source_file_count": 1,
                    "roots": [
                        {
                            "label": "base-reth",
                            "usable": True,
                            "expected_languages": ["rust"],
                            "language_presence": {"rust": 1, "solidity": 0},
                            "sample_files": [{"suffix": ".rs"}],
                        }
                    ],
                },
            )

            payload = mod.build_payload(ws, base_root=reth, reth_roots=[reth])

        self.assertFalse(payload["operator_answer"]["can_run_base_now"])
        self.assertFalse(payload["operator_answer"]["smart_contract_roots_ready"])
        self.assertTrue(payload["operator_answer"]["rust_dlt_roots_ready"])
        self.assertIn("smart_contract_roots_missing", payload["blockers"])
        self.assertNotIn("rust_dlt_roots_missing", payload["blockers"])

    def test_missing_rust_dlt_root_blocks_even_when_smart_contract_root_is_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            contracts = ws / "external" / "base-contracts"
            (contracts / "src").mkdir(parents=True)
            (contracts / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n", encoding="utf-8")
            (contracts / "src" / "Bridge.sol").write_text("contract Bridge {}\n", encoding="utf-8")
            (ws / "SCOPE.md").write_text("Smart contracts and Blockchain/DLT components are in scope.\n", encoding="utf-8")
            (ws / "OOS_PASTED.md").write_text("- Social engineering\n", encoding="utf-8")
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text("Critical: direct theft of user funds.\n", encoding="utf-8")
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text("Critical: consensus safety failure.\n", encoding="utf-8")
            write_json(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", {"root_count": 0})
            write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {
                    "declared_root_count": 1,
                    "ready_root_count": 1,
                    "source_file_count": 1,
                    "roots": [
                        {
                            "label": "base-contracts",
                            "usable": True,
                            "expected_languages": ["solidity"],
                            "language_presence": {"rust": 0, "solidity": 1},
                            "sample_files": [{"suffix": ".sol"}],
                        }
                    ],
                },
            )

            payload = mod.build_payload(ws, smart_contract_roots=[contracts])

        self.assertFalse(payload["operator_answer"]["can_run_base_now"])
        self.assertTrue(payload["operator_answer"]["smart_contract_roots_ready"])
        self.assertFalse(payload["operator_answer"]["rust_dlt_roots_ready"])
        self.assertIn("rust_dlt_roots_missing", payload["blockers"])
        self.assertNotIn("smart_contract_roots_missing", payload["blockers"])

    def test_reth_tee_zk_deep_runtime_requires_component_roots_and_runtime_artifacts(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            reth = ws / "external" / "reth"
            tee = ws / "external" / "tee"
            zk = ws / "external" / "zk"
            for root in (reth, tee, zk):
                (root / "src").mkdir(parents=True)
                (root / "Cargo.toml").write_text("[package]\nname = \"demo\"\nversion = \"0.1.0\"\n", encoding="utf-8")
                (root / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
            write_json(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", {"root_count": 3})
            write_json(ws / ".auditooor" / "rust_cross_crate_graph.json", {"_meta": {"edge_count": 3}})
            write_json(ws / ".auditooor" / "runtime_dlt_execution_evidence_validator.json", {"dlt_row_count": 1})

            payload = mod.build_payload(ws, reth_roots=[reth], tee_roots=[tee], zk_roots=[zk])

        self.assertTrue(payload["root_roles"]["reth_roots_ready"])
        self.assertTrue(payload["root_roles"]["tee_roots_ready"])
        self.assertTrue(payload["root_roles"]["zk_roots_ready"])
        self.assertTrue(payload["operator_answer"]["base_reth_tee_zk_deep_runtime_ready"])

    def test_zkbugs_repo_content_indexed_and_queued_does_not_require_provider_pull(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(
                ws / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json",
                {"summary": {"total": 2}, "briefs": ["a.md", "b.md"]},
            )
            write_json(
                ws / ".audit_logs" / "zkbugs_farming" / "provider_queue" / "zkbugs_provider_queue.json",
                {"rows": [{"id": "a"}]},
            )

            payload = mod.build_payload(ws)

        self.assertEqual(payload["zkbugs"]["status"], "repo_content_indexed_and_queued")
        self.assertTrue(payload["zkbugs"]["fully_mined"])
        self.assertFalse(payload["zkbugs"]["provider_pull_recorded"])
        self.assertEqual(payload["zkbugs"]["total_records"], 2)
        self.assertNotIn("zkbugs_corpus_not_fully_ingested_or_queued", payload["blockers"])

    def test_cli_writes_json_and_markdown(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rc = mod.main(["--workspace", str(ws)])

            self.assertEqual(rc, 0)
            self.assertTrue((ws / ".auditooor" / "rust_base_scan_readiness.json").is_file())
            text = (ws / ".auditooor" / "rust_base_scan_readiness.md").read_text(encoding="utf-8")
            self.assertIn("Mined all RustBugs", text)
            self.assertIn("Base Refresh Commands", text)
            self.assertIn("Operator Bootstrap Checklist", text)
            self.assertIn("project-source-root-readiness", text)
            self.assertIn("Scope / Roots / Live Preconditions", text)

    def test_consumes_rust_scan_readiness_artifact(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            write_json(
                ws / "scanners" / "rust" / "RUST_SCAN_READINESS.json",
                {
                    "schema": "auditooor.rust_scan_readiness.v1",
                    "root_count": 0,
                    "roots": [],
                    "missing_tools": ["cargo-audit", "semgrep"],
                    "tool_available": {"cargo_audit": False, "semgrep": False, "clippy": True},
                    "can_run_scan_rust": False,
                    "blockers": ["rust_roots_missing", "cargo_audit_and_semgrep_missing"],
                },
            )

            payload = mod.build_payload(ws)

        self.assertTrue(payload["rust_scan"]["readiness_present"])
        self.assertFalse(payload["rust_scan"]["readiness_can_run_scan_rust"])
        self.assertEqual(payload["rust_scan"]["readiness_root_count"], 0)
        self.assertIn("semgrep", payload["rust_scan"]["readiness_missing_tools"])
        self.assertIn("scan_rust_readiness_rust_roots_missing", payload["blockers"])
        self.assertIn("scan_rust_readiness_cargo_audit_and_semgrep_missing", payload["blockers"])
        rendered = mod.render_markdown(payload)
        self.assertIn("scan-rust readiness present", rendered)
        self.assertIn("missing tools `cargo-audit, semgrep`", rendered)


if __name__ == "__main__":
    unittest.main()
