from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-binding-source-import-readiness.py"


def _import():
    spec = importlib.util.spec_from_file_location("impact_binding_source_import_readiness_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ImpactBindingSourceImportReadinessTests(unittest.TestCase):
    def test_terminalizes_when_no_ready_project_source_roots_exist(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            discovery = ws / ".auditooor" / "impact_binding_source_harness_discovery.json"
            readiness = ws / ".auditooor" / "project_source_root_readiness.json"
            _write_json(
                discovery,
                {
                    "reductions": [
                        {
                            "candidate_id": "imo-critical-access-control-01",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "requirement": "candidate_bound_project_source_citation",
                            "discovery_status": "terminal_no_project_source_roots",
                        },
                        {
                            "candidate_id": "imo-critical-access-control-01",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "terminal_harness_blocked_no_project_source_roots",
                        },
                    ]
                },
            )
            _write_json(readiness, {"roots": []})

            payload = mod.build_payload(ws, discovery_path=discovery, readiness_path=readiness)

        self.assertEqual(payload["source_import_unit_count"], 2)
        self.assertEqual(payload["ready_source_file_count"], 0)
        self.assertEqual(payload["line_hit_unit_count"], 0)
        self.assertEqual(payload["summary"]["source_import_status_counts"]["terminal_no_ready_project_source_roots"], 2)
        self.assertFalse(payload["promotion_allowed"])

    def test_real_ready_root_emits_line_level_source_and_harness_review_units(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "target_project" / "src"
            src.mkdir(parents=True)
            source_file = src / "OracleSettlement.sol"
            source_file.write_text(
                "\n".join(
                    [
                        "contract OracleSettlement {",
                        "  function settle(uint256 price) external {",
                        "    require(price > 0, 'oracle price');",
                        "  }",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            discovery = ws / ".auditooor" / "impact_binding_source_harness_discovery.json"
            readiness = ws / ".auditooor" / "project_source_root_readiness.json"
            _write_json(
                discovery,
                {
                    "reductions": [
                        {
                            "candidate_id": "imo-high-oracle-settlement-01",
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "discovery_status": "candidate_project_source_hints_require_manual_citation",
                        },
                        {
                            "candidate_id": "imo-high-oracle-settlement-01",
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "harness_binding_hints_require_project_setup",
                        },
                    ]
                },
            )
            _write_json(
                readiness,
                {
                    "roots": [
                        {
                            "label": "target",
                            "usable": True,
                            "sample_files": [
                                {
                                    "file": "target_project/src/OracleSettlement.sol",
                                    "abs_path": str(source_file),
                                    "suffix": ".sol",
                                }
                            ],
                        }
                    ]
                },
            )

            payload = mod.build_payload(
                ws,
                discovery_path=discovery,
                readiness_path=readiness,
                bundle_dir=ws / ".auditooor" / "source_import_bundles",
            )
            self.assertTrue((ws / ".auditooor" / "source_import_bundles" / "oracle_settlement.json").exists())

        statuses = {row["requirement"]: row["source_import_status"] for row in payload["units"]}
        self.assertEqual(statuses["candidate_bound_project_source_citation"], "source_review_candidate_lines_found")
        self.assertEqual(statuses["project_specific_harness_execution"], "harness_binding_candidate_lines_found")
        self.assertEqual(payload["line_hit_unit_count"], 2)
        self.assertEqual(payload["closure_candidate_count"], 0)
        self.assertIn("source-proof-record", payload["units"][0]["next_command"])

    def test_ready_root_without_candidate_line_hits_stays_terminal_without_promotion(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "target_project" / "src"
            src.mkdir(parents=True)
            source_file = src / "Vault.sol"
            source_file.write_text("contract Vault { function deposit() external {} }\n", encoding="utf-8")
            discovery = ws / ".auditooor" / "impact_binding_source_harness_discovery.json"
            readiness = ws / ".auditooor" / "project_source_root_readiness.json"
            _write_json(
                discovery,
                {
                    "reductions": [
                        {
                            "candidate_id": "imo-high-oracle-settlement-01",
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "discovery_status": "terminal_no_candidate_family_match_in_project_sources",
                        }
                    ]
                },
            )
            _write_json(
                readiness,
                {
                    "roots": [
                        {
                            "label": "target",
                            "usable": True,
                            "sample_files": [
                                {
                                    "file": "target_project/src/Vault.sol",
                                    "abs_path": str(source_file),
                                    "suffix": ".sol",
                                }
                            ],
                        }
                    ]
                },
            )

            payload = mod.build_payload(ws, discovery_path=discovery, readiness_path=readiness)

        self.assertEqual(payload["ready_source_file_count"], 1)
        self.assertEqual(payload["line_hit_unit_count"], 0)
        self.assertEqual(payload["units"][0]["source_import_status"], "terminal_no_candidate_line_hits_in_project_source")
        self.assertFalse(payload["units"][0]["promotion_allowed"])


if __name__ == "__main__":
    unittest.main()
