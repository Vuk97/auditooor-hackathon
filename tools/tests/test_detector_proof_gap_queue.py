"""Tests for detector-proof-gap-queue.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-proof-gap-queue.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("detector_proof_gap_queue", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["detector_proof_gap_queue"] = module
    spec.loader.exec_module(module)
    return module


def _fixture_inventory() -> dict:
    return {
        "schema": "auditooor.scanner_wiring_truth_inventory.v1",
        "limit": 99,
        "item_count": 7,
        "total_row_count": 7,
        "truncated": False,
        "rows": [
            {
                "scanner_id": "rust_shape",
                "pattern_id": "",
                "backend": "rust",
                "source_paths": ["detectors/rust_wave1/rust_shape.py"],
                "evidence_kind": "detector_python",
                "wiring_status": "rust_source_shape_only",
                "proof_status": "source_shape_only",
                "blockers": [
                    "positive_or_vulnerable_fixture_missing",
                    "clean_or_negative_fixture_missing",
                    "rust_runtime_semantics_unverified",
                ],
                "suggested_next_action": "lift rust proof",
                "memory_priority": 90,
            },
            {
                "scanner_id": "move-backend-executor",
                "pattern_id": "",
                "backend": "move",
                "source_paths": [],
                "evidence_kind": "backend_executor_signal",
                "wiring_status": "backend_executor_missing_or_tbd",
                "proof_status": "no_known_executor_signal_found",
                "blockers": ["move_executor_missing_or_unknown"],
                "suggested_next_action": "add move executor",
                "memory_priority": 85,
            },
            {
                "scanner_id": "almost_fixture_backed",
                "pattern_id": "",
                "backend": "solidity",
                "source_paths": [
                    "detectors/wave18/almost_fixture_backed.py",
                    "detectors/test_fixtures/almost_fixture_backed_vulnerable.sol",
                ],
                "evidence_kind": "detector_python",
                "wiring_status": "generated_no_fixture",
                "proof_status": "detector_without_fixture_pair",
                "blockers": ["clean_or_negative_fixture_missing"],
                "suggested_next_action": "add clean fixture",
                "memory_priority": 75,
            },
            {
                "scanner_id": "",
                "pattern_id": "dsl_only",
                "backend": "solidity",
                "source_paths": ["reference/patterns.dsl/dsl_only.yaml"],
                "evidence_kind": "dsl_yaml",
                "wiring_status": "dsl_only_or_unverified",
                "proof_status": "no_detector_or_fixture_evidence",
                "blockers": ["detector_file_missing", "fixture_pair_missing"],
                "suggested_next_action": "wire detector",
                "memory_priority": 70,
            },
            {
                "scanner_id": "fake_guard",
                "pattern_id": "",
                "backend": "solidity",
                "source_paths": ["detectors/wave14/_quarantine/fake_guard.py"],
                "evidence_kind": "detector_python",
                "wiring_status": "quarantined_fake",
                "proof_status": "quarantined_or_fake_detector_artifact",
                "blockers": ["detector_must_not_count_as_wired"],
                "suggested_next_action": "retire",
                "memory_priority": 100,
            },
            {
                "scanner_id": "verified_detector",
                "pattern_id": "",
                "backend": "rust",
                "source_paths": [
                    "detectors/rust_wave1/verified_detector.py",
                    "detectors/rust_wave1/test_fixtures/verified_detector_positive.rs",
                    "detectors/rust_wave1/test_fixtures/verified_detector_negative.rs",
                ],
                "evidence_kind": "detector_python",
                "wiring_status": "wired_verified",
                "proof_status": "detector_and_fixture_pair_present",
                "blockers": [],
                "suggested_next_action": "keep wired",
                "memory_priority": 20,
            },
            {
                "scanner_id": "",
                "pattern_id": "scanner-overview",
                "backend": "unknown",
                "source_paths": ["docs/SCANNER_OVERVIEW.md"],
                "evidence_kind": "doc_artifact",
                "wiring_status": "documentation_only",
                "proof_status": "report_or_doc_only",
                "blockers": ["documentation_is_not_detector_wiring_proof"],
                "suggested_next_action": "docs only",
                "memory_priority": 30,
            },
        ],
    }


class DetectorProofGapQueueTests(unittest.TestCase):
    def test_build_gap_queue_sections_are_bounded_and_actionable(self) -> None:
        tool = _load_tool()
        queue = tool.build_gap_queue(_fixture_inventory(), section_limit=1, full_throttle_limit=6, repo_root=ROOT)

        self.assertEqual(queue["schema"], "auditooor.detector_proof_gap_queue.v1")
        self.assertEqual(set(queue["sections"]), set(tool.SECTIONS))
        self.assertEqual(queue["fixture_needed"], queue["sections"]["fixture_needed"])
        self.assertEqual(queue["sections"]["fixture_needed"]["emitted"], 1)
        self.assertTrue(queue["sections"]["fixture_needed"]["truncated"])
        self.assertEqual(
            queue["sections"]["fixture_needed"]["rows"][0]["queue_id"],
            "almost_fixture_backed",
        )
        self.assertGreater(
            queue["sections"]["fixture_needed"]["rows"][0]["actionability_score"],
            queue["sections"]["docs_only"]["rows"][0]["actionability_score"],
        )
        self.assertEqual(queue["sections"]["rust_lift_needed"]["rows"][0]["suggested_test_command"], "bash detectors/rust_wave1/test_fixtures/test_detectors.sh --detector=rust_shape")
        self.assertIn("No validity claim", queue["sections"]["rust_lift_needed"]["rows"][0]["claim_guard"])
        self.assertIn("Fixture/proof evidence is present", queue["sections"]["proof_verified"]["rows"][0]["claim_guard"])

    def test_full_throttle_keeps_real_repair_work_above_fake_cleanup(self) -> None:
        tool = _load_tool()
        queue = tool.build_gap_queue(_fixture_inventory(), section_limit=3, full_throttle_limit=4, repo_root=ROOT)
        sections = [item["section"] for item in queue["full_throttle"]["rows"]]
        self.assertIn("rust_lift_needed", sections[:3])
        self.assertIn("backend_needed", sections[:3])
        self.assertIn("fixture_needed", sections[:3])
        self.assertNotEqual(sections[0], "retire_fake_candidate")

    def test_source_burndown_rank_orders_fixture_rows_before_score(self) -> None:
        tool = _load_tool()
        burndown = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "unique_action_count": 2,
            "actions": [
                {
                    "lane": "add_fixture_or_proof",
                    "row_id": "dsl_only",
                    "rank": 1,
                },
                {
                    "lane": "add_fixture_or_proof",
                    "row_id": "almost_fixture_backed",
                    "rank": 20,
                },
            ],
        }

        queue = tool.build_gap_queue(
            _fixture_inventory(),
            burndown,
            section_limit=3,
            full_throttle_limit=6,
            repo_root=ROOT,
        )

        fixture_rows = queue["sections"]["fixture_needed"]["rows"]
        self.assertEqual(fixture_rows[0]["queue_id"], "dsl_only")
        self.assertEqual(fixture_rows[0]["source_burndown_rank"], 1)
        self.assertEqual(fixture_rows[1]["queue_id"], "almost_fixture_backed")
        self.assertEqual(fixture_rows[1]["source_burndown_rank"], 20)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            inventory_path = ws / "inventory.json"
            burndown_path = ws / "burndown.json"
            json_out = ws / "queue.json"
            md_out = ws / "queue.md"
            inventory_path.write_text(json.dumps(_fixture_inventory()), encoding="utf-8")
            burndown_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "unique_action_count": 1,
                        "actions": [
                            {
                                "lane": "rust_detector_lift",
                                "row_id": "rust_shape",
                                "rank": 4,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--inventory",
                    str(inventory_path),
                    "--burndown",
                    str(burndown_path),
                    "--repo-root",
                    str(ROOT),
                    "--json-out",
                    str(json_out),
                    "--md-out",
                    str(md_out),
                    "--section-limit",
                    "2",
                    "--full-throttle-limit",
                    "5",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["sections"]["rust_lift_needed"]["rows"][0]["source_burndown_rank"], 4)
            self.assertTrue(json_out.is_file())
            self.assertTrue(md_out.is_file())
            markdown = md_out.read_text(encoding="utf-8")
            self.assertIn("Detector Proof Gap Queue", markdown)
            self.assertIn("Full Throttle Queue", markdown)
            self.assertIn("No validity claim", markdown)

    def test_cli_defaults_to_latest_compatible_inventory_and_burndown_when_omitted(self) -> None:
        def inventory_for(scanner_id: str) -> dict:
            packet = _fixture_inventory()
            packet["rows"] = [
                {
                    "scanner_id": scanner_id,
                    "pattern_id": "",
                    "backend": "solidity",
                    "source_paths": [
                        f"detectors/wave18/{scanner_id}.py",
                        f"detectors/test_fixtures/{scanner_id}_vulnerable.sol",
                    ],
                    "evidence_kind": "detector_python",
                    "wiring_status": "generated_no_fixture",
                    "proof_status": "detector_without_fixture_pair",
                    "blockers": ["clean_or_negative_fixture_missing"],
                    "suggested_next_action": "add clean fixture",
                    "memory_priority": 50,
                }
            ]
            return packet

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            (reports / "scanner_wiring_truth_inventory_2026-05-05.json").write_text(
                json.dumps(inventory_for("old_inventory_row")),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_truth_inventory_2026-05-08-l24.json").write_text(
                json.dumps(inventory_for("latest_inventory_row")),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_burndown_queue_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "unique_action_count": 1,
                        "actions": [{"lane": "add_fixture_or_proof", "row_id": "old_inventory_row", "rank": 1}],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_burndown_queue_2026-05-08-l24.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "unique_action_count": 1,
                        "actions": [{"lane": "add_fixture_or_proof", "row_id": "latest_inventory_row", "rank": 3}],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_burndown_queue_l22_enhanced_2026-05-09.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue_l22.v1",
                        "ranked_queue": [{"row_id": "wrong_schema_row"}],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--section-limit",
                    "5",
                    "--full-throttle-limit",
                    "5",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)

        fixture_rows = payload["sections"]["fixture_needed"]["rows"]
        self.assertEqual(payload["source_inventory_path"], "reports/scanner_wiring_truth_inventory_2026-05-08-l24.json")
        self.assertEqual(payload["source_burndown_path"], "reports/scanner_wiring_burndown_queue_2026-05-08-l24.json")
        self.assertEqual([row["queue_id"] for row in fixture_rows], ["latest_inventory_row"])
        self.assertEqual(fixture_rows[0]["source_burndown_rank"], 3)

    def test_cli_latest_inventory_skips_wrong_schema_even_when_newer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            inventory = _fixture_inventory()
            inventory["rows"] = [inventory["rows"][2]]
            inventory["rows"][0]["scanner_id"] = "compatible_inventory_row"
            (reports / "scanner_wiring_truth_inventory_2026-05-08.json").write_text(
                json.dumps(inventory),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_truth_inventory_2026-05-09.json").write_text(
                json.dumps({"schema": "wrong.schema", "rows": [{"scanner_id": "wrong_schema_row"}]}),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_burndown_queue_2026-05-08.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actions": [{"lane": "add_fixture_or_proof", "row_id": "compatible_inventory_row", "rank": 1}],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--section-limit",
                    "5",
                    "--full-throttle-limit",
                    "5",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)

        self.assertEqual(payload["source_inventory_path"], "reports/scanner_wiring_truth_inventory_2026-05-08.json")
        self.assertEqual(payload["sections"]["fixture_needed"]["rows"][0]["queue_id"], "compatible_inventory_row")


if __name__ == "__main__":
    unittest.main()
