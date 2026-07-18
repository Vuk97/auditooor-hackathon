from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "known-limitations-dispatch.py"


def load_module():
    spec = importlib.util.spec_from_file_location("known_limitations_dispatch", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestKnownLimitationsDispatch(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_build_dispatch_report_classifies_and_schedules_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            (root / "docs").mkdir()
            (root / "tools" / "tests").mkdir(parents=True)
            for relative_path in (
                "tools/source-ref-replay-manifest.py",
                "tools/tests/test_source_ref_replay_manifest.py",
                "reports/g1_source_root_locator_2026-05-05.json",
                "reports/fallback_handler_address_guard_calibration_2026-05-05.json",
                "docs/HARNESS_FAILURE_MEMORY.md",
                "reports/harness_failures.jsonl",
            ):
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
            input_path = root / "reports" / "known_limitations_burndown_queue_2026-05-05.json"
            input_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_queue.v1",
                        "date": "2026-05-05",
                        "rows": [
                            {
                                "rank": 1,
                                "id": "KLBQ-001",
                                "limitation": "Source refs are lost unless checkout succeeds.",
                                "implementation_status": "partially_implemented_v0",
                                "verification_status": "partial_pass",
                                "concrete_next_patch": "Close the residual artifact gap.",
                                "loop_estimate": "1 loop",
                                "remaining_blockers": ["manifest fixture is still absent locally"],
                                "local_evidence": [
                                    "tools/source-ref-replay-manifest.py",
                                    "tools/tests/test_source_ref_replay_manifest.py",
                                ],
                                "source_refs": [
                                    "reports/source_ref_replay_manifest_fixture.json",
                                ],
                            },
                            {
                                "rank": 2,
                                "id": "KLBQ-002",
                                "limitation": "G1 source replay is blocked by absent local roots.",
                                "implementation_status": "partially_implemented_v0",
                                "verification_status": "pass_with_real_blockers_remaining",
                                "concrete_next_patch": "Acquire the exact local source roots.",
                                "loop_estimate": "1 loop",
                                "remaining_blockers": ["exact local source roots are absent"],
                                "source_refs": [
                                    "reports/g1_source_root_locator_2026-05-05.json",
                                ],
                            },
                            {
                                "rank": 6,
                                "id": "KLBQ-006",
                                "limitation": "R94 fallback-handler detector family is calibration-only.",
                                "implementation_status": "partially_implemented_v0",
                                "verification_status": "partial_pass",
                                "concrete_next_patch": "Run broader bounded precision.",
                                "loop_estimate": "1 loop",
                                "local_evidence": [
                                    "reports/fallback_handler_address_guard_calibration_2026-05-05.json",
                                ],
                            },
                            {
                                "rank": 7,
                                "id": "KLBQ-007",
                                "limitation": "Harness-failure memory is aggregate root-cause state.",
                                "concrete_next_patch": "Add harness-failure event rows.",
                                "loop_estimate": "2 loops",
                                "source_refs": [
                                    "docs/HARNESS_FAILURE_MEMORY.md",
                                    "reports/harness_failures.jsonl",
                                ],
                            },
                            {
                                "rank": 9,
                                "id": "KLBQ-009",
                                "limitation": "Unknown-reason declines are correctly documented.",
                                "implementation_status": "implemented_v0",
                                "verification_status": "pass",
                                "concrete_next_patch": "Preserve the unknown-reason contract.",
                                "loop_estimate": "0 loops",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = self.module.build_dispatch_report(root, input_path)

            self.assertEqual(report["summary"]["known_limitations_total"], 5)
            work_items = {item["limitation_id"]: item for item in report["work_items"]}
            self.assertEqual(work_items["KLBQ-001"]["dispatch_lane"], "commit_mining")
            self.assertEqual(work_items["KLBQ-002"]["dispatch_lane"], "blocked_needs_source")
            self.assertEqual(work_items["KLBQ-006"]["dispatch_lane"], "harness_execution")
            self.assertEqual(work_items["KLBQ-007"]["dispatch_lane"], "memory_handoff")
            self.assertEqual(work_items["KLBQ-009"]["current_status"], "implemented_verified")
            self.assertFalse(work_items["KLBQ-009"]["dispatch_ready"])
            self.assertIn(
                "reports/source_ref_replay_manifest_fixture.json",
                work_items["KLBQ-001"]["missing_evidence_paths"],
            )
            self.assertEqual(report["dispatch_lanes"][:4], [
                "memory_handoff",
                "harness_execution",
                "scanner_wiring",
                "rust_detector_lift",
            ])
            self.assertEqual(
                report["priority_policy"]["known_limitation_burndown_lanes"],
                ["scanner_wiring", "rust_detector_lift", "commit_mining"],
            )
            self.assertEqual(report["top_ready_now"], ["KLBQ-007", "KLBQ-006", "KLBQ-001"])
            self.assertEqual(report["loop_schedule"][0]["items"], ["KLBQ-007", "KLBQ-006"])
            self.assertEqual(report["loop_schedule"][1]["items"], ["KLBQ-001"])

    def test_missing_input_is_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_input = root / "reports" / "missing.json"
            report = self.module.build_dispatch_report(root, missing_input)
            self.assertFalse(report["source_report_present"])
            self.assertEqual(report["work_items"], [])
            self.assertIn("missing input report", report["issues"][0])

    def test_default_input_path_prefers_latest_local_burndown_queue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            newest = root / "reports" / "known_limitations_burndown_queue_2026-05-06.json"
            newest.write_text("{}", encoding="utf-8")

            resolved = self.module.default_input_path(root)

        self.assertEqual(resolved, newest)

    def test_klbq_010_uses_local_preflight_status_packet_for_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            input_path = root / "reports" / "known_limitations_burndown_queue_2026-05-05.json"
            input_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_queue.v1",
                        "date": "2026-05-05",
                        "rows": [
                            {
                                "rank": 10,
                                "id": "KLBQ-010",
                                "limitation": "Impact-contract gating exists but is still not universal.",
                                "concrete_next_patch": "Add a strict impact-contract preflight wrapper.",
                                "blocked_until": [
                                    "strict impact-contract preflight is wired to filing and promotion routes"
                                ],
                                "owner_lane": "submission finalization / exploit discovery",
                                "loop_estimate": "2 loops",
                                "source_refs": ["docs/KNOWN_LIMITATIONS.md"],
                                "not_submission_evidence": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports" / "impact_contract_preflight_status_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.impact_contract_preflight_status.v1",
                        "limitation_id": "KLBQ-010",
                        "implementation_status": "implemented_verified_local_evidence",
                        "open": False,
                        "dispatch_ready": False,
                        "expected_loop_cost": 0,
                        "not_submission_evidence": True,
                        "closed_benefit": "Route coverage is locally verified.",
                        "verification_commands": [
                            "python3 -m unittest tools.tests.test_impact_contract_preflight_status -v",
                            "python3 -m json.tool reports/impact_contract_preflight_status_2026-05-05.json",
                        ],
                        "evidence_paths": [
                            "tools/impact-contract-preflight.py",
                            "tools/tests/test_impact_contract_preflight_status.py",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            for relative_path in (
                "tools/impact-contract-preflight.py",
                "tools/tests/test_impact_contract_preflight_status.py",
                "docs/IMPACT_CONTRACT_PREFLIGHT_STATUS_2026-05-05.md",
                "reports/impact_contract_preflight_status_2026-05-05.json",
            ):
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("fixture\n", encoding="utf-8")

            report = self.module.build_dispatch_report(root, input_path)

        work_items = {item["limitation_id"]: item for item in report["work_items"]}
        klbq_010 = work_items["KLBQ-010"]
        self.assertEqual(klbq_010["current_status"], "implemented_verified_local_evidence")
        self.assertEqual(klbq_010["dispatch_lane"], "docs_state")
        self.assertFalse(klbq_010["dispatch_ready"])
        self.assertEqual(klbq_010["expected_loop_cost"], 0)
        self.assertIn("KLBQ-010", report["maintenance_backlog"])
        self.assertNotIn("KLBQ-010", report["top_ready_now"])
        self.assertEqual(report["local_status_overrides"], ["KLBQ-010"])
        self.assertIn(
            "python3 -m unittest tools.tests.test_impact_contract_preflight_status -v",
            klbq_010["verification_commands"],
        )
        self.assertIn(
            "reports/impact_contract_preflight_status_2026-05-05.json",
            klbq_010["evidence_paths"],
        )
        self.assertIn("not exploit proof", klbq_010["status_notes"])

    def test_klbq_001_uses_detector_gap_provenance_for_real_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            input_path = root / "reports" / "known_limitations_burndown_queue_2026-05-05.json"
            input_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_queue.v1",
                        "date": "2026-05-05",
                        "rows": [
                            {
                                "rank": 1,
                                "id": "KLBQ-001",
                                "limitation": "Source refs are lost unless checkout succeeds.",
                                "implementation_status": "partially_implemented_v0",
                                "verification_status": "partial_pass",
                                "concrete_next_patch": "Wire the manifest builder into detector generation.",
                                "loop_estimate": "1 loop",
                                "remaining_blockers": [
                                    "detector/report generation still drops github_ref"
                                ],
                                "local_evidence": [
                                    "tools/source-ref-replay-manifest.py",
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports" / "detector_gap_regen_provenance_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.detector_gap_regen_provenance.v1",
                        "status": "blocked_missing_exact_findings_export",
                        "fail_closed": True,
                        "regenerated": False,
                        "blocking_reason": "The exact Solodit findings export is absent locally.",
                        "required_input": {
                            "description": "Exact local JSON export for the 98-row Solodit run."
                        },
                        "next_commands": [
                            "python3.13 tools/detector-blindspot-scan.py --data <export> --max-findings 98",
                            "jq 'map(select(.github_ref != null)) | length' reports/detector_gap.json",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            for relative_path in (
                "tools/_run_gap_analysis.py",
                "tools/detector-blindspot-scan.py",
                "tools/source-ref-replay-manifest.py",
                "tools/tests/test_source_ref_replay_manifest.py",
                "tools/tests/test_detector_blindspot_scan.py",
                "reports/detector_gap_regen_provenance_2026-05-05.json",
                "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md",
                "reports/detector_gap.json",
            ):
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("fixture\n", encoding="utf-8")

            report = self.module.build_dispatch_report(root, input_path)

        work_items = {item["limitation_id"]: item for item in report["work_items"]}
        klbq_001 = work_items["KLBQ-001"]
        self.assertEqual(klbq_001["current_status"], "implemented_verified_with_followup_blockers")
        self.assertEqual(klbq_001["dispatch_lane"], "blocked_needs_source")
        self.assertFalse(klbq_001["dispatch_ready"])
        self.assertIn("KLBQ-001", report["blocked_backlog"])
        self.assertEqual(report["local_status_overrides"], ["KLBQ-001"])
        self.assertIn("exact Solodit findings export is absent", klbq_001["blocker"])
        self.assertIn("detector-blindspot-scan.py --data", klbq_001["next_action"])
        self.assertIn(
            "python3 -m unittest tools.tests.test_source_ref_replay_manifest tools.tests.test_detector_blindspot_scan -v",
            klbq_001["verification_commands"],
        )
        self.assertIn("reports/detector_gap_regen_provenance_2026-05-05.json", klbq_001["evidence_paths"])

    def test_klbq_001_uses_latest_detector_gap_packet_when_default_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            input_path = root / "reports" / "known_limitations_burndown_queue_2026-05-06.json"
            input_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_queue.v1",
                        "date": "2026-05-06",
                        "rows": [
                            {
                                "rank": 1,
                                "id": "KLBQ-001",
                                "limitation": "Source refs are lost unless checkout succeeds.",
                                "implementation_status": "partially_implemented_v0",
                                "verification_status": "partial_pass",
                                "concrete_next_patch": "Wire the manifest builder into detector generation.",
                                "loop_estimate": "1 loop",
                                "remaining_blockers": [
                                    "detector/report generation still drops github_ref"
                                ],
                                "local_evidence": [
                                    "tools/source-ref-replay-manifest.py",
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports" / "detector_gap_regen_provenance_2026-05-06.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.detector_gap_regen_provenance.v1",
                        "status": "blocked_missing_exact_findings_export",
                        "fail_closed": True,
                        "regenerated": False,
                        "blocking_reason": "The exact Solodit findings export is absent locally.",
                        "required_input": {
                            "description": "Exact local JSON export for the 98-row Solodit run."
                        },
                        "next_commands": [
                            "python3.13 tools/detector-blindspot-scan.py --data <export> --max-findings 98",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            for relative_path in (
                "tools/_run_gap_analysis.py",
                "tools/detector-blindspot-scan.py",
                "tools/source-ref-replay-manifest.py",
                "tools/tests/test_source_ref_replay_manifest.py",
                "tools/tests/test_detector_blindspot_scan.py",
                "reports/detector_gap_regen_provenance_2026-05-06.json",
                "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-06.md",
                "reports/detector_gap.json",
            ):
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("fixture\n", encoding="utf-8")

            report = self.module.build_dispatch_report(root, input_path)

        klbq_001 = next(item for item in report["work_items"] if item["limitation_id"] == "KLBQ-001")
        self.assertEqual(report["local_status_overrides"], ["KLBQ-001"])
        self.assertIn("reports/detector_gap_regen_provenance_2026-05-06.json", klbq_001["evidence_paths"])
        self.assertIn(
            "python3 -m json.tool reports/detector_gap_regen_provenance_2026-05-06.json",
            klbq_001["verification_commands"],
        )

    def test_klbq_001_stays_blocked_when_stale_detector_gap_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            input_path = root / "reports" / "known_limitations_burndown_queue_2026-05-05.json"
            input_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_queue.v1",
                        "date": "2026-05-05",
                        "rows": [
                            {
                                "rank": 1,
                                "id": "KLBQ-001",
                                "limitation": "Source refs are lost unless checkout succeeds.",
                                "implementation_status": "partially_implemented_v0",
                                "verification_status": "partial_pass",
                                "concrete_next_patch": "Wire the manifest builder into detector generation.",
                                "loop_estimate": "1 loop",
                                "remaining_blockers": [
                                    "detector/report generation still drops github_ref"
                                ],
                                "local_evidence": [
                                    "tools/source-ref-replay-manifest.py",
                                    "reports/detector_gap.json",
                                    "reports/legacy_detector_gap_summary.json",
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports" / "detector_gap_regen_provenance_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.detector_gap_regen_provenance.v1",
                        "status": "blocked_missing_exact_findings_export",
                        "fail_closed": True,
                        "regenerated": False,
                        "blocking_reason": "The exact Solodit findings export is absent locally.",
                        "required_input": {
                            "description": "Exact local JSON export for the 98-row Solodit run."
                        },
                        "next_commands": [
                            "python3.13 tools/detector-blindspot-scan.py --data <export> --max-findings 98",
                            "jq 'map(select(.github_ref != null)) | length' reports/detector_gap.json",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports" / "detector_gap.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.detector_gap.v1",
                        "rows": [
                            {"finding_id": "F-1", "github_ref": None},
                            {"finding_id": "F-2", "github_ref": None},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports" / "legacy_detector_gap_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.legacy_detector_gap_summary.v1",
                        "status": "stale",
                        "note": "old local summary must not override provenance",
                    }
                ),
                encoding="utf-8",
            )
            for relative_path in (
                "tools/_run_gap_analysis.py",
                "tools/detector-blindspot-scan.py",
                "tools/source-ref-replay-manifest.py",
                "tools/tests/test_source_ref_replay_manifest.py",
                "tools/tests/test_detector_blindspot_scan.py",
                "reports/detector_gap_regen_provenance_2026-05-05.json",
                "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md",
                "reports/detector_gap.json",
                "reports/legacy_detector_gap_summary.json",
            ):
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("fixture\n", encoding="utf-8")

            report = self.module.build_dispatch_report(root, input_path)

        klbq_001 = next(item for item in report["work_items"] if item["limitation_id"] == "KLBQ-001")
        self.assertEqual(klbq_001["dispatch_lane"], "blocked_needs_source")
        self.assertFalse(klbq_001["dispatch_ready"])
        self.assertEqual(report["local_status_overrides"], ["KLBQ-001"])
        self.assertIn("reports/detector_gap.json", klbq_001["evidence_paths"])
        self.assertIn("reports/legacy_detector_gap_summary.json", klbq_001["evidence_paths"])
        self.assertIn("exact Solodit findings export is absent", klbq_001["blocker"])
        self.assertIn("reports/detector_gap_regen_provenance_2026-05-05.json", klbq_001["evidence_paths"])

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            input_path = root / "reports" / "known_limitations_burndown_queue_2026-05-05.json"
            input_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_queue.v1",
                        "rows": [
                            {
                                "rank": 8,
                                "id": "KLBQ-008",
                                "limitation": "Terminal dispatch attempts need slot refill audits.",
                                "concrete_next_patch": "Wire task-finalization-ledger audit-manifest into refill.",
                                "loop_estimate": "1 loop",
                                "source_refs": ["reports/task_finalization.jsonl"],
                            },
                            {
                                "rank": 4,
                                "id": "KLBQ-004",
                                "limitation": "Harness-plan rows still stall at needs_human.",
                                "concrete_next_patch": "Emit a runnable artifact or blocked manifest.",
                                "implementation_status": "implemented_v0",
                                "verification_status": "pass_with_real_blockers_remaining",
                                "loop_estimate": "0 loops",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output_path = root / "reports" / "dispatch.json"
            docs_path = root / "docs" / "dispatch.md"

            proc = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--docs",
                    str(docs_path),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(proc.returncode, 0, msg=f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
            self.assertTrue(output_path.is_file())
            self.assertTrue(docs_path.is_file())
            report = json.loads(output_path.read_text(encoding="utf-8"))
            work_items = {item["limitation_id"]: item for item in report["work_items"]}
            self.assertEqual(work_items["KLBQ-004"]["dispatch_lane"], "docs_state")
            self.assertIn("KLBQ-004", report["maintenance_backlog"])
            self.assertNotIn("KLBQ-004", report["blocked_backlog"])
            self.assertEqual(work_items["KLBQ-008"]["dispatch_lane"], "memory_handoff")
            self.assertIn("Sorted Work Items", docs_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
