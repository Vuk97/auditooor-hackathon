from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / "tools" / "semantic-fixture-smoke-tasks.py"
GATE = ROOT / "tools" / "semantic-fixture-smoke-gate.py"


def _write_inventory(ws: Path, *, with_existing_smoke: bool = False) -> None:
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir()
    fixture_dir = ws / "detectors" / "fixtures" / "semantic_portal"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "ssi-fix-001_positive.sol").write_text("contract Positive {}\n", encoding="utf-8")
    (fixture_dir / "ssi-fix-001_clean.sol").write_text("contract Clean {}\n", encoding="utf-8")
    if with_existing_smoke:
        (fixture_dir / "ssi-fix-001_smoke.json").write_text(
            json.dumps(
                {
                    "status": "pass",
                    "command": "detector-smoke semantic_portal",
                    "positive_hits": 1,
                    "clean_hits": 0,
                }
            ),
            encoding="utf-8",
        )
    (audit_dir / "semantic_scanner_inventory.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_scanner_inventory.v1",
                "detector_fixture_task_queue": [
                    {
                        "queue_id": "SSI-Q-001",
                        "inventory_id": "SSI-001",
                        "task_type": "detector_rewrite_with_fixture_pair",
                        "source_component": "Portal.finalizeWithdrawal",
                        "candidate_detector_family": "verifier-adapter-call",
                        "suggested_detector_slug": "semantic_portal",
                        "fixture_task": {
                            "fixture_id": "SSI-FIX-001",
                            "positive_fixture_path": "detectors/fixtures/semantic_portal/ssi-fix-001_positive.sol",
                            "clean_fixture_path": "detectors/fixtures/semantic_portal/ssi-fix-001_clean.sol",
                            "smoke_record_path": "detectors/fixtures/semantic_portal/ssi-fix-001_smoke.json",
                        },
                    },
                    {
                        "queue_id": "SSI-Q-002",
                        "inventory_id": "SSI-002",
                        "task_type": "coverage_to_detector_worklist",
                        "source_component": "Portal.routeOnly",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _run(*args: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _write_gate(
    ws: Path,
    *,
    detector_slug: str = "semantic_portal",
    smoke_record_path: str | None = None,
    status: str = "fixture_smoke_passed",
) -> None:
    inventory = json.loads((ws / ".auditooor" / "semantic_scanner_inventory.json").read_text(encoding="utf-8"))
    row = inventory["detector_fixture_task_queue"][0]
    fixture_task = row["fixture_task"]
    smoke_rel = smoke_record_path or fixture_task["smoke_record_path"]
    (ws / ".auditooor" / "semantic_fixture_smoke_gate.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_fixture_smoke_gate.v1",
                "rows": [
                    {
                        "queue_id": row["queue_id"],
                        "status": status,
                        "suggested_detector_slug": detector_slug,
                        "positive_fixture_path": str((ws / fixture_task["positive_fixture_path"]).resolve()),
                        "clean_fixture_path": str((ws / fixture_task["clean_fixture_path"]).resolve()),
                        "smoke_record_path": str((ws / smoke_rel).resolve()),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class SemanticFixtureSmokeTasksTest(unittest.TestCase):
    def test_task_manifest_consumes_existing_gate_output_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws, with_existing_smoke=True)
            gate_proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(gate_proc.returncode, 0, gate_proc.stderr or gate_proc.stdout)

            proc = _run(sys.executable, TASKS, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_fixture_smoke_tasks.v1")
            self.assertEqual(payload["processed_count"], 2)
            self.assertEqual(payload["smoke_required_count"], 1)
            self.assertEqual(payload["terminal_clean_positive_count"], 1)
            self.assertEqual(payload["blocking_count"], 0)
            self.assertEqual(
                payload["detector_precision_accounting"]["accounting_mode"],
                "fixture_smoke_precision_accounting_only",
            )
            self.assertEqual(payload["detector_precision_accounting"]["terminal_clean_positive_count"], 1)
            self.assertEqual(payload["detector_precision_accounting"]["blocked_missing_fixture_or_smoke_count"], 0)
            self.assertEqual(payload["detector_precision_accounting"]["precision_claim"], "not_computed_fixture_smoke_only")
            self.assertEqual(payload["severity"], "none")
            self.assertEqual(payload["selected_impact"], "")
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(payload["promotion_allowed"])
            statuses = {row["queue_id"]: row["terminal_state"] for row in payload["rows"]}
            self.assertEqual(statuses["SSI-Q-001"], "terminal_clean_positive_fixture_smoke")
            self.assertEqual(statuses["SSI-Q-002"], "not_applicable_source_review_or_coverage")
            self.assertTrue(all(row["severity"] == "none" for row in payload["rows"]))
            md = (ws / ".auditooor" / "semantic_fixture_smoke_tasks.md").read_text(encoding="utf-8")
            self.assertIn("Semantic Fixture Smoke Tasks", md)
            self.assertIn("terminal_clean_positive_fixture_smoke", md)

    def test_bound_gate_pass_clears_missing_smoke_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            _write_gate(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke_path.write_text(
                json.dumps(
                    {
                        "status": "smoke_pass",
                        "positive_command": "run positive semantic_portal",
                        "clean_command": "run clean semantic_portal",
                        "positive_hits": 1,
                        "clean_hits": 0,
                    }
                ),
                encoding="utf-8",
            )

            proc = _run(sys.executable, TASKS, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 1)
            self.assertEqual(payload["blocking_count"], 0)
            self.assertEqual(row["existing_gate_status"], "fixture_smoke_passed")
            self.assertEqual(row["terminal_state"], "terminal_clean_positive_fixture_smoke")
            self.assertEqual(row["blockers"], [])
            self.assertEqual(row["existing_smoke_summary"]["command"], "run positive semantic_portal ; run clean semantic_portal")

    def test_bound_gate_pass_does_not_clear_missing_current_smoke_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            _write_gate(ws)

            proc = _run(sys.executable, TASKS, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["blocking_count"], 1)
            self.assertEqual(row["existing_gate_status"], "fixture_smoke_passed")
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke record missing", row["blockers"][0])

    def test_stale_gate_pass_does_not_clear_blockers_when_inventory_id_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            _write_gate(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke_path.write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "smoke_command": "detector-smoke semantic_portal",
                        "positive_hits": 0,
                        "clean_hits": 0,
                    }
                ),
                encoding="utf-8",
            )

            gate_path = ws / ".auditooor" / "semantic_fixture_smoke_gate.json"
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            gate["rows"][0]["inventory_id"] = "SSI-OLD"
            gate_path.write_text(json.dumps(gate), encoding="utf-8")

            proc = _run(sys.executable, TASKS, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["blocking_count"], 1)
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertEqual(row["existing_gate_status"], "fixture_smoke_passed")
            self.assertIn("positive/vulnerable fixture produced zero hits", row["blockers"])

    def test_stale_gate_pass_does_not_clear_blockers_when_smoke_path_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            _write_gate(ws)

            inventory_path = ws / ".auditooor" / "semantic_scanner_inventory.json"
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            task = inventory["detector_fixture_task_queue"][0]
            task["fixture_task"]["smoke_record_path"] = "detectors/fixtures/semantic_portal/ssi-fix-001-rerun_smoke.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")

            proc = _run(sys.executable, TASKS, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["blocking_count"], 1)
            self.assertEqual(row["existing_gate_status"], "fixture_smoke_passed")
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke record missing", row["blockers"][0])

    def test_stale_gate_pass_does_not_clear_blockers_when_detector_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            _write_gate(ws, detector_slug="semantic_portal_rerun")

            proc = _run(sys.executable, TASKS, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["blocking_count"], 1)
            self.assertEqual(row["existing_gate_status"], "fixture_smoke_passed")
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke record missing", row["blockers"][0])

    def test_ingests_external_smoke_result_into_gate_record_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_results = ws / "smoke-results"
            smoke_results.mkdir()
            (smoke_results / "semantic-portal-result.json").write_text(
                json.dumps(
                    {
                        "queue_id": "SSI-Q-001",
                        "inventory_id": "SSI-001",
                        "fixture_id": "SSI-FIX-001",
                        "detector_slug": "semantic_portal",
                        "status": "pass",
                        "smoke_command": "detector-smoke semantic_portal --fixtures detectors/fixtures/semantic_portal",
                        "fixtures": {
                            "vulnerable": {"hits": 3},
                            "clean": {"hits": 0},
                        },
                    }
                ),
                encoding="utf-8",
            )

            proc = _run(sys.executable, TASKS, "--workspace", ws, "--smoke-results", smoke_results)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["terminal_clean_positive_count"], 1)
            self.assertEqual(payload["ingested_record_count"], 1)
            normalized = json.loads(
                (ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json").read_text(encoding="utf-8")
            )
            self.assertEqual(normalized["schema"], "auditooor.semantic_fixture_smoke_record.v1")
            self.assertEqual(normalized["positive_hits"], 3)
            self.assertEqual(normalized["clean_hits"], 0)
            self.assertEqual(normalized["submission_posture"], "NOT_SUBMIT_READY")

            gate_proc = _run(sys.executable, GATE, "--workspace", ws, "--strict")
            self.assertEqual(gate_proc.returncode, 0, gate_proc.stderr or gate_proc.stdout)
            gate_payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(gate_payload["smoke_passed_count"], 1)
            self.assertEqual(gate_payload["blocking_count"], 0)

    def test_existing_smoke_command_must_bind_to_current_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws, with_existing_smoke=True)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            smoke["command"] = "detector-smoke unrelated_detector --fixtures detectors/fixtures/unrelated"
            smoke_path.write_text(json.dumps(smoke), encoding="utf-8")

            proc = _run(sys.executable, TASKS, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke command does not bind to queued detector or fixtures", row["blockers"])

    def test_external_smoke_identity_match_still_requires_command_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_results = ws / "smoke-results"
            smoke_results.mkdir()
            (smoke_results / "borrowed-result.json").write_text(
                json.dumps(
                    {
                        "queue_id": "SSI-Q-001",
                        "inventory_id": "SSI-001",
                        "fixture_id": "SSI-FIX-001",
                        "detector_slug": "semantic_portal",
                        "status": "pass",
                        "smoke_command": "detector-smoke unrelated_detector --fixtures detectors/fixtures/unrelated",
                        "fixtures": {
                            "vulnerable": {"hits": 3},
                            "clean": {"hits": 0},
                        },
                    }
                ),
                encoding="utf-8",
            )

            proc = _run(sys.executable, TASKS, "--workspace", ws, "--smoke-results", smoke_results)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["ingested_record_count"], 0)
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke record missing", row["blockers"][0])
            self.assertFalse((ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json").exists())

    def test_conflicting_external_smoke_identity_is_not_ingested_by_fuzzy_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_results = ws / "smoke-results"
            smoke_results.mkdir()
            (smoke_results / "semantic-portal-result.json").write_text(
                json.dumps(
                    {
                        "queue_id": "SSI-Q-999",
                        "inventory_id": "SSI-999",
                        "fixture_id": "SSI-FIX-999",
                        "detector_slug": "semantic_portal",
                        "status": "pass",
                        "smoke_command": "detector-smoke semantic_portal --fixtures detectors/fixtures/semantic_portal",
                        "fixtures": {
                            "vulnerable": {"hits": 3},
                            "clean": {"hits": 0},
                        },
                    }
                ),
                encoding="utf-8",
            )

            proc = _run(sys.executable, TASKS, "--workspace", ws, "--smoke-results", smoke_results)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["ingested_record_count"], 0)
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke record missing", row["blockers"][0])
            self.assertFalse((ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json").exists())

    def test_external_smoke_requires_strong_identity_not_detector_slug_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_results = ws / "smoke-results"
            smoke_results.mkdir()
            (smoke_results / "semantic-portal-result.json").write_text(
                json.dumps(
                    {
                        "detector_slug": "semantic_portal",
                        "status": "passed_vulnerable_clean_smoke",
                        "smoke_command": "detector-smoke semantic_portal --fixtures stale/semantic_portal",
                        "fixtures": {
                            "vulnerable": {"hits": 3},
                            "clean": {"hits": 0},
                        },
                    }
                ),
                encoding="utf-8",
            )

            proc = _run(sys.executable, TASKS, "--workspace", ws, "--smoke-results", smoke_results)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["ingested_record_count"], 0)
            self.assertEqual(row["terminal_state"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke record missing", row["blockers"][0])
            self.assertFalse((ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json").exists())

    def test_strict_mode_fails_when_smoke_required_rows_remain_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            proc = _run(sys.executable, TASKS, "--workspace", ws, "--strict")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("blocked=1", proc.stderr)

    def test_strict_mode_fails_when_extraction_failure_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            manifest_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            (manifest_path.parent / "extraction_failure.json").write_text(
                json.dumps({"reason": "fixture_extractor_failed", "detail": "model returned no fixture"}),
                encoding="utf-8",
            )

            proc = _run(sys.executable, TASKS, "--workspace", ws, "--strict")

            self.assertEqual(proc.returncode, 1)
            self.assertIn("blocked=0", proc.stderr)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["terminal_extraction_failed_count"], 1)
            self.assertEqual(payload["rows"][0]["terminal_state"], "terminal_extraction_failed")

    def test_materializes_fixture_manifests_with_exact_extraction_commands_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            proc = _run(sys.executable, TASKS, "--workspace", ws, "--materialize-manifests")
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["terminal_clean_positive_count"], 0)
            self.assertEqual(payload["blocking_count"], 0)
            self.assertEqual(payload["terminal_cannot_run_count"], 1)
            self.assertEqual(payload["terminal_fixture_manifest_count"], 1)
            self.assertEqual(payload["exact_extraction_command_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["terminal_state"], "terminal_cannot_run_dependency_preflight")
            self.assertIn("missing_llm_network_consent", row["cannot_run_reason"])
            self.assertIn("detector_argument_inference", row["dependency_preflight"])
            self.assertTrue(row["fixture_manifest_terminal"])
            self.assertIn("p1-fixture-extractor.py", row["fixture_manifest_shell_command"])
            self.assertFalse(row["promotion_allowed"])
            manifest = json.loads(
                (ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["schema"], "auditooor.semantic_fixture_materialization.v1")
            self.assertEqual(manifest["materialization_status"], "exact_extraction_command_ready")
            self.assertIn("--strict-smoke-fire", manifest["argv"])
            self.assertEqual(manifest["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(manifest["promotion_allowed"])

    def test_limit_defaults_to_fifty_concrete_queue_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            rows = [
                {
                    "queue_id": f"SSI-Q-{idx:03d}",
                    "inventory_id": f"SSI-{idx:03d}",
                    "task_type": "coverage_to_detector_worklist",
                    "source_component": f"Portal{idx}.review",
                }
                for idx in range(1, 61)
            ]
            (audit_dir / "semantic_scanner_inventory.json").write_text(
                json.dumps({"detector_fixture_task_queue": rows}),
                encoding="utf-8",
            )
            proc = _run(sys.executable, TASKS, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((audit_dir / "semantic_fixture_smoke_tasks.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["limit"], 50)
            self.assertEqual(payload["queue_item_count"], 60)
            self.assertEqual(payload["processed_count"], 50)
            self.assertEqual(payload["smoke_required_count"], 0)
            self.assertEqual(payload["blocking_count"], 0)


if __name__ == "__main__":
    unittest.main()
