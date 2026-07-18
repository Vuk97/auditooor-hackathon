from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "tools" / "semantic-fixture-smoke-gate.py"


def _write_inventory(ws: Path) -> None:
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir()
    fixture_dir = ws / "detectors" / "fixtures" / "semantic_portal"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "ssi-fix-001_positive.sol").write_text("contract Positive {}\n", encoding="utf-8")
    (fixture_dir / "ssi-fix-001_clean.sol").write_text("contract Clean {}\n", encoding="utf-8")
    (fixture_dir / "ssi-fix-001_smoke.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "command": "make -C detectors run TARGET=detectors/fixtures/semantic_portal",
                "positive_hits": 2,
                "clean_hits": 0,
                "pattern": "semantic-portal",
                "detector_slug": "semantic_portal",
                "detector_path": "detectors/wave_test/semantic_portal.py",
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
                        "suggested_detector_slug": "semantic_portal",
                        "fixture_task": {
                            "positive_fixture_path": "detectors/fixtures/semantic_portal/ssi-fix-001_positive.sol",
                            "clean_fixture_path": "detectors/fixtures/semantic_portal/ssi-fix-001_clean.sol",
                            "smoke_record_path": "detectors/fixtures/semantic_portal/ssi-fix-001_smoke.json",
                        },
                    },
                    {
                        "queue_id": "SSI-Q-002",
                        "inventory_id": "SSI-002",
                        "task_type": "fixture_pair_before_detector_rewrite",
                        "source_component": "Portal.routeOnly",
                        "fixture_task": {
                            "positive_fixture_path": "detectors/fixtures/missing/ssi-fix-002_positive.sol",
                            "clean_fixture_path": "detectors/fixtures/missing/ssi-fix-002_clean.sol",
                            "smoke_record_path": "detectors/fixtures/missing/ssi-fix-002_smoke.json",
                        },
                    },
                    {
                        "queue_id": "SSI-Q-003",
                        "inventory_id": "SSI-003",
                        "task_type": "source_review_or_kill_note",
                        "source_component": "Portal.noDetector",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_detector_stub(ws: Path, argument: str) -> None:
    detector_dir = ws / "detectors" / "wave_test"
    detector_dir.mkdir(parents=True, exist_ok=True)
    (detector_dir / f"{argument.replace('-', '_')}.py").write_text(
        f'class StubDetector:\n    ARGUMENT = "{argument}"\n',
        encoding="utf-8",
    )


def _run(*args: Path | str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


class SemanticFixtureSmokeGateTest(unittest.TestCase):
    def test_gate_accepts_smoke_record_when_metadata_binds_to_queued_detector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-001"]
            self.assertEqual(row["status"], "fixture_smoke_passed")
            self.assertEqual(row["smoke_summary"]["pattern"], "semantic-portal")
            self.assertEqual(row["smoke_summary"]["detector_slug"], "semantic_portal")
            self.assertEqual(row["smoke_summary"]["detector_path"], "detectors/wave_test/semantic_portal.py")

    def test_gate_accepts_inventory_smoke_status_and_split_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            smoke["status"] = "smoke_pass"
            smoke.pop("command")
            smoke["positive_command"] = "run positive semantic_portal"
            smoke["clean_command"] = "run clean semantic_portal"
            smoke_path.write_text(json.dumps(smoke), encoding="utf-8")

            proc = _run(sys.executable, GATE, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-001"]
            self.assertEqual(row["status"], "fixture_smoke_passed")
            self.assertEqual(row["smoke_summary"]["status"], "smoke_pass")
            self.assertEqual(row["smoke_summary"]["command"], "run positive semantic_portal ; run clean semantic_portal")

    def test_gate_accepts_vulnerable_clean_smoke_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            smoke["status"] = "passed_vulnerable_clean_smoke"
            smoke_path.write_text(json.dumps(smoke), encoding="utf-8")

            proc = _run(sys.executable, GATE, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-001"]
            self.assertEqual(row["status"], "fixture_smoke_passed")
            self.assertEqual(row["smoke_summary"]["status"], "passed_vulnerable_clean_smoke")

    def test_gate_blocks_smoke_record_when_pattern_or_detector_path_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            smoke["pattern"] = "other-detector-pattern"
            smoke["detector_path"] = "detectors/wave_test/other_detector.py"
            smoke_path.write_text(json.dumps(smoke), encoding="utf-8")
            proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-001"]
            self.assertEqual(row["status"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke pattern conflicts with queued detector context", "; ".join(row["blockers"]))
            self.assertIn("smoke detector_path conflicts with queued detector context", "; ".join(row["blockers"]))

    def test_gate_blocks_smoke_record_when_command_does_not_bind_to_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            smoke["command"] = "detector-smoke unrelated_detector --fixtures detectors/fixtures/unrelated"
            smoke_path.write_text(json.dumps(smoke), encoding="utf-8")

            proc = _run(sys.executable, GATE, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-001"]
            self.assertEqual(row["status"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke command does not bind to queued detector or fixtures", row["blockers"])

    def test_gate_blocks_smoke_record_when_fixture_refs_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            smoke_path = ws / "detectors" / "fixtures" / "semantic_portal" / "ssi-fix-001_smoke.json"
            smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
            smoke["positive_fixture_path"] = "detectors/fixtures/other/ssi-fix-001_positive.sol"
            smoke_path.write_text(json.dumps(smoke), encoding="utf-8")

            proc = _run(sys.executable, GATE, "--workspace", ws)

            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-001"]
            self.assertEqual(row["status"], "blocked_missing_fixture_or_smoke")
            self.assertIn("smoke positive fixture conflicts with queued fixture", "; ".join(row["blockers"]))

    def test_gate_checks_fixture_pair_and_smoke_without_promoting_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)

            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_fixture_smoke_gate.v1")
            self.assertEqual(payload["processed_count"], 3)
            self.assertEqual(payload["smoke_required_count"], 2)
            self.assertEqual(payload["smoke_passed_count"], 1)
            self.assertEqual(payload["blocking_count"], 1)
            self.assertFalse(payload["gate_passed"])
            self.assertEqual(payload["severity"], "none")
            self.assertEqual(payload["selected_impact"], "")
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(payload["promotion_allowed"])
            statuses = {row["queue_id"]: row["status"] for row in payload["rows"]}
            self.assertEqual(statuses["SSI-Q-001"], "fixture_smoke_passed")
            self.assertEqual(statuses["SSI-Q-002"], "blocked_missing_fixture_or_smoke")
            self.assertEqual(statuses["SSI-Q-003"], "not_applicable_source_review_or_coverage")
            self.assertTrue(all(row["severity"] == "none" for row in payload["rows"]))
            self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["rows"]))
            md = (ws / ".auditooor" / "semantic_fixture_smoke_gate.md").read_text(encoding="utf-8")
            self.assertIn("Semantic Fixture Smoke Gate", md)
            self.assertIn("fixture_smoke_passed", md)

    def test_strict_mode_fails_when_a_smoke_required_row_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            proc = _run(sys.executable, GATE, "--workspace", ws, "--strict")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("blocked=1", proc.stderr)

    def test_gate_counts_fixture_manifest_evidence_without_passing_smoke_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            manifest_path = ws / "detectors" / "fixtures" / "missing" / "ssi-fix-002_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "queue_id": "SSI-Q-002",
                        "materialization_status": "exact_extraction_command_ready",
                        "shell_command": "python3 tools/p1-fixture-extractor.py --pattern demo --strict-smoke-fire",
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                    }
                ),
                encoding="utf-8",
            )
            proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["smoke_passed_count"], 1)
            self.assertEqual(payload["blocking_count"], 0)
            self.assertEqual(payload["terminal_cannot_run_count"], 1)
            self.assertEqual(payload["terminal_fixture_manifest_count"], 1)
            self.assertEqual(payload["exact_extraction_command_count"], 1)
            blocked = {row["queue_id"]: row for row in payload["rows"]}["SSI-Q-002"]
            self.assertEqual(blocked["status"], "terminal_cannot_run_dependency_preflight")
            self.assertIn("missing_llm_network_consent", blocked["cannot_run_reason"])
            self.assertTrue(blocked["fixture_manifest_terminal"])
            self.assertFalse(blocked["promotion_allowed"])

    def test_gate_classifies_proof_of_life_failure_as_terminal_cannot_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            proof_dir = ws / "detectors" / "python_wave1" / "test_fixtures"
            proof_dir.mkdir(parents=True, exist_ok=True)
            proof_script = proof_dir / "test_detectors.sh"
            proof_script.write_text("#!/usr/bin/env bash\necho proof_of_life failed\nexit 1\n", encoding="utf-8")
            proof_script.chmod(0o755)
            manifest_path = ws / "detectors" / "fixtures" / "missing" / "ssi-fix-002_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "queue_id": "SSI-Q-002",
                        "materialization_status": "exact_extraction_command_ready",
                        "argv": [
                            "python3",
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            "demo",
                            "--mock-dispatcher",
                            "/tmp/mock.py",
                            "--runner",
                            "/tmp/mock_runner.py",
                        ],
                        "shell_command": "python3 tools/p1-fixture-extractor.py --pattern demo --mock-dispatcher /tmp/mock.py --runner /tmp/mock_runner.py",
                        "promotion_allowed": False,
                        "submission_posture": "NOT_SUBMIT_READY",
                    }
                ),
                encoding="utf-8",
            )
            proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-002"]
            self.assertEqual(row["status"], "terminal_cannot_run_dependency_preflight")
            self.assertIn("proof_of_life_detector_failure", row["cannot_run_reason"])
            self.assertEqual(payload["terminal_cannot_run_count"], 1)

    def test_strict_mode_fails_when_extraction_failure_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            manifest_path = ws / "detectors" / "fixtures" / "missing" / "ssi-fix-002_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            (manifest_path.parent / "extraction_failure.json").write_text(
                json.dumps({"reason": "fixture_extractor_failed", "detail": "model returned no fixture"}),
                encoding="utf-8",
            )

            proc = _run(sys.executable, GATE, "--workspace", ws, "--strict")

            self.assertEqual(proc.returncode, 1)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            self.assertFalse(payload["gate_passed"])
            self.assertEqual(payload["terminal_extraction_failed_count"], 1)
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-002"]
            self.assertEqual(row["status"], "terminal_extraction_failed")
            self.assertIn("terminal extraction failed", "; ".join(row["blockers"]))

    def test_slither_preflight_honors_explicit_python_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_inventory(ws)
            _write_detector_stub(ws, "demo")
            manifest_path = ws / "detectors" / "fixtures" / "missing" / "ssi-fix-002_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "queue_id": "SSI-Q-002",
                        "materialization_status": "exact_extraction_command_ready",
                        "argv": [
                            "python3",
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            "demo",
                            "--mock-dispatcher",
                            "/tmp/mock.py",
                        ],
                        "shell_command": "python3 tools/p1-fixture-extractor.py --pattern demo --mock-dispatcher /tmp/mock.py",
                    }
                ),
                encoding="utf-8",
            )
            fake_python = Path(tmp) / "python-with-slither"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"-c\" && \"$2\" == *\"slither\"* ]]; then exit 0; fi\n"
                "exec python3 \"$@\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            env = {**os.environ, "AUDITOOOR_PYTHON_SLITHER": str(fake_python)}
            proc = _run(sys.executable, GATE, "--workspace", ws, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-002"]
            self.assertNotIn("missing_slither_analyzer", row["cannot_run_reason"])
            self.assertEqual(row["dependency_preflight"]["slither_python"], str(fake_python))
            self.assertEqual(payload["terminal_cannot_run_count"], 0)

    def test_gate_enriches_default_runner_manifest_when_detector_argument_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            manifest_path = ws / "detectors" / "fixtures" / "missing" / "ssi-fix-002_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "queue_id": "SSI-Q-002",
                        "materialization_status": "exact_extraction_command_ready",
                        "argv": [
                            "python3",
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            "not-compiled-yet",
                            "--mock-dispatcher",
                            "/tmp/mock.py",
                        ],
                        "shell_command": "python3 tools/p1-fixture-extractor.py --pattern not-compiled-yet --mock-dispatcher /tmp/mock.py",
                    }
                ),
                encoding="utf-8",
            )
            fake_python = Path(tmp) / "python-with-slither"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"-c\" && \"$2\" == *\"slither\"* ]]; then exit 0; fi\n"
                "exec python3 \"$@\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            env = {**os.environ, "AUDITOOOR_PYTHON_SLITHER": str(fake_python)}
            proc = _run(sys.executable, GATE, "--workspace", ws, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-002"]
            self.assertEqual(row["status"], "terminal_cannot_run_dependency_preflight")
            self.assertIn("missing_detector_argument", row["cannot_run_reason"])
            self.assertIn("not-compiled-yet", "; ".join(row["blockers"]))
            inference = row["dependency_preflight"]["detector_argument_inference"]
            self.assertFalse(inference["ok"])
            self.assertEqual(inference["argument"], "not-compiled-yet")
            self.assertEqual(inference["inference"]["source"], "manifest_argv_pattern")

    def test_gate_infers_missing_detector_argument_from_manifest_fields_without_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inventory(ws)
            manifest_path = ws / "detectors" / "fixtures" / "missing" / "ssi-fix-002_manifest.json"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "queue_id": "SSI-Q-002",
                        "materialization_status": "exact_extraction_command_ready",
                        "detector_slug": "manifest_slug_detector",
                        "argv": [
                            "python3",
                            "tools/p1-fixture-extractor.py",
                            "--mock-dispatcher",
                            "/tmp/mock.py",
                        ],
                        "shell_command": "python3 tools/p1-fixture-extractor.py --mock-dispatcher /tmp/mock.py",
                    }
                ),
                encoding="utf-8",
            )
            fake_python = Path(tmp) / "python-with-slither"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"-c\" && \"$2\" == *\"slither\"* ]]; then exit 0; fi\n"
                "exec python3 \"$@\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            env = {**os.environ, "AUDITOOOR_PYTHON_SLITHER": str(fake_python)}
            proc = _run(sys.executable, GATE, "--workspace", ws, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((ws / ".auditooor" / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            row = {item["queue_id"]: item for item in payload["rows"]}["SSI-Q-002"]
            inference = row["dependency_preflight"]["detector_argument_inference"]
            self.assertEqual(inference["argument"], "manifest-slug-detector")
            self.assertEqual(inference["inference"]["source"], "manifest_detector_slug")
            self.assertIn("inferred from manifest_detector_slug", "; ".join(row["blockers"]))

    def test_limit_defaults_to_fifty_concrete_queue_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            rows = [
                {
                    "queue_id": f"SSI-Q-{idx:03d}",
                    "inventory_id": f"SSI-{idx:03d}",
                    "task_type": "source_review_or_kill_note",
                    "source_component": f"Portal{idx}.review",
                }
                for idx in range(1, 61)
            ]
            (audit_dir / "semantic_scanner_inventory.json").write_text(
                json.dumps({"detector_fixture_task_queue": rows}),
                encoding="utf-8",
            )
            proc = _run(sys.executable, GATE, "--workspace", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
            payload = json.loads((audit_dir / "semantic_fixture_smoke_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["limit"], 50)
            self.assertEqual(payload["queue_item_count"], 60)
            self.assertEqual(payload["processed_count"], 50)
            self.assertEqual(payload["smoke_required_count"], 0)
            self.assertTrue(payload["gate_passed"])


if __name__ == "__main__":
    unittest.main()
