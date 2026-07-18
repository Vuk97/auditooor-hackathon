from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "evidence-class-legacy-backfill.py"
VALIDATOR = REPO_ROOT / "tools" / "evidence-class-validator.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class EvidenceClassLegacyBackfillTest(unittest.TestCase):
    def test_backfills_provider_closure_and_stale_execution_outcomes(self) -> None:
        tool = _load(TOOL, "evidence_class_legacy_backfill")
        validator = _load(VALIDATOR, "evidence_class_validator_for_backfill")
        with tempfile.TemporaryDirectory(prefix="ec-legacy-") as tmp:
            ws = Path(tmp)
            closure_dir = ws / ".audit_logs" / "pr560_worker_ax"
            closure_dir.mkdir(parents=True)
            closure = closure_dir / "provider_local_verification_closure.json"
            closure.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_local_verification_closure.v1",
                        "submit_ready": False,
                        "advisory_only": True,
                        "rows": [
                            {
                                "task_id": "LPV-001",
                                "submit_ready": False,
                                "submission_posture": "NOT_SUBMIT_READY",
                            },
                            {
                                "task_id": "LPV-002",
                                "submit_ready": False,
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            outcomes = ws / ".auditooor" / "execution_proof_outcomes"
            outcomes.mkdir(parents=True)
            (outcomes / "old.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.execution_proof_outcome.v1",
                        "task_id": "old",
                        "submit_ready": False,
                        "outcome": {"executed": True, "status": "pass"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            triage_dir = ws / ".audit_logs" / "pr560_worker_bj"
            triage_dir.mkdir(parents=True)
            (triage_dir / "live_provider_result_triage.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_provider_result_triage.v1",
                        "rows": [
                            {"task_id": "LPRT-001", "submit_ready": False},
                            {"task_id": "LPRT-002", "submit_ready": False},
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            before = validator.collect(ws)
            summary = tool.run(ws)
            after = validator.collect(ws)

        self.assertEqual(before["legacy_count"], 5)
        self.assertEqual(summary["rows_changed"], 5)
        self.assertEqual(after["legacy_count"], 0)
        self.assertEqual(after["policy_violation_count"], 0)
        self.assertEqual(
            after["per_artifact"]["provider_local_verification_closure"]["counts"][
                "generated_hypothesis"
            ],
            2,
        )
        self.assertEqual(
            after["per_artifact"]["execution_proof_outcomes"]["counts"][
                "scaffolded_unverified"
            ],
            1,
        )
        self.assertEqual(
            after["per_artifact"]["live_provider_result_triage"]["counts"][
                "generated_hypothesis"
            ],
            2,
        )

    def test_dry_run_does_not_mutate(self) -> None:
        tool = _load(TOOL, "evidence_class_legacy_backfill_dry")
        validator = _load(VALIDATOR, "evidence_class_validator_for_backfill_dry")
        with tempfile.TemporaryDirectory(prefix="ec-legacy-dry-") as tmp:
            ws = Path(tmp)
            outcomes = ws / ".auditooor" / "execution_proof_outcomes"
            outcomes.mkdir(parents=True)
            (outcomes / "old.json").write_text(
                json.dumps({"schema": "auditooor.execution_proof_outcome.v1"})
                + "\n",
                encoding="utf-8",
            )
            summary = tool.run(ws, dry_run=True)
            after = validator.collect(ws)

        self.assertEqual(summary["rows_changed"], 1)
        self.assertEqual(after["legacy_count"], 1)

    def test_normalizes_existing_advisory_rows_without_promoting_proof(self) -> None:
        tool = _load(TOOL, "evidence_class_legacy_backfill_normalize")
        validator = _load(VALIDATOR, "evidence_class_validator_for_backfill_normalize")
        with tempfile.TemporaryDirectory(prefix="ec-legacy-normalize-") as tmp:
            ws = Path(tmp)
            closure_dir = ws / ".audit_logs" / "pr560_worker_ax"
            closure_dir.mkdir(parents=True)
            closure = closure_dir / "provider_local_verification_closure.json"
            closure.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.provider_local_verification_closure.v1",
                        "rows": [
                            {
                                "task_id": "LPV-UNSAFE",
                                "evidence_class": "generated_hypothesis",
                                "submit_ready": True,
                                "promotion_allowed": True,
                                "promotion_authority": True,
                                "submission_posture": "SUBMIT_READY",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            before = validator.collect(ws)
            summary = tool.run(ws)
            after = validator.collect(ws)
            payload = json.loads(closure.read_text(encoding="utf-8"))

        self.assertEqual(before["legacy_count"], 0)
        self.assertEqual(before["policy_violation_count"], 2)
        self.assertEqual(summary["rows_changed"], 1)
        self.assertEqual(after["legacy_count"], 0)
        self.assertEqual(after["policy_violation_count"], 0)
        row = payload["rows"][0]
        self.assertEqual(row["evidence_class"], "generated_hypothesis")
        self.assertFalse(row["submit_ready"])
        self.assertFalse(row["promotion_allowed"])
        self.assertFalse(row["promotion_authority"])
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")

    def test_canonicalizes_scanner_terminal_blocker_rows(self) -> None:
        tool = _load(TOOL, "evidence_class_legacy_backfill_scanner")
        validator = _load(VALIDATOR, "evidence_class_validator_for_backfill_scanner")
        with tempfile.TemporaryDirectory(prefix="ec-legacy-scanner-") as tmp:
            ws = Path(tmp)
            audit = ws / ".auditooor"
            audit.mkdir()
            artifact = audit / "scanner_autonomy_execution.json"
            artifact.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_autonomy_execution.v1",
                        "rows": [
                            {
                                "task_id": "SAE-001",
                                "status": "terminal_cannot_run",
                                "evidence_class": "terminal_blocker",
                                "promotion_allowed": False,
                            },
                            {
                                "task_id": "SAE-002",
                                "status": "executed_ok",
                                "evidence_class": "executed_with_manifest",
                                "promotion_allowed": False,
                                "submission_posture": "NOT_SUBMIT_READY",
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            before = validator.collect(ws)
            summary = tool.run(ws)
            after = validator.collect(ws)
            payload = json.loads(artifact.read_text(encoding="utf-8"))

        self.assertEqual(before["legacy_count"], 1)
        self.assertEqual(summary["rows_changed"], 1)
        self.assertEqual(after["legacy_count"], 0)
        self.assertEqual(after["policy_violation_count"], 0)
        self.assertEqual(payload["rows"][0]["evidence_class"], "scaffolded_unverified")
        self.assertEqual(payload["rows"][0]["terminal_evidence_status"], "terminal_blocker")
        self.assertEqual(payload["rows"][1]["evidence_class"], "executed_with_manifest")


if __name__ == "__main__":
    unittest.main()
