import importlib.util
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "task-finalization-ledger.py"


def load_module():
    spec = importlib.util.spec_from_file_location("task_finalization_ledger", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ledger_tool = load_module()


class TaskFinalizationLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-task-finalization-test-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        self.ledger = self.root / "reports" / "task_finalization.jsonl"
        self.completed = self.vault / "gap-analysis" / "_completed.jsonl"
        self.notes = self.vault / "tasks" / "finalized"

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, **overrides):
        row = {
            "schema": "auditooor.task_finalization.v1",
            "task_id": "g8-001-slot-1-landed",
            "gap_id": "G8-001",
            "slot_id": "slot-1",
            "status": "landed",
            "finalization_row_kind": "merged_pr",
            "owner": "codex",
            "dispatch_source": "vault://NEXT_LOOP.md#G8-001",
            "source_manifest": "obsidian-vault/dispatch/next_dispatch_manifest.json",
            "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/605",
            "changed_files": ["tools/task-finalization-ledger.py"],
            "verification": {
                "commands": [{"command": "make task-finalization-test", "exit_code": 0}],
                "passed": True,
            },
            "open_followups": [],
            "docs_updated": True,
            "readme_updated": False,
            "frontdoor_updated": False,
            "outcome_or_calibration_updated": False,
            "memory_updates": ["obsidian-vault/tasks/finalized/g8-001-slot-1-landed.md"],
            "blocked_by": None,
            "closed_at": "2026-05-05T00:00:00+00:00",
        }
        row.update(overrides)
        return row

    def read_jsonl(self, path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def fake_merge(self, pr_number=607, merge_commit=None, changed_files=None):
        return ledger_tool.PrMerge(
            pr_number=pr_number,
            merge_commit=merge_commit or ("a" * 40),
            merged_at="2026-05-05T00:00:00+00:00",
            source_owner="Vuk97",
            source_branch=f"pr-{pr_number}-branch",
            subject=f"Merge pull request #{pr_number} from Vuk97/pr-{pr_number}-branch",
            changed_files=tuple(changed_files or ["tools/example.py"]),
        )

    def test_append_row_writes_machine_ledger_completed_log_and_note(self):
        result = ledger_tool.append_row(
            self.row(knowledge_gap_refs=["KG-20260505-001"]),
            self.ledger,
            self.completed,
            self.notes,
        )

        self.assertEqual(result["row"]["schema"], "auditooor.task_finalization.v1")
        self.assertTrue(self.ledger.is_file())
        self.assertTrue(self.completed.is_file())
        self.assertTrue((self.notes / "g8-001-slot-1-landed.md").is_file())
        rows = self.read_jsonl(self.ledger)
        completed = self.read_jsonl(self.completed)
        self.assertEqual(rows[0]["gap_id"], "G8-001")
        self.assertEqual(rows[0]["knowledge_gap_refs"], ["KG-20260505-001"])
        self.assertEqual(completed[0]["gap_id"], "G8-001")
        self.assertEqual(completed[0]["knowledge_gap_refs"], ["KG-20260505-001"])
        self.assertEqual(completed[0]["verification"]["commands"][0]["exit_code"], 0)
        note = (self.notes / "g8-001-slot-1-landed.md").read_text(encoding="utf-8")
        self.assertIn("tools/task-finalization-ledger.py", note)
        self.assertIn("KG-20260505-001", note)
        self.assertEqual(ledger_tool.validate_ledger(self.ledger), [])

    def test_append_row_accepts_false_positive_as_gap_retiring_closure(self):
        row = self.row(
            task_id="g8-004-slot-1-false-positive",
            gap_id="G8-004",
            status="false_positive",
            finalization_row_kind="killed_candidate",
            changed_files=[],
            verification={
                "commands": [{"command": "refutation note reviewed", "exit_code": 0}],
                "passed": False,
            },
            memory_updates=["obsidian-vault/tasks/finalized/g8-004-slot-1-false-positive.md"],
        )

        result = ledger_tool.append_row(row, self.ledger, self.completed, self.notes)

        self.assertEqual(result["row"]["status"], "false_positive")
        completed = self.read_jsonl(self.completed)
        self.assertEqual(completed[0]["finalization_row_kind"], "killed_candidate")
        self.assertEqual(ledger_tool.validate_ledger(self.ledger), [])

        with self.assertRaisesRegex(ValueError, "gap/slot already retired"):
            ledger_tool.append_row(
                self.row(
                    task_id="g8-004-slot-1-retry",
                    gap_id="G8-004",
                    memory_updates=["obsidian-vault/tasks/finalized/g8-004-slot-1-retry.md"],
                    closed_at="2026-05-05T01:00:00+00:00",
                ),
                self.ledger,
                self.completed,
                self.notes,
            )

    def test_validate_missing_ledger_fails_closed(self):
        errors = ledger_tool.validate_ledger(self.ledger)

        self.assertTrue(any("ledger missing" in error for error in errors))

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = ledger_tool.main(["validate", "--ledger", str(self.ledger)])

        self.assertEqual(rc, 1)
        self.assertIn("ledger missing", err.getvalue())

    def test_validate_ledger_rejects_raw_rows_missing_required_fields(self):
        raw = self.row()
        raw.pop("schema")
        raw.pop("closed_at")
        raw.pop("docs_updated")
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(json.dumps(raw) + "\n", encoding="utf-8")

        errors = ledger_tool.validate_ledger(self.ledger)
        summary = ledger_tool.summarize_ledger(self.ledger)

        self.assertTrue(any("schema is required" in error for error in errors))
        self.assertTrue(any("closed_at is required" in error for error in errors))
        self.assertEqual(summary["valid_rows"], 0)
        self.assertEqual(summary["invalid_rows"], 1)

    def test_append_row_rejects_raw_rows_missing_required_fields(self):
        raw = self.row()
        raw.pop("schema")

        with self.assertRaisesRegex(ValueError, "schema is required"):
            ledger_tool.append_row(raw, self.ledger, self.completed, self.notes)

        self.assertFalse(self.ledger.exists())

    def test_append_row_rejects_malformed_knowledge_gap_refs(self):
        with self.assertRaisesRegex(ValueError, "knowledge_gap_refs"):
            ledger_tool.append_row(
                self.row(knowledge_gap_refs=["KG-20260505-001", "../secret"]),
                self.ledger,
                self.completed,
                self.notes,
            )

        self.assertFalse(self.ledger.exists())

    def test_append_row_repairs_missing_sidecars_when_canonical_row_exists(self):
        normalized = ledger_tool.normalize_row(self.row())
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(json.dumps(normalized, sort_keys=True) + "\n", encoding="utf-8")

        result = ledger_tool.append_row(normalized, self.ledger, self.completed, self.notes)

        self.assertTrue(result["ledger_reused"])
        self.assertTrue(result["sidecars_repaired"])
        self.assertEqual(len(self.read_jsonl(self.ledger)), 1)
        self.assertTrue(self.completed.is_file())
        self.assertTrue((self.notes / "g8-001-slot-1-landed.md").is_file())

    def test_rejects_weak_or_spoofed_finalization_rows(self):
        bad_rows = [
            self.row(verification={"commands": [], "passed": True}),
            self.row(verification={"commands": [{"command": "make docs-check", "exit_code": 1}], "passed": True}),
            self.row(terminal_artifact="/Users/wolf/private.md"),
            self.row(terminal_artifact="commit:"),
            self.row(terminal_artifact="commit:notasha"),
            self.row(terminal_artifact="https://github.com/Vuk97/auditooor/issues/1"),
            self.row(terminal_artifact="docs"),
            self.row(terminal_artifact="reports/does-not-exist.md"),
            self.row(changed_files=[]),
            self.row(slot_id="slot-9"),
            self.row(closed_at="2026-05-05T00:00:00"),
        ]
        for row in bad_rows:
            with self.assertRaises(ValueError):
                ledger_tool.append_row(row, self.ledger, self.completed, self.notes)
        self.assertFalse(self.ledger.exists())

    def test_rejects_inconsistent_status_and_finalization_kind_pairs(self):
        bad_rows = [
            self.row(status="landed", finalization_row_kind="operator_deferred"),
            self.row(status="failed", finalization_row_kind="merged_pr", changed_files=[]),
            self.row(status="deferred", finalization_row_kind="failed_gate", changed_files=[], blocked_by="later"),
            self.row(status="false_positive", finalization_row_kind="merged_pr", changed_files=[]),
        ]

        for row in bad_rows:
            with self.assertRaisesRegex(ValueError, "finalization_row_kind for status="):
                ledger_tool.append_row(row, self.ledger, self.completed, self.notes)
        self.assertFalse(self.ledger.exists())

    def test_blocked_row_requires_blocker_or_followup(self):
        blocked = self.row(
            status="blocked",
            finalization_row_kind="operator_deferred",
            changed_files=[],
            verification={
                "commands": [{"command": "make docs-check", "exit_code": 1}],
                "passed": False,
            },
            terminal_artifact="https://github.com/Vuk97/auditooor/pull/605",
            blocked_by=None,
            open_followups=[],
        )
        with self.assertRaises(ValueError):
            ledger_tool.append_row(blocked, self.ledger, self.completed, self.notes)

        blocked["blocked_by"] = "operator gate"
        result = ledger_tool.append_row(blocked, self.ledger, self.completed, self.notes)
        self.assertEqual(result["row"]["status"], "blocked")

    def test_audit_manifest_surfaces_terminal_rows_without_ledger(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [
                {
                    "gap_id": "G8-001",
                    "slot_id": "slot-1",
                    "status": "landed",
                    "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/605",
                },
                {"gap_id": "G8-002", "slot_id": "slot-2", "status": "ready_for_operator_review"},
            ],
            "in_flight_slots": [],
        }), encoding="utf-8")

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)
        self.assertEqual([gap["gap_id"] for gap in gaps], ["G8-001"])

        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)
        self.assertEqual(ledger_tool.manifest_completion_gaps(manifest, self.ledger), [])

    def test_enforce_active_manifest_returns_hook_friendly_statuses(self):
        no_manifest = ledger_tool.enforce_active_manifest(
            self.root,
            manifest=self.vault / "dispatch" / "next_dispatch_manifest.json",
            ledger=self.ledger,
        )
        self.assertEqual(no_manifest["status"], "no_manifest")
        self.assertEqual(no_manifest["completion_gap_count"], 0)

        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [{
                "gap_id": "G8-001",
                "slot_id": "slot-1",
                "status": "landed",
                "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/605",
            }],
        }), encoding="utf-8")

        blocked = ledger_tool.enforce_active_manifest(self.root, manifest=manifest, ledger=self.ledger)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["completion_gap_count"], 1)

        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)
        ok = ledger_tool.enforce_active_manifest(self.root, manifest=manifest, ledger=self.ledger)
        self.assertEqual(ok["status"], "ok")
        self.assertEqual(ok["completion_gap_count"], 0)

    def test_audit_manifest_requires_provable_manifest_artifact_even_with_canonical_row(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [{"gap_id": "G8-001", "slot_id": "slot-1", "status": "landed"}],
            "in_flight_slots": [],
        }), encoding="utf-8")
        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)

        self.assertEqual([gap["gap_id"] for gap in gaps], ["G8-001"])
        self.assertEqual(gaps[0]["proof_gap_reason"], "manifest_terminal_artifact_unproved")

    def test_audit_manifest_ignores_invalid_ledger_rows(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [{"gap_id": "G8-001", "slot_id": "slot-1", "status": "landed"}],
            "in_flight_slots": [],
        }), encoding="utf-8")
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(json.dumps({
            "gap_id": "G8-001",
            "slot_id": "slot-1",
            "status": "landed",
            "terminal_artifact": "commit:",
        }) + "\n", encoding="utf-8")

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)

        self.assertEqual([gap["gap_id"] for gap in gaps], ["G8-001"])

    def test_audit_manifest_does_not_treat_prior_unresolved_attempt_as_later_closure(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        terminal_artifact = "https://github.com/Vuk97/auditooor/pull/605"
        manifest.write_text(json.dumps({
            "slots": [{
                "gap_id": "G8-001",
                "slot_id": "slot-1",
                "status": "landed",
                "terminal_artifact": terminal_artifact,
            }],
            "in_flight_slots": [],
        }), encoding="utf-8")
        ledger_tool.append_row(
            self.row(
                task_id="g8-001-slot-1-deferred",
                status="deferred",
                finalization_row_kind="operator_deferred",
                changed_files=[],
                verification={
                    "commands": [{"command": "operator deferred", "exit_code": 0}],
                    "passed": False,
                },
                open_followups=["retry G8-001"],
                blocked_by="operator scheduling",
            ),
            self.ledger,
            self.completed,
            self.notes,
        )

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)

        self.assertEqual([gap["gap_id"] for gap in gaps], ["G8-001"])

        ledger_tool.append_row(
            self.row(terminal_artifact=terminal_artifact, closed_at="2026-05-05T01:00:00+00:00"),
            self.ledger,
            self.completed,
            self.notes,
        )
        self.assertEqual(ledger_tool.manifest_completion_gaps(manifest, self.ledger), [])

    def test_audit_manifest_requires_exact_artifact_when_manifest_has_artifact(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [{
                "gap_id": "G8-001",
                "slot_id": "slot-1",
                "status": "landed",
                "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/606",
            }],
        }), encoding="utf-8")
        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)

        self.assertEqual([gap["gap_id"] for gap in gaps], ["G8-001"])

    def test_audit_manifest_status_mismatch_is_not_covered_without_artifact(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [{"gap_id": "G8-001", "slot_id": "slot-1", "status": "landed"}],
        }), encoding="utf-8")
        ledger_tool.append_row(
            self.row(
                status="failed",
                finalization_row_kind="failed_gate",
                changed_files=[],
                verification={
                    "commands": [{"command": "make docs-check", "exit_code": 1}],
                    "passed": False,
                },
            ),
            self.ledger,
            self.completed,
            self.notes,
        )

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)

        self.assertEqual([gap["status"] for gap in gaps], ["landed"])

    def test_validate_ledger_rejects_rows_after_gap_retirement(self):
        first = self.row()
        second = self.row(
            task_id="g8-001-slot-1-failed",
            status="failed",
            finalization_row_kind="failed_gate",
            changed_files=[],
            terminal_artifact="reports/fail.log",
        )
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(
            json.dumps(first) + "\n" + json.dumps(second) + "\n",
            encoding="utf-8",
        )

        errors = ledger_tool.validate_ledger(self.ledger)

        self.assertTrue(any("finalization row after retired gap/slot" in error for error in errors))

    def test_audit_manifest_does_not_use_row_after_retirement_as_coverage(self):
        manifest = self.vault / "dispatch" / "next_dispatch_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "slots": [{
                "gap_id": "G8-001",
                "slot_id": "slot-1",
                "status": "failed",
                "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/606",
            }],
        }), encoding="utf-8")
        first = self.row()
        invalid_later = self.row(
            task_id="g8-001-slot-1-failed",
            status="failed",
            finalization_row_kind="failed_gate",
            changed_files=[],
            terminal_artifact="https://github.com/Vuk97/auditooor/pull/606",
            verification={
                "commands": [{"command": "make docs-check", "exit_code": 1}],
                "passed": False,
            },
        )
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(
            json.dumps(first) + "\n" + json.dumps(invalid_later) + "\n",
            encoding="utf-8",
        )

        gaps = ledger_tool.manifest_completion_gaps(manifest, self.ledger)

        self.assertTrue(any("finalization row after retired gap/slot" in error
                            for error in ledger_tool.validate_ledger(self.ledger)))
        self.assertEqual([gap["gap_id"] for gap in gaps], ["G8-001"])

    def test_validate_ledger_rejects_duplicate_task_ids(self):
        first = self.row()
        duplicate = self.row(
            gap_id="G8-002",
            slot_id="slot-2",
            closed_at="2026-05-05T01:00:00+00:00",
        )
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(
            json.dumps(first) + "\n" + json.dumps(duplicate) + "\n",
            encoding="utf-8",
        )

        errors = ledger_tool.validate_ledger(self.ledger)
        summary = ledger_tool.summarize_ledger(self.ledger)
        report = ledger_tool.build_report(self.ledger)

        self.assertTrue(any("duplicate task_id" in error for error in errors))
        self.assertEqual(summary["duplicate_task_id_count"], 1)
        self.assertEqual(report["summary"]["duplicate_task_id_count"], 1)

    def test_append_row_allows_unresolved_attempt_then_gap_retiring_retry(self):
        failed = self.row(
            task_id="g8-001-slot-1-failed",
            status="failed",
            finalization_row_kind="failed_gate",
            changed_files=[],
            terminal_artifact="https://github.com/Vuk97/auditooor/pull/605",
            verification={
                "commands": [{"command": "make task-finalization-test", "exit_code": 1}],
                "passed": False,
            },
        )

        ledger_tool.append_row(failed, self.ledger, self.completed, self.notes)
        ledger_tool.append_row(self.row(closed_at="2026-05-05T01:00:00+00:00"), self.ledger, self.completed, self.notes)

        rows = self.read_jsonl(self.ledger)
        self.assertEqual([row["status"] for row in rows], ["failed", "landed"])
        self.assertEqual(ledger_tool.validate_ledger(self.ledger), [])

    def test_append_row_rejects_existing_task_or_gap_slot(self):
        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)

        with self.assertRaisesRegex(ValueError, "task_id already finalized"):
            ledger_tool.append_row(self.row(gap_id="G8-002"), self.ledger, self.completed, self.notes)

        with self.assertRaisesRegex(ValueError, "gap/slot already retired"):
            ledger_tool.append_row(
                self.row(task_id="g8-001-slot-1-replayed"),
                self.ledger,
                self.completed,
                self.notes,
            )

    def test_append_row_persists_failed_and_deferred_rows_with_status_and_blockers(self):
        failed = self.row(
            task_id="g8-002-slot-1-failed",
            gap_id="G8-002",
            status="failed",
            finalization_row_kind="failed_gate",
            changed_files=[],
            terminal_artifact="https://github.com/Vuk97/auditooor/pull/605",
            verification={
                "commands": [{"command": "make docs-check", "exit_code": 1}],
                "passed": False,
            },
            memory_updates=["reports/failure-analysis.md"],
        )
        deferred = self.row(
            task_id="g8-003-slot-2-deferred",
            gap_id="G8-003",
            slot_id="slot-2",
            status="deferred",
            finalization_row_kind="operator_deferred",
            changed_files=[],
            terminal_artifact="https://github.com/Vuk97/auditooor/pull/605",
            verification={
                "commands": [{"command": "operator deferred", "exit_code": 0}],
                "passed": False,
            },
            open_followups=["G9-001"],
            blocked_by="operator scheduling",
        )

        ledger_tool.append_row(failed, self.ledger, self.completed, self.notes)
        ledger_tool.append_row(deferred, self.ledger, self.completed, self.notes)

        rows = self.read_jsonl(self.ledger)
        completed = self.read_jsonl(self.completed)
        self.assertEqual([row["status"] for row in rows], ["failed", "deferred"])
        self.assertEqual([row["status"] for row in completed], ["failed", "deferred"])
        self.assertEqual(rows[0]["verification"]["commands"][0]["exit_code"], 1)
        deferred_note = (self.notes / "g8-003-slot-2-deferred.md").read_text(encoding="utf-8")
        self.assertIn("Status: `deferred`", deferred_note)
        self.assertIn("operator scheduling", deferred_note)

    def test_from_commit_builds_landed_row_from_symbolic_commit_and_writes_outputs(self):
        out = io.StringIO()

        with contextlib.redirect_stdout(out):
            rc = ledger_tool.main([
                "from-commit",
                "--ledger", str(self.ledger),
                "--vault-dir", str(self.vault),
                "--commit", "HEAD",
                "--gap-id", "G8-010",
                "--slot-id", "slot-1",
                "--owner", "codex",
                "--source-manifest", "obsidian-vault/dispatch/next_dispatch_manifest.json",
                "--verification", "make task-finalization-test=0",
                "--memory-update", "docs/TASK_FINALIZATION_LEDGER.md",
                "--docs-updated",
            ])

        self.assertEqual(rc, 0)
        result = json.loads(out.getvalue())
        row = result["row"]
        self.assertEqual(row["gap_id"], "G8-010")
        self.assertEqual(row["status"], "landed")
        self.assertRegex(row["terminal_artifact"], r"^commit:[0-9a-f]{40}$")
        self.assertTrue(row["changed_files"])
        self.assertEqual(row["verification"]["commands"][0]["exit_code"], 0)
        self.assertTrue((self.notes / f"{row['task_id']}.md").is_file())

    def test_report_summarizes_counts_recent_rows_and_invalid_rows(self):
        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)
        self.ledger.write_text(
            self.ledger.read_text(encoding="utf-8")
            + json.dumps({"gap_id": "bad", "slot_id": "slot-1", "status": "landed"}) + "\n",
            encoding="utf-8",
        )

        report = ledger_tool.build_report(self.ledger, limit=1)
        markdown = ledger_tool.render_report(report)

        self.assertEqual(report["schema"], "auditooor.task_finalization_report.v1")
        self.assertEqual(report["summary"]["total_rows"], 2)
        self.assertEqual(report["summary"]["valid_rows"], 1)
        self.assertEqual(report["summary"]["invalid_row_count"], 1)
        self.assertEqual(report["summary"]["by_status"], {"landed": 1})
        self.assertEqual(len(report["rows_recent"]), 1)
        self.assertIn("Task Finalization Report", markdown)
        self.assertIn("Validation Errors", markdown)

    def test_report_orders_latest_and_recent_rows_by_parsed_closed_at(self):
        first = self.row(
            task_id="g8-001-slot-1-landed",
            gap_id="G8-001",
            closed_at="2026-05-05T01:00:00+02:00",
        )
        later = self.row(
            task_id="g8-002-slot-1-landed",
            gap_id="G8-002",
            closed_at="2026-05-04T23:30:00Z",
        )
        ledger_tool.append_row(first, self.ledger, self.completed, self.notes)
        ledger_tool.append_row(later, self.ledger, self.completed, self.notes)

        report = ledger_tool.build_report(self.ledger, limit=2)

        self.assertEqual(report["latest"]["task_id"], "g8-002-slot-1-landed")
        self.assertEqual(
            [row["task_id"] for row in report["rows_recent"]],
            ["g8-002-slot-1-landed", "g8-001-slot-1-landed"],
        )

    def test_main_report_json_exits_zero_even_with_invalid_rows(self):
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(json.dumps({"gap_id": "bad"}) + "\n", encoding="utf-8")
        out = io.StringIO()

        with contextlib.redirect_stdout(out):
            rc = ledger_tool.main(["report", "--ledger", str(self.ledger), "--json"])

        payload = json.loads(out.getvalue())
        self.assertEqual(rc, 0)
        self.assertEqual(payload["summary"]["invalid_row_count"], 1)

    def test_main_report_malformed_jsonl_returns_error(self):
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text("{not-json}\n", encoding="utf-8")
        err = io.StringIO()

        with contextlib.redirect_stderr(err):
            rc = ledger_tool.main(["report", "--ledger", str(self.ledger), "--json"])

        self.assertEqual(rc, 2)
        self.assertIn("invalid JSONL row", err.getvalue())

    def test_main_summary_json_and_markdown_emit_summary_schema(self):
        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)
        json_out = io.StringIO()

        with contextlib.redirect_stdout(json_out):
            json_rc = ledger_tool.main(["summary", "--ledger", str(self.ledger), "--json"])

        payload = json.loads(json_out.getvalue())
        self.assertEqual(json_rc, 0)
        self.assertEqual(payload["schema"], "auditooor.task_finalization_summary.v1")
        self.assertEqual(payload["valid_rows"], 1)

        md_out = io.StringIO()
        with contextlib.redirect_stdout(md_out):
            md_rc = ledger_tool.main(["summary", "--ledger", str(self.ledger), "--markdown"])

        self.assertEqual(md_rc, 0)
        self.assertIn("Task Finalization Summary", md_out.getvalue())

    def test_main_summary_out_writes_file(self):
        ledger_tool.append_row(self.row(), self.ledger, self.completed, self.notes)
        out_path = self.root / "summary.json"

        rc = ledger_tool.main(["summary", "--ledger", str(self.ledger), "--json", "--out", str(out_path)])

        self.assertEqual(rc, 0)
        self.assertEqual(
            json.loads(out_path.read_text(encoding="utf-8"))["schema"],
            "auditooor.task_finalization_summary.v1",
        )

    def test_parse_pr_merge_subject_rejects_non_pr_merge(self):
        self.assertEqual(
            ledger_tool.parse_pr_merge_subject("Merge pull request #607 from Vuk97/feature"),
            (607, "Vuk97", "feature"),
        )
        self.assertIsNone(ledger_tool.parse_pr_merge_subject("Merge branch 'main' into feature"))

    def test_pr_range_status_reports_missing_without_ledger(self):
        original_commit_exists = ledger_tool.commit_exists
        ledger_tool.commit_exists = lambda sha: True
        try:
            payload = ledger_tool.build_pr_range_status(
                self.ledger,
                "origin/main",
                607,
                608,
                discovered=[self.fake_merge(607), self.fake_merge(608, merge_commit="b" * 40)],
            )
        finally:
            ledger_tool.commit_exists = original_commit_exists

        self.assertEqual(payload["schema"], "auditooor.task_finalization_pr_range_status.v1")
        self.assertEqual(payload["summary"]["readiness"], "missing")
        self.assertEqual(payload["summary"]["missing_count"], 2)

    def test_pr_range_status_accepts_github_pr_url_as_coverage(self):
        ledger_tool.append_row(
            self.row(
                task_id="pr607-url-coverage",
                gap_id="PR607",
                terminal_artifact="https://github.com/Vuk97/auditooor/pull/607",
                memory_updates=["obsidian-vault/tasks/finalized/pr607-url-coverage.md"],
            ),
            self.ledger,
            self.completed,
            self.notes,
        )
        original_commit_exists = ledger_tool.commit_exists
        ledger_tool.commit_exists = lambda sha: True
        try:
            payload = ledger_tool.build_pr_range_status(
                self.ledger, "origin/main", 607, 607, discovered=[self.fake_merge(607)])
        finally:
            ledger_tool.commit_exists = original_commit_exists

        self.assertEqual(payload["summary"]["readiness"], "ready")
        self.assertEqual(payload["rows"][0]["status"], "covered")

    def test_pr_range_status_reports_mismatch_for_wrong_commit(self):
        original_commit_exists = ledger_tool.commit_exists
        ledger_tool.commit_exists = lambda sha: True
        try:
            ledger_tool.append_row(
                self.row(
                    task_id="pr607-wrong-commit",
                    gap_id="PR607",
                    terminal_artifact=f"commit:{'b' * 40}",
                    memory_updates=["obsidian-vault/tasks/finalized/pr607-wrong-commit.md"],
                ),
                self.ledger,
                self.completed,
                self.notes,
            )
            payload = ledger_tool.build_pr_range_status(
                self.ledger, "origin/main", 607, 607, discovered=[self.fake_merge(607, merge_commit="a" * 40)])
        finally:
            ledger_tool.commit_exists = original_commit_exists

        self.assertEqual(payload["summary"]["readiness"], "invalid")
        self.assertEqual(payload["rows"][0]["status"], "mismatch")

    def test_pr_range_backfill_dry_run_emits_valid_rows_and_writes_nothing(self):
        original_commit_exists = ledger_tool.commit_exists
        ledger_tool.commit_exists = lambda sha: True
        try:
            payload = ledger_tool.build_pr_range_backfill(
                self.ledger,
                self.completed,
                self.notes,
                "origin/main",
                607,
                608,
                "codex",
                dry_run=True,
                discovered=[self.fake_merge(607), self.fake_merge(608, merge_commit="b" * 40)],
            )
            for row in payload["generated_rows"]:
                self.assertEqual(ledger_tool.validate_row(row), [])
        finally:
            ledger_tool.commit_exists = original_commit_exists

        self.assertEqual(payload["schema"], "auditooor.task_finalization_pr_range_backfill.v1")
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["generated_count"], 2)
        self.assertFalse(self.ledger.exists())

    def test_pr_range_backfill_write_is_idempotent(self):
        original_commit_exists = ledger_tool.commit_exists
        ledger_tool.commit_exists = lambda sha: True
        merge = self.fake_merge(607)
        try:
            first = ledger_tool.build_pr_range_backfill(
                self.ledger,
                self.completed,
                self.notes,
                "origin/main",
                607,
                607,
                "codex",
                dry_run=False,
                discovered=[merge],
            )
            second = ledger_tool.build_pr_range_backfill(
                self.ledger,
                self.completed,
                self.notes,
                "origin/main",
                607,
                607,
                "codex",
                dry_run=False,
                discovered=[merge],
            )
        finally:
            ledger_tool.commit_exists = original_commit_exists

        self.assertEqual(first["appended_count"], 1)
        self.assertEqual(first["status_after"]["readiness"], "ready")
        self.assertEqual(second["appended_count"], 0)
        self.assertEqual(len(self.read_jsonl(self.ledger)), 1)
        self.assertTrue((self.notes / first["generated_rows"][0]["task_id"]).with_suffix(".md").is_file())

    def test_main_pr_range_backfill_defaults_to_dry_run_and_write_requires_flag(self):
        original_commit_exists = ledger_tool.commit_exists
        original_discover = ledger_tool.discover_pr_merges
        ledger_tool.commit_exists = lambda sha: True
        ledger_tool.discover_pr_merges = lambda base_ref, start_pr, end_pr: [self.fake_merge(607)]
        dry_run_out = self.root / "dry-run.json"
        write_out = self.root / "write.json"
        try:
            dry_rc = ledger_tool.main([
                "backfill-pr-range",
                "--ledger", str(self.ledger),
                "--vault-dir", str(self.vault),
                "--start-pr", "607",
                "--end-pr", "607",
                "--json",
                "--out", str(dry_run_out),
            ])
            dry_payload = json.loads(dry_run_out.read_text(encoding="utf-8"))
            write_rc = ledger_tool.main([
                "backfill-pr-range",
                "--ledger", str(self.ledger),
                "--vault-dir", str(self.vault),
                "--start-pr", "607",
                "--end-pr", "607",
                "--write",
                "--json",
                "--out", str(write_out),
            ])
        finally:
            ledger_tool.commit_exists = original_commit_exists
            ledger_tool.discover_pr_merges = original_discover

        self.assertEqual(dry_rc, 0)
        self.assertTrue(dry_payload["dry_run"])
        self.assertEqual(dry_payload["generated_count"], 1)
        self.assertEqual(write_rc, 0)
        self.assertTrue(self.ledger.is_file())
        self.assertEqual(json.loads(write_out.read_text(encoding="utf-8"))["appended_count"], 1)

    def test_pr_range_backfill_fails_closed_on_invalid_existing_row(self):
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(json.dumps({"gap_id": "PR607", "slot_id": "slot-1", "status": "landed"}) + "\n",
                               encoding="utf-8")
        original_commit_exists = ledger_tool.commit_exists
        ledger_tool.commit_exists = lambda sha: True
        try:
            with self.assertRaisesRegex(ValueError, "cannot backfill PR range"):
                ledger_tool.build_pr_range_backfill(
                    self.ledger,
                    self.completed,
                    self.notes,
                    "origin/main",
                    607,
                    607,
                    "codex",
                    dry_run=True,
                    discovered=[self.fake_merge(607)],
                )
        finally:
            ledger_tool.commit_exists = original_commit_exists


if __name__ == "__main__":
    unittest.main()
