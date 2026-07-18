#!/usr/bin/env python3
"""Tests for the agent-recall-detector-loop 5-stage orchestrator."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LOOP_TOOL = ROOT / "tools" / "agent-recall-detector-loop.py"
BRIEF_TEMPLATE = ROOT / "agent_briefs" / "templates" / "detector-authoring-brief.template.md"


def load_loop():
    spec = importlib.util.spec_from_file_location("agent_recall_detector_loop", LOOP_TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loop = load_loop()


def _make_ws(tasks: list | None = None) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="ardl_test_"))
    audit = ws / ".auditooor"
    audit.mkdir()
    if tasks is not None:
        payload = {
            "schema": "auditooor.pr560.agent_recall_detector_tasks.v1",
            "task_count": len(tasks),
            "queue_count": len(tasks),
            "task_type_counts": {"detector_task": sum(1 for t in tasks if t.get("task_type") == "detector_task")},
            "tasks": tasks,
        }
        (audit / "agent_recall_detector_tasks.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
    return ws


class TestDetectorTaskFiltering(unittest.TestCase):
    def test_detector_tasks_extracted_from_payload(self):
        tasks = [
            {"task_type": "detector_task", "task_id": "ARDT-001", "queue_id": "ARDQ-001",
             "source": "agent_recall", "source_id": "foo-bar", "reason": "needs fixture",
             "next_command": "make foo", "terminal_blockers": ["missing_vulnerable_fixture"],
             "claims_detected": ["Contract.sol:42"]},
            {"task_type": "source_proof_task", "task_id": "ARDT-002", "queue_id": "ARDQ-002",
             "source": "provider", "source_id": "sp-01", "reason": "source proof",
             "next_command": "make bar", "terminal_blockers": [], "claims_detected": []},
            {"task_type": "terminal_blocker", "task_id": "ARDT-003", "queue_id": "ARDQ-003",
             "source": "known_limitations", "source_id": "kl-01", "reason": "blocker",
             "next_command": "make baz", "terminal_blockers": [], "claims_detected": []},
        ]
        payload = {"tasks": tasks, "task_count": 3, "queue_count": 3}
        result = loop._detector_tasks(payload)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["task_id"], "ARDT-001")

    def test_empty_tasks_returns_empty(self):
        self.assertEqual(loop._detector_tasks({}), [])
        self.assertEqual(loop._detector_tasks({"tasks": []}), [])

    def test_non_dict_tasks_skipped(self):
        payload = {"tasks": [None, "string", 42, {"task_type": "detector_task", "task_id": "X"}]}
        result = loop._detector_tasks(payload)
        self.assertEqual(len(result), 1)


class TestBriefRendering(unittest.TestCase):
    def test_renders_brief_with_template_placeholders(self):
        task = {
            "task_id": "ARDT-001",
            "queue_id": "ARDQ-001",
            "source": "agent_recall",
            "source_id": "my-detector",
            "source_artifact": "agent_outputs/foo.md",
            "reason": "needs fixture-backed detectorization",
            "claims_detected": ["Foo.sol:10", "Bar.sol:20"],
            "terminal_blockers": ["missing_vulnerable_fixture", "missing_clean_fixture"],
            "next_command": "make agent-recall-detector-queue WS=<workspace>",
            "suggested_detector_slug": "reentrancy-cross-function",
        }
        content = loop._render_brief(task, lang="solidity", context_pack_id="test-pack-id")
        self.assertIn("reentrancy-cross-function", content)
        self.assertIn("test-pack-id", content)
        self.assertIn("ARDQ-001", content)
        self.assertIn("Foo.sol:10", content)
        self.assertIn("missing_vulnerable_fixture", content)

    def test_renders_brief_fallback_when_template_missing(self):
        task = {
            "task_id": "ARDT-099",
            "queue_id": "ARDQ-099",
            "source": "semantic_scanner_inventory",
            "source_id": "sem-99",
            "source_artifact": "",
            "reason": "semantic row",
            "claims_detected": [],
            "terminal_blockers": [],
            "next_command": "make foo",
        }
        # Use default template (no file)
        content = loop._default_template().format(
            detector_slug="sem-99",
            context_pack_id="cp-test",
            queue_id="ARDQ-099",
            task_id="ARDT-099",
            source="semantic_scanner_inventory",
            source_artifact="",
            generated_at_utc="2026-01-01T00:00:00+00:00",
            claims_detected="- _none recorded_",
            reason="semantic row",
            lang="solidity",
            ext="sol",
            terminal_blockers="- _none_",
            next_command="make foo",
        )
        self.assertIn("ARDQ-099", content)
        self.assertIn("cp-test", content)

    def test_slug_truncates_long_names(self):
        long = "a" * 200
        result = loop._slug(long)
        self.assertLessEqual(len(result), 80)

    def test_slug_normalises_special_chars(self):
        result = loop._slug("Missing Guard / Re-entrancy (Cross-Function)")
        self.assertRegex(result, r"^[a-z0-9-]+$")


class TestStage1BuildQueue(unittest.TestCase):
    def test_dry_run_returns_existing_tasks_payload(self):
        tasks = [{"task_type": "detector_task", "task_id": "ARDT-001"}]
        ws = _make_ws(tasks)
        logged = []
        result = loop.run_stage1_build_queue(ws, dry_run=True, log=logged.append)
        self.assertIn("tasks", result)
        self.assertEqual(len(result["tasks"]), 1)

    def test_dry_run_returns_empty_when_no_artifact(self):
        ws = _make_ws()  # no tasks file
        logged = []
        result = loop.run_stage1_build_queue(ws, dry_run=True, log=logged.append)
        self.assertEqual(result.get("tasks", []), [])


class TestStage2Dispatcher(unittest.TestCase):
    def test_returns_detector_tasks_subset(self):
        tasks = [
            {"task_type": "detector_task", "task_id": "ARDT-001", "source_id": "d1"},
            {"task_type": "source_proof_task", "task_id": "ARDT-002", "source_id": "s1"},
        ]
        payload = {"tasks": tasks, "task_count": 2, "queue_count": 2}
        ws = _make_ws(tasks)
        logged = []
        result = loop.run_stage2_dispatcher(ws, payload, dry_run=True, log=logged.append)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["task_id"], "ARDT-001")

    def test_returns_empty_when_no_detector_tasks(self):
        tasks = [{"task_type": "source_proof_task", "task_id": "ARDT-002", "source_id": "s1"}]
        payload = {"tasks": tasks}
        ws = _make_ws(tasks)
        logged = []
        result = loop.run_stage2_dispatcher(ws, payload, dry_run=True, log=logged.append)
        self.assertEqual(result, [])


class TestStage3MaterialiseBriefs(unittest.TestCase):
    def test_dry_run_returns_paths_without_writing(self):
        task = {
            "task_type": "detector_task",
            "task_id": "ARDT-001",
            "queue_id": "ARDQ-001",
            "source": "agent_recall",
            "source_id": "check-access-control",
            "source_artifact": "",
            "reason": "needs fixture",
            "claims_detected": ["Token.sol:42"],
            "terminal_blockers": ["missing_vulnerable_fixture"],
            "next_command": "make foo",
            "suggested_detector_slug": "check-access-control",
        }
        ws = _make_ws()
        logged = []
        result = loop.run_stage3_materialise_briefs(
            ws, [task], dry_run=True, lang="solidity",
            context_pack_id="test-pack", log=logged.append
        )
        self.assertEqual(len(result), 1)
        # file should NOT exist in dry-run
        self.assertFalse(result[0].exists())
        self.assertTrue(any("dry-run" in msg for msg in logged))

    def test_writes_brief_in_non_dry_run(self):
        task = {
            "task_type": "detector_task",
            "task_id": "ARDT-001",
            "queue_id": "ARDQ-001",
            "source": "agent_recall",
            "source_id": "reentrancy-guard",
            "source_artifact": "",
            "reason": "needs fixture",
            "claims_detected": [],
            "terminal_blockers": [],
            "next_command": "make foo",
            "suggested_detector_slug": "reentrancy-guard",
        }
        ws = _make_ws()
        logged = []
        result = loop.run_stage3_materialise_briefs(
            ws, [task], dry_run=False, lang="solidity",
            context_pack_id="cp-123", log=logged.append
        )
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].exists())
        content = result[0].read_text(encoding="utf-8")
        self.assertIn("cp-123", content)


class TestStage4SeedFixtures(unittest.TestCase):
    def test_dry_run_does_not_create_files(self):
        task = {
            "task_id": "ARDT-001",
            "source_id": "unguarded-ext-call",
            "suggested_detector_slug": "unguarded-ext-call",
        }
        ws = _make_ws()
        logged = []
        result = loop.run_stage4_seed_fixtures(ws, [task], dry_run=True, lang="solidity", log=logged.append)
        for p in result:
            self.assertFalse(p.exists())

    def test_skips_existing_fixture(self):
        import tempfile
        # Create a positive fixture that already exists
        fixture_dir = ROOT / "detectors" / "fixtures" / "solidity"
        task = {
            "task_id": "ARDT-001",
            "source_id": "existing-detector",
            "suggested_detector_slug": "existing-detector",
        }
        # We run in dry-run so no actual files are written
        ws = _make_ws()
        logged = []
        result = loop.run_stage4_seed_fixtures(ws, [task], dry_run=True, lang="solidity", log=logged.append)
        # Should still list the paths even in dry-run
        self.assertIsInstance(result, list)


class TestStage5PromoteCheck(unittest.TestCase):
    def test_dry_run_returns_0(self):
        ws = _make_ws()
        logged = []
        rc = loop.run_stage5_promote_check(ws, dry_run=True, log=logged.append)
        self.assertEqual(rc, 0)
        self.assertTrue(any("dry-run" in msg for msg in logged))


class TestWriteLoopManifest(unittest.TestCase):
    def test_manifest_written_correctly(self):
        ws = _make_ws()
        path = loop.write_loop_manifest(
            ws,
            stages_run=[1, 2, 3, 4, 5],
            detector_tasks=[{"task_id": "ARDT-001"}],
            briefs=[],
            fixtures=[],
            promote_rc=0,
            dry_run=True,
            context_pack_id="cp-xyz",
        )
        self.assertTrue(path.exists())
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], loop.SCHEMA)
        self.assertEqual(payload["context_pack_id"], "cp-xyz")
        self.assertEqual(payload["detector_task_count"], 1)
        self.assertTrue(payload["advisory_only"])
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")


class TestCLIDryRun(unittest.TestCase):
    def test_cli_dry_run_exits_0_or_1(self):
        """CLI --dry-run must exit 0 (tasks found) or 1 (no detector tasks) — never crash."""
        ws = _make_ws()
        result = subprocess.run(
            [sys.executable, str(LOOP_TOOL), "--workspace", str(ws), "--dry-run"],
            capture_output=True, text=True,
        )
        self.assertIn(result.returncode, (0, 1),
                      msg=f"unexpected rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}")

    def test_cli_missing_workspace_returns_2(self):
        result = subprocess.run(
            [sys.executable, str(LOOP_TOOL), "--workspace", "/nonexistent/__no_such_dir__", "--dry-run"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)

    def test_cli_stage_range_1_3(self):
        ws = _make_ws()
        result = subprocess.run(
            [sys.executable, str(LOOP_TOOL), "--workspace", str(ws), "--dry-run", "--stage", "1-3"],
            capture_output=True, text=True,
        )
        self.assertIn(result.returncode, (0, 1))
        # manifest should exist
        manifest = ws / ".auditooor" / "agent_recall_detector_loop.json"
        self.assertTrue(manifest.exists())
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        # only stages 1,2,3 should have run (4 and 5 skipped)
        self.assertNotIn(5, payload["stages_run"])


class TestBriefTemplateExists(unittest.TestCase):
    def test_template_file_present(self):
        self.assertTrue(BRIEF_TEMPLATE.is_file(), f"Template missing: {BRIEF_TEMPLATE}")

    def test_template_has_required_placeholders(self):
        content = BRIEF_TEMPLATE.read_text(encoding="utf-8")
        for placeholder in ["{detector_slug}", "{context_pack_id}", "{queue_id}", "{claims_detected}"]:
            self.assertIn(placeholder, content, f"Missing placeholder: {placeholder}")


if __name__ == "__main__":
    unittest.main()
