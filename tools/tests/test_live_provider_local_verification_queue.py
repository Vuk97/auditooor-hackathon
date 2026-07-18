from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-provider-local-verification-queue.py"


def _import():
    spec = importlib.util.spec_from_file_location("live_provider_local_verification_queue_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _provider_pair(base: Path, task_id: str, kimi_obj: dict, minimax_obj: dict) -> dict:
    kimi = base / f"{task_id}.kimi.out.jsonl"
    minimax = base / f"{task_id}.minimax.out.jsonl"
    kimi.write_text(json.dumps(kimi_obj) + "\n", encoding="utf-8")
    minimax.write_text(json.dumps(minimax_obj) + "\n", encoding="utf-8")
    final = base / f"{task_id}.provider-assist.json"
    final.write_text(json.dumps({"task_id": task_id}), encoding="utf-8")
    return {
        "task_id": task_id,
        "final": str(final),
        "kimi_output": str(kimi),
        "minimax_output": str(minimax),
        "provider_object_count": 2,
        "advisory_only": True,
        "promotion_authority": False,
        "local_verification_required": True,
    }


class LiveProviderLocalVerificationQueueTests(unittest.TestCase):
    def test_candidate_harvest_routes_to_grep_fixture_and_source_review(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            row = _provider_pair(
                root,
                "worker-at-001",
                {
                    "candidate_detector_shape": {
                        "family": "path-filtering",
                        "local_verification_grep_patterns": ["def _skip_path", "SKIP_DIR_PARTS"],
                    },
                    "extracted_source_facts": {
                        "file": str(ROOT / "tools" / "anchor-detector-runner.py"),
                        "symbol": "_skip_path",
                    },
                    "local_checks_required": ["grep callers of _skip_path"],
                },
                {
                    "classification": "KEEP_FOR_LOCAL_VERIFICATION",
                    "minimum_followup_check": "Verify `_skip_path` callers and add fixture coverage",
                },
            )
            row.update(
                {
                    "primary_category": "candidate_harvest",
                    "categories": ["candidate_harvest", "needs_local_grep", "needs_fixture", "non_detectorizable"],
                    "classifications": ["KEEP_FOR_LOCAL_VERIFICATION"],
                    "reason": "keep",
                }
            )
            triage = root / "triage.json"
            triage.write_text(json.dumps({"rows": [row]}), encoding="utf-8")
            payload = mod.build_queue(triage)

        self.assertEqual(payload["summary"]["candidate_harvest_rows"], 1)
        self.assertEqual(payload["summary"]["local_grep_tasks"], 1)
        self.assertEqual(payload["summary"]["fixture_needed_tasks"], 1)
        self.assertEqual(payload["summary"]["source_review_tasks"], 1)
        self.assertEqual(payload["summary"]["killed_rows"], 0)
        self.assertEqual(payload["summary"]["total_queue_items"], 3)
        grep = payload["local_grep_tasks"][0]
        self.assertEqual(grep["severity"], "none")
        self.assertFalse(grep["submit_ready"])
        self.assertIn("def _skip_path", grep["grep_patterns"])
        self.assertIn("rg -n", grep["next_command"])

    def test_killed_by_minimax_rows_are_preserved_without_candidate_promotion(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            row = _provider_pair(
                root,
                "worker-at-002",
                {
                    "candidate_detector_shape": {"family": "json-load"},
                    "extracted_source_facts": {"file": str(ROOT / "tools" / "attach-invariant.py"), "symbol": "load_manifest"},
                },
                {
                    "classification": "REJECT_DUPLICATE",
                    "minimum_followup_check": "Confirm MANIFEST path is hardcoded",
                },
            )
            row.update(
                {
                    "primary_category": "killed_by_minimax",
                    "categories": ["killed_by_minimax", "needs_local_grep"],
                    "classifications": ["REJECT_DUPLICATE"],
                    "reason": "Minimax classification(s): REJECT_DUPLICATE",
                }
            )
            triage = root / "triage.json"
            triage.write_text(json.dumps({"rows": [row]}), encoding="utf-8")
            payload = mod.build_queue(triage)

        self.assertEqual(payload["summary"]["candidate_harvest_rows"], 0)
        self.assertEqual(payload["summary"]["killed_rows"], 1)
        killed = payload["killed_rows"][0]
        self.assertEqual(killed["route"], "killed_by_minimax")
        self.assertEqual(killed["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("kill_confirmed", killed["terminal_state_options"])
        self.assertNotIn("candidate_harvest", killed["provider_categories"])

    def test_markdown_renders_all_four_sections(self) -> None:
        mod = _import()
        payload = {
            "source_triage": "triage.json",
            "advisory_only": True,
            "submit_ready": False,
            "summary": {
                "total_queue_items": 0,
                "candidate_harvest_rows": 0,
                "killed_by_minimax_rows": 0,
                "local_grep_tasks": 0,
                "fixture_needed_tasks": 0,
                "source_review_tasks": 0,
                "killed_rows": 0,
            },
            "local_grep_tasks": [],
            "fixture_needed_tasks": [],
            "source_review_tasks": [],
            "killed_rows": [],
        }
        md = mod.render_markdown(payload)
        self.assertIn("Local Grep Tasks", md)
        self.assertIn("Fixture Needed Tasks", md)
        self.assertIn("Source Review Tasks", md)
        self.assertIn("Killed Rows", md)
        self.assertIn("No row promotes severity", md)


if __name__ == "__main__":
    unittest.main()
