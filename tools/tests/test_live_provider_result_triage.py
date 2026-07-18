from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRIAGE = ROOT / "tools" / "live-provider-result-triage.py"


def _import():
    spec = importlib.util.spec_from_file_location("live_provider_result_triage_test", str(TRIAGE))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_result(base: Path, task_id: str, kimi: str, minimax: str) -> Path:
    final_dir = base / "final"
    kimi_dir = base / "kimi"
    minimax_dir = base / "minimax"
    final_dir.mkdir(parents=True, exist_ok=True)
    kimi_dir.mkdir(parents=True, exist_ok=True)
    minimax_dir.mkdir(parents=True, exist_ok=True)
    kimi_path = kimi_dir / f"{task_id}.kimi.out.jsonl"
    minimax_path = minimax_dir / f"{task_id}.minimax.out.jsonl"
    kimi_path.write_text(kimi, encoding="utf-8")
    minimax_path.write_text(minimax, encoding="utf-8")
    final_path = final_dir / f"{task_id}.provider-assist.json"
    final_path.write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_provider_assist_result.v1",
                "task_id": task_id,
                "advisory_only": True,
                "promotion_authority": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "severity": "none",
                "selected_impact": "",
                "local_verification_required": True,
                "kimi_output": str(kimi_path),
                "minimax_output": str(minimax_path),
                "kimi": {"status": "ok"},
                "minimax": {"status": "ok"},
            }
        ),
        encoding="utf-8",
    )
    return final_path


class LiveProviderResultTriageTests(unittest.TestCase):
    def test_parse_pretty_fenced_json_object(self) -> None:
        mod = _import()
        objects, notes = mod.parse_provider_objects(
            textwrap.dedent(
                """
                ```json
                {
                  "task_id": "row-1",
                  "candidate_detector_shape": {"family": "consent"},
                  "local_checks_required": ["grep for consent gate"]
                }
                ```
                """
            )
        )
        self.assertEqual(notes, [])
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["candidate_detector_shape"]["family"], "consent")

    def test_keep_result_is_candidate_harvest_and_needs_grep(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final = _write_result(
                root,
                "row-keep",
                '{"task_id":"row-keep","candidate_detector_shape":{"family":"auth"},"local_checks_required":["grep auth paths"],"advisory_only":true}\n',
                '{"task_id":"row-keep","classification":"KEEP_FOR_LOCAL_VERIFICATION","reason":"verify with local grep","local_verification_required":true}\n',
            )
            row = mod.classify_result(final)
        self.assertEqual(row["primary_category"], "candidate_harvest")
        self.assertEqual(row["evidence_class"], "generated_hypothesis")
        self.assertFalse(row["submit_ready"])
        self.assertIn("needs_local_grep", row["categories"])
        self.assertIn("candidate_harvest", row["categories"])
        self.assertEqual(row["provider_object_count"], 2)
        self.assertEqual(row["local_checks_required"], ["grep auth paths"])
        self.assertEqual(row["actionable_local_check_count"], 1)

    def test_rejected_result_is_killed_by_minimax(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final = _write_result(
                root,
                "row-kill",
                '{"task_id":"row-kill","candidate_detector_shape":{"family":"common"},"advisory_only":true}\n',
                '{"task_id":"row-kill","classification":"REJECT_COMMON_PATTERN","reason":"common pattern, not actionable"}\n',
            )
            row = mod.classify_result(final)
        self.assertEqual(row["primary_category"], "killed_by_minimax")
        self.assertIn("killed_by_minimax", row["categories"])
        self.assertIn("non_detectorizable", row["categories"])
        self.assertNotIn("candidate_harvest", row["categories"])

    def test_missing_provider_file_is_malformed(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final_dir = root / "final"
            final_dir.mkdir()
            final = final_dir / "row-missing.provider-assist.json"
            final.write_text(
                json.dumps(
                    {
                        "task_id": "row-missing",
                        "kimi_output": str(root / "missing.kimi.out.jsonl"),
                        "minimax_output": str(root / "missing.minimax.out.jsonl"),
                        "kimi": {"status": "ok"},
                        "minimax": {"status": "ok"},
                    }
                ),
                encoding="utf-8",
            )
            row = mod.classify_result(final)
        self.assertEqual(row["primary_category"], "malformed")
        self.assertEqual(row["evidence_class"], "generated_hypothesis")
        self.assertFalse(row["submit_ready"])
        self.assertIn("malformed", row["categories"])

    def test_ok_provider_output_with_unparseable_minimax_fails_closed(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final = _write_result(
                root,
                "row-bad-minimax",
                '{"task_id":"row-bad-minimax","candidate_detector_shape":{"family":"auth"},"local_checks_required":["grep auth paths"],"advisory_only":true}\n',
                "verify the auth paths manually, no JSON here\n",
            )
            row = mod.classify_result(final)
        self.assertEqual(row["primary_category"], "malformed")
        self.assertIn("malformed", row["categories"])
        self.assertNotIn("candidate_harvest", row["categories"])
        self.assertEqual(row["provider_object_count"], 1)
        self.assertIn("no-json-object", row["parse_notes"]["minimax"])
        self.assertEqual(row["local_checks_required"], ["grep auth paths"])

    def test_unsupported_minimax_classification_fails_closed_but_keeps_checks(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final = _write_result(
                root,
                "row-unsupported",
                '{"task_id":"row-unsupported","candidate_detector_shape":{"family":"auth"},"local_checks_required":["grep auth paths"],"advisory_only":true}\n',
                '{"task_id":"row-unsupported","classification":"APPROVE_FOR_SUBMISSION","minimum_followup_check":"confirm auth gate locally"}\n',
            )
            row = mod.classify_result(final)
        self.assertEqual(row["primary_category"], "malformed")
        self.assertNotIn("candidate_harvest", row["categories"])
        self.assertIn("unsupported-classification:APPROVE_FOR_SUBMISSION", ";".join(row["provider_schema_notes"]))
        self.assertEqual(row["local_checks_required"], ["grep auth paths"])
        self.assertEqual(row["minimum_followup_checks"], ["confirm auth gate locally"])

    def test_candidate_shape_without_actionable_local_check_fails_closed(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            final = _write_result(
                root,
                "row-no-check",
                '{"task_id":"row-no-check","candidate_detector_shape":{"family":"auth"},"advisory_only":true}\n',
                '{"task_id":"row-no-check","classification":"KEEP","reason":"looks plausible"}\n',
            )
            row = mod.classify_result(final)
        self.assertEqual(row["primary_category"], "malformed")
        self.assertNotIn("candidate_harvest", row["categories"])
        self.assertIn("candidate-without-actionable-local-check", row["provider_schema_notes"])

    def test_build_triage_counts_primary_and_any_match_categories(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_result(
                root / "batch-a",
                "row-1",
                '{"task_id":"row-1","candidate_detector_shape":{"family":"auth"},"local_checks_required":["grep paths"],"advisory_only":true}\n',
                '{"task_id":"row-1","classification":"KEEP","minimum_followup_check":"add fixture coverage"}\n',
            )
            _write_result(
                root / "batch-b",
                "row-2",
                '{"task_id":"row-2","candidate_detector_shape":{"family":"common"},"advisory_only":true}\n',
                '{"task_id":"row-2","classification":"NOT_VULNERABLE","reason":"common pattern"}\n',
            )
            payload = mod.build_triage([root])
        self.assertEqual(payload["result_count"], 2)
        self.assertEqual(payload["primary_summary"]["candidate_harvest"], 1)
        self.assertEqual(payload["primary_summary"]["killed_by_minimax"], 1)
        self.assertEqual(payload["summary"]["needs_fixture"], 1)
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["evidence_class"], "generated_hypothesis")
        self.assertFalse(payload["promotion_authority"])
        self.assertTrue(
            all(row["evidence_class"] == "generated_hypothesis" for row in payload["rows"])
        )
        self.assertTrue(all(row["submit_ready"] is False for row in payload["rows"]))


if __name__ == "__main__":
    unittest.main()
