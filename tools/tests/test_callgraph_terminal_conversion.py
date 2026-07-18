from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "callgraph-terminal-conversion.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("callgraph_terminal_conversion", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CallgraphTerminalConversionTest(unittest.TestCase):
    def test_smoked_fixture_row_converts_without_promotion(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            detector = base / "detectors" / "wave17" / "factory.py"
            detector.parent.mkdir(parents=True)
            detector.write_text("# detector\n", encoding="utf-8")
            dsl = base / "reference" / "patterns.dsl" / "factory-smoke.yaml"
            dsl.parent.mkdir(parents=True)
            dsl.write_text("id: factory-smoke\n", encoding="utf-8")
            smoke_dir = base / "logs"
            smoke_dir.mkdir()
            (smoke_dir / "factory_smoke_vulnerable_factory-smoke.log").write_text("[done] total hits: 1\n", encoding="utf-8")
            (smoke_dir / "factory_smoke_clean_factory-smoke.log").write_text("[done] total hits: 0\n", encoding="utf-8")
            row = {
                "task_id": "CGL-001-FIXTURE",
                "blocker_id": "CGL-BLOCKER-001",
                "detector_argument": "factory-smoke",
                "detector_path": str(detector.relative_to(ROOT)) if detector.is_relative_to(ROOT) else str(detector),
                "execution_status": "terminal_blocker_fixture_pair_present_smoke_blocked",
                "action_lane": "fixture_pair_required",
                "evidence": [],
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
            }
            blocker = {
                "blocker_id": "CGL-BLOCKER-001",
                "claim_labels": ["factory.*deploy phrase"],
                "candidate_family": "factory_deployment_callgraph",
                "dsl_source_path": str(dsl.relative_to(ROOT)) if dsl.is_relative_to(ROOT) else str(dsl),
            }
            payload = mod.build_conversion(
                execution_path=_write_json(base / "execution.json", {"task_results": [row]}),
                queue_path=_write_json(base / "queue.json", {"blockers": [blocker]}),
                smoke_log_dir=smoke_dir,
            )

        converted = payload["rows"][0]
        self.assertEqual(converted["conversion_status"], "converted_detector_fixture_smoked")
        self.assertEqual(converted["terminal_decision"], "fixture_pair_landed_and_smoked")
        self.assertEqual(converted["evidence_class"], "generated_hypothesis")
        self.assertFalse(converted["promotion_allowed"])
        self.assertEqual(converted["submission_posture"], "NOT_SUBMIT_READY")
        self.assertTrue(converted["smoke_evidence"]["passed"])
        evidence = converted["durable_fixture_evidence"]
        self.assertEqual(evidence["schema"], "auditooor.callgraph_fixture_smoke_evidence.v1")
        self.assertEqual(evidence["fixture_evidence_status"], "terminal_clean_positive_fixture_smoke")
        self.assertEqual(evidence["evidence_class"], "scaffolded_unverified")
        self.assertEqual(evidence["callgraph_claim"], "not_proved")
        self.assertFalse(evidence["callgraph_overclaim_allowed"])

    def test_real_execution_converts_target_sized_terminal_batch(self) -> None:
        mod = _load_module()
        payload = mod.build_conversion(
            execution_path=ROOT / ".auditooor" / "callgraph_limitation_execution_de.json",
            queue_path=ROOT / ".auditooor" / "callgraph_limitation_queue.json",
            smoke_log_dir=ROOT / ".auditooor" / "command_logs" / "callgraph_dj",
        )
        self.assertGreaterEqual(payload["conversion_count"], 150)
        self.assertLessEqual(payload["conversion_count"], 300)
        self.assertEqual(payload["conversion_status_counts"]["enriched_terminal_blocker"], 114)
        self.assertEqual(payload["conversion_status_counts"]["converted_semantic_source_shape_evidence"], 3)
        self.assertEqual(payload["conversion_status_counts"]["converted_detector_fixture_smoked"], 3)
        self.assertEqual(payload["durable_fixture_evidence_count"], 3)
        self.assertTrue(all(not row["callgraph_overclaim_allowed"] for row in payload["durable_fixture_evidence_rows"]))
        self.assertTrue(all(row["evidence_class"] == "generated_hypothesis" for row in payload["rows"]))
        self.assertTrue(all(row["evidence_class"] == "scaffolded_unverified" for row in payload["durable_fixture_evidence_rows"]))
        self.assertFalse(payload["promotion_allowed"])

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            smoke_dir = base / "logs"
            smoke_dir.mkdir()
            execution = _write_json(
                base / "execution.json",
                {
                    "task_results": [
                        {
                            "task_id": f"CGL-{idx:03d}-CALLGRAPH",
                            "blocker_id": f"CGL-BLOCKER-{idx:03d}",
                            "detector_argument": f"detector-{idx}",
                            "detector_path": "detectors/wave17/example.py",
                            "execution_status": "terminal_blocker",
                            "action_lane": "callgraph_required",
                            "promotion_allowed": False,
                            "submission_posture": "NOT_SUBMIT_READY",
                        }
                        for idx in range(1, 151)
                    ]
                },
            )
            queue = _write_json(base / "queue.json", {"blockers": []})
            out_json = base / "conversion.json"
            out_md = base / "conversion.md"
            evidence_json = base / "fixture-evidence.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--execution",
                    str(execution),
                    "--queue",
                    str(queue),
                    "--smoke-log-dir",
                    str(smoke_dir),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--out-fixture-evidence-json",
                    str(evidence_json),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["conversion_count"], 150)
            self.assertIn("Callgraph Terminal Conversion", out_md.read_text(encoding="utf-8"))
            evidence_payload = json.loads(evidence_json.read_text(encoding="utf-8"))
            self.assertEqual(evidence_payload["schema"], "auditooor.callgraph_fixture_smoke_evidence.v1")
            self.assertEqual(evidence_payload["evidence_class"], "scaffolded_unverified")
            self.assertEqual(evidence_payload["evidence_count"], 0)
            self.assertFalse(evidence_payload["callgraph_overclaim_allowed"])


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main()
