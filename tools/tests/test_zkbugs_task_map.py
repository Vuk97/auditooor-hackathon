from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-task-map.py"


def _import_tool():
    spec = importlib.util.spec_from_file_location("zkbugs_task_map_test_subject", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _record(**overrides):
    base = {
        "title": "Missing range checks in BigMod",
        "bug_id": "demo/range",
        "dsl": "Circom",
        "vulnerability": "Under-Constrained",
        "impact": "Soundness",
        "root_cause": "Missing Range Check",
        "project": "demo/project",
        "commit": "abc123",
        "fix_commit": "def456",
        "location_path": "circuits/bigmod.circom",
        "location_function": "BigMod",
        "location_line": "12",
        "report_files": ["reports/documents/demo.pdf"],
        "report_text_files": ["reports/documents/demo.txt"],
        "source_links": ["https://example.invalid/report"],
        "priority_score": 65,
        "priority_reasons": ["has-fix-commit", "has-local-report-text"],
        "commands": {},
    }
    base.update(overrides)
    return base


class ZkbugsTaskMapTests(unittest.TestCase):
    def test_routes_circom_range_check_to_detector_fixture_and_prompt_ready(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            prompt_dir = td_path / "provider_queue" / "prompts"
            prompt_dir.mkdir(parents=True)
            kimi = prompt_dir / "001_circom__under-constrained__missing-range-checks-in-bigmod.kimi.md"
            minimax = prompt_dir / "001_circom__under-constrained__missing-range-checks-in-bigmod.minimax.template.md"
            kimi.write_text("kimi", encoding="utf-8")
            minimax.write_text("minimax", encoding="utf-8")
            index = {"records": [_record()], "source": "local"}
            queue = {
                "rows": [
                    {
                        "index": 1,
                        "brief": str(td_path / "briefs" / "circom__under-constrained__missing-range-checks-in-bigmod.md"),
                        "kimi_prompt": str(kimi),
                        "minimax_prompt_template": str(minimax),
                    }
                ]
            }

            payload = mod.build_task_map(index, queue)

        self.assertEqual(payload["summary"]["total_tasks"], 1)
        self.assertEqual(payload["summary"]["ready_for_provider_prompts"], 1)
        task = payload["tasks"][0]
        self.assertEqual(task["artifact_type"], "circom_circuit")
        self.assertEqual(task["proof_feasibility"], "source_diff_replay_feasible")
        self.assertIn("circom_text_detector", task["detector_invariant_suitability"])
        self.assertIn("replay_or_smoke_fixture", task["detector_invariant_suitability"])
        self.assertEqual(task["provider_prompt_readiness"]["status"], "prompt_ready")

    def test_main_writes_json_and_markdown_without_github_issue_corpus(self) -> None:
        mod = _import_tool()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            index = td_path / "zkbugs_index.json"
            queue = td_path / "queue.json"
            out_json = td_path / "task_map.json"
            out_md = td_path / "task_map.md"
            queue_dir = td_path / "task_queues"
            index.write_text(
                json.dumps({"records": [_record(title="Verifier VK root missing", dsl="Plonky3")]}),
                encoding="utf-8",
            )
            queue.write_text(json.dumps({"rows": []}), encoding="utf-8")

            rc = mod.main(
                [
                    "--index",
                    str(index),
                    "--provider-queue",
                    str(queue),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--queue-dir",
                    str(queue_dir),
                ]
            )

            payload = json.loads(out_json.read_text(encoding="utf-8"))
            md = out_md.read_text(encoding="utf-8")
            completeness = json.loads((queue_dir / "zkbugs_route_completeness.json").read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertIn("GitHub issues are not used", payload["corpus_boundary"])
        self.assertIn("zkBugs Task Map", md)
        self.assertEqual(payload["summary"]["by_provider_prompt_readiness"]["missing_prompt_artifacts"], 1)
        self.assertEqual(completeness["status"], "blocked")
        self.assertIn("not_all_records_have_ready_provider_prompts", completeness["blockers"])


if __name__ == "__main__":
    unittest.main()
