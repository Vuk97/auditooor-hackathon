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
QUEUE = ROOT / "tools" / "callgraph-limitation-queue.py"


def _load_queue_module():
    spec = importlib.util.spec_from_file_location("callgraph_limitation_queue", QUEUE)
    assert spec and spec.loader, f"could not load {QUEUE}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_detector(folder: Path, name: str, body: str) -> None:
    (folder / name).write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")


class CallgraphLimitationQueueTest(unittest.TestCase):
    def test_synthetic_blockers_fan_out_into_terminal_advisory_tasks(self) -> None:
        mod = _load_queue_module()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            _write_detector(
                folder,
                "cross_contract_no_graph.py",
                '''
                """cross-contract detector generated for a sibling deployment claim."""

                class CrossContractNoGraph:
                    ARGUMENT = "cross-contract-no-graph"
                    HELP = "Cross-contract reentrancy across deployments."
                    WIKI_DESCRIPTION = "Sibling contract reads this value during callback."

                    def _detect(self):
                        return []
                ''',
            )
            _write_detector(
                folder,
                "proxy_no_graph.py",
                '''
                """proxy detector."""

                class ProxyNoGraph:
                    ARGUMENT = "proxy-no-graph"
                    HELP = "Proxy upgrade points to an unsafe implementation."
                    WIKI_DESCRIPTION = "Proxy implementation can be replaced."

                    def _detect(self):
                        return []
                ''',
            )

            payload = mod.build_queue(folders=[folder], limit=300)

        self.assertEqual(payload["schema"], "auditooor.callgraph_limitation_queue.v1")
        self.assertEqual(payload["blocker_count"], 2)
        self.assertEqual(payload["task_count"], 10)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(
            set(payload["action_lane_counts"]),
            {
                "callgraph_required",
                "semantic_graph_required",
                "fixture_pair_required",
                "claim_scope_required",
                "terminal_decision_required",
            },
        )
        self.assertTrue(all(task["severity"] == "none" for task in payload["tasks"]))
        self.assertTrue(all(task["impact_contract_required"] for task in payload["tasks"]))
        self.assertTrue(any(
            task["task_kind"] == "callgraph_required_detector_rewrite"
            and "preferred APIs:" in " ".join(task["required_artifacts"])
            for task in payload["tasks"]
        ))
        self.assertTrue(any(
            task["task_kind"] == "terminal_non_detectorizable_decision"
            and "terminal_non_detectorizable_source_review_only" in task["terminal_decision_options"]
            for task in payload["tasks"]
        ))

    def test_real_corpus_currently_generates_target_sized_queue(self) -> None:
        mod = _load_queue_module()
        payload = mod.build_queue(limit=300)
        # Worker CZ ownership starts from the CV baseline: 30 detector-lint rows.
        self.assertEqual(payload["blocker_count"], 30)
        self.assertGreaterEqual(payload["task_count"], 150)
        self.assertLessEqual(payload["task_count"], 300)
        self.assertEqual(payload["action_lane_counts"]["callgraph_required"], 30)
        self.assertEqual(payload["action_lane_counts"]["semantic_graph_required"], 30)
        self.assertEqual(payload["action_lane_counts"]["fixture_pair_required"], 30)
        self.assertEqual(payload["action_lane_counts"]["claim_scope_required"], 30)
        self.assertEqual(payload["action_lane_counts"]["terminal_decision_required"], 30)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "detectors"
            folder.mkdir()
            _write_detector(
                folder,
                "factory_no_graph.py",
                '''
                """factory detector."""

                class FactoryNoGraph:
                    ARGUMENT = "factory-no-graph"
                    HELP = "Factory deploys child contracts across deployments."
                    WIKI_DESCRIPTION = "Factory deploys a child with mismatched config."

                    def _detect(self):
                        return []
                ''',
            )
            out_json = Path(tmp) / "queue.json"
            out_md = Path(tmp) / "queue.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(QUEUE),
                    "--detector-folder",
                    str(folder),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["blocker_count"], 1)
            self.assertEqual(payload["task_count"], 5)
            self.assertIn("Callgraph Limitation Queue", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
