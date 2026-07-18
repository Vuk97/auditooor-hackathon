from __future__ import annotations

import sys
import unittest
from pathlib import Path

from tools.tests import test_pipeline_executor as pipeline_tests


class PipelineDirectoryInputToctouTests(unittest.TestCase):
    setUp = pipeline_tests.PipelineExecutorTests.setUp
    workspace = pipeline_tests.PipelineExecutorTests.workspace
    write_manifest = pipeline_tests.PipelineExecutorTests.write_manifest
    state = pipeline_tests.PipelineExecutorTests.state

    def test_directory_input_mutation_during_consumer_rejects_credit(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            artifact_dir = root / "producer-artifact"
            downstream = root / "downstream.json"
            producer = (
                "from pathlib import Path; "
                f"artifact=Path({str(artifact_dir)!r}); "
                "artifact.mkdir(parents=True, exist_ok=True); "
                "(artifact / 'payload.json').write_text('{}', encoding='utf-8')"
            )
            consumer = (
                "from pathlib import Path; "
                f"artifact=Path({str(artifact_dir)!r}); "
                "(artifact / 'payload.json').write_text('changed=true', encoding='utf-8'); "
                f"Path({str(downstream)!r}).write_text('[]', encoding='utf-8')"
            )
            graph = pipeline_tests.manifest(
                [
                    pipeline_tests.step(0, produces=["directory"], target=[sys.executable, "-c", producer]),
                    pipeline_tests.step(1, produces=["downstream"], consumes=["directory"], target=[sys.executable, "-c", consumer]),
                ],
                [
                    {"id": "directory", "path": "producer-artifact", "kind": "directory", "validators": ["directory_exists"]},
                    {"id": "downstream", "path": "downstream.json", "kind": "file", "validators": ["json"]},
                ],
            )
            path = self.write_manifest(root, graph)
            self.assertTrue(pipeline_tests.executor.run_step(manifest_path=path, workspace=root, step_id="step-0")["ok"])
            result = pipeline_tests.executor.run_step(manifest_path=path, workspace=root, step_id="step-1")
            self.assertFalse(result["ok"])
            self.assertIn("input_artifact_stale_on_disk:directory", result["diagnostics"])
            self.assertTrue((artifact_dir / "payload.json").is_file())
            self.assertTrue(downstream.is_file())
            state = self.state(root)
            self.assertEqual(state["steps"]["step-1"]["state"], "failed")
            self.assertIsNone(state["steps"]["step-1"]["current_receipt_id"])


if __name__ == "__main__":
    unittest.main()
