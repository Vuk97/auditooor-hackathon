#!/usr/bin/env python3
"""Regression: the unhunted-followthrough gate excludes agent scratch worklists
(hunt_prompts/) and disposition-note artifacts (*refutation*/*_dispositions*) from
surface-collection, so they are never mis-read as abandoned surfaces - while still
scanning the real exploit_queue.json."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "unhunted-surface-followthrough-gate.py"
_spec = importlib.util.spec_from_file_location("uf_excl_test", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestArtifactExclusion(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor"
        (d / "hunt_prompts").mkdir(parents=True)
        (d / "exploit_queue.json").write_text('{"queue":[]}')
        (d / "hunt_prompts" / "depth_adjud_batch.jsonl").write_text(
            '{"id":"CJP-1","title":"x","state":"ready_for_poc_planning"}\n')
        (d / "unhunted_rubric_class_refutation.md").write_text(
            "State: ready_for_poc_planning\nsome surface-shaped text")
        (d / "unhunted_terminal_verdicts.json").write_text('{"verdicts":[]}')
        return ws

    def test_scratch_and_disposition_artifacts_excluded(self):
        ws = self._ws()
        json_paths, text_paths = _m._candidate_artifacts(ws)
        names = {p.name for p in json_paths + text_paths}
        self.assertIn("exploit_queue.json", names)                 # real queue scanned
        self.assertNotIn("depth_adjud_batch.jsonl", names)         # hunt_prompts/ scratch skipped
        self.assertNotIn("unhunted_rubric_class_refutation.md", names)  # refutation note skipped
        # verify none of the scanned paths live under hunt_prompts/
        self.assertFalse(any("hunt_prompts" in p.parts for p in json_paths + text_paths))


if __name__ == "__main__":
    unittest.main()
