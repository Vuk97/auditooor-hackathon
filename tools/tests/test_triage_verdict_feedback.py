"""Tests for triage-verdict-feedback persistence wiring."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "triage-verdict-feedback.py"


def load_module():
    spec = importlib.util.spec_from_file_location("triage_verdict_feedback", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_module()


class TestTriageVerdictFeedback(unittest.TestCase):
    def _with_output_env(self, tmp: Path):
        old_derived = os.environ.get("AUDITOOOR_DERIVED_DIR")
        old_anti = os.environ.get("AUDITOOOR_ANTI_PATTERNS_V2_DIR")
        os.environ["AUDITOOOR_DERIVED_DIR"] = str(tmp / "derived")
        os.environ["AUDITOOOR_ANTI_PATTERNS_V2_DIR"] = str(tmp / "anti")
        return old_derived, old_anti

    def _restore_output_env(self, old_derived, old_anti) -> None:
        if old_derived is None:
            os.environ.pop("AUDITOOOR_DERIVED_DIR", None)
        else:
            os.environ["AUDITOOOR_DERIVED_DIR"] = old_derived
        if old_anti is None:
            os.environ.pop("AUDITOOOR_ANTI_PATTERNS_V2_DIR", None)
        else:
            os.environ["AUDITOOOR_ANTI_PATTERNS_V2_DIR"] = old_anti

    def test_triage_survivor_merges_into_workspace_exploit_queue(self) -> None:
        with tempfile.TemporaryDirectory(prefix="triage-feedback-") as tmp_raw:
            tmp = Path(tmp_raw)
            old = self._with_output_env(tmp)
            try:
                ws = tmp / "workspace"
                (ws / ".auditooor").mkdir(parents=True)
                triage = tmp / "triage"
                triage.mkdir()
                row = {
                    "decision": "PROMOTE-HIGH",
                    "workspace": str(ws),
                    "task_id": "task-1",
                    "severity": "High",
                    "attack_class": "theft",
                    "finding": "Withdraw path drains victim funds",
                    "reason": "survived triage",
                }
                (triage / "triage_v2_results.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
                rc = MOD.main(["--triage-dir", str(triage), "--json"])
                self.assertEqual(rc, 0)
                queue = json.loads((ws / ".auditooor" / "exploit_queue.json").read_text(encoding="utf-8"))
                rows = queue["queue"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["candidate_id"], "task-1")
                self.assertEqual(rows[0]["quality_gate_status"], "triage-survivor")

                rc2 = MOD.main(["--triage-dir", str(triage), "--json"])
                self.assertEqual(rc2, 0)
                queue2 = json.loads((ws / ".auditooor" / "exploit_queue.json").read_text(encoding="utf-8"))
                self.assertEqual(len(queue2["queue"]), 1)
            finally:
                self._restore_output_env(*old)

    def test_r76_report_writes_antipattern_and_oos_extension(self) -> None:
        with tempfile.TemporaryDirectory(prefix="triage-r76-") as tmp_raw:
            tmp = Path(tmp_raw)
            old = self._with_output_env(tmp)
            try:
                report = tmp / "r76.json"
                report.write_text(
                    json.dumps({
                        "fails": [
                            {
                                "task_id": "mimo-1",
                                "workspace": "hyperbridge",
                                "verdict": "fail-conceptual-file-line",
                                "reason": "conceptual file_line",
                                "source_artifact": "audit/corpus_tags/derived/mimo_harness_hyperbridge/x.json",
                            }
                        ]
                    }),
                    encoding="utf-8",
                )
                rc = MOD.main(["--r76-report", str(report), "--json"])
                self.assertEqual(rc, 0)
                anti_files = list((tmp / "anti").glob("*.md"))
                self.assertEqual(len(anti_files), 1)
                oos = tmp / "derived" / "workspace_oos_extension_hyperbridge.json"
                self.assertTrue(oos.is_file())
                rows = json.loads(oos.read_text(encoding="utf-8"))["rows"]
                self.assertEqual(rows[0]["source"], "kill-r76-hallucination")
            finally:
                self._restore_output_env(*old)


if __name__ == "__main__":
    unittest.main()
