"""Tests for review_attribution.py - the reverse-evolution defense: 4-way
attribution + cross-workspace admission gate."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "review_attribution.py"
_spec = importlib.util.spec_from_file_location("review_attribution", _TOOL)
RA = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(RA)


class TestClassify(unittest.TestCase):
    def test_gate_families(self):
        self.assertEqual(RA.classify_gate("completeness-matrix"), "task-design")
        self.assertEqual(RA.classify_gate("inscope-disposition"), "context")
        self.assertEqual(RA.classify_gate("hunt-trust"), "reasoning")
        self.assertEqual(RA.classify_gate("invariant-fuzz"), "verification-artifacts")
        self.assertEqual(RA.classify_gate("unknown-gate"), "reasoning")  # default


class TestRecordAdmit(unittest.TestCase):
    def _ledger(self):
        return Path(tempfile.mkdtemp()) / "review_attributions.jsonl"

    def test_record_rejects_bad_class(self):
        with self.assertRaises(ValueError):
            RA.record("ws1", "gate:x", "not-a-class", ledger=self._ledger())

    def test_admit_holds_below_threshold_then_passes(self):
        led = self._ledger()
        # one workspace -> hold (a single-workspace issue is local)
        RA.record("strata", "gate:completeness-matrix", "task-design", ledger=led)
        r1 = RA.admit("gate:completeness-matrix", "task-design", threshold=3, ledger=led)
        self.assertEqual(r1["verdict"], "hold-fix-locally")
        self.assertEqual(r1["distinct_workspaces"], 1)
        # same workspace again does NOT inflate the distinct count
        RA.record("strata", "gate:completeness-matrix", "task-design", ledger=led)
        self.assertEqual(RA.admit("gate:completeness-matrix", "task-design", 3, led)["distinct_workspaces"], 1)
        # three DISTINCT workspaces -> admit the global change
        RA.record("polygon", "gate:completeness-matrix", "task-design", ledger=led)
        RA.record("beanstalk", "gate:completeness-matrix", "task-design", ledger=led)
        r2 = RA.admit("gate:completeness-matrix", "task-design", threshold=3, ledger=led)
        self.assertEqual(r2["verdict"], "pass-admit-global-change")
        self.assertEqual(r2["distinct_workspaces"], 3)

    def test_admit_class_must_match(self):
        led = self._ledger()
        for ws in ("a", "b", "c"):
            RA.record(ws, "gate:hunt-trust", "reasoning", ledger=led)
        # querying a different class for the same subject -> no matches
        self.assertEqual(RA.admit("gate:hunt-trust", "context", 3, led)["distinct_workspaces"], 0)
        self.assertEqual(RA.admit("gate:hunt-trust", "reasoning", 3, led)["verdict"], "pass-admit-global-change")


class TestFromAuditComplete(unittest.TestCase):
    def test_records_failing_gates_only(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "audit_complete_last_result.json").write_text(json.dumps({
            "verdict": "fail-audit-complete",
            "signals": [
                {"signal": "completeness-matrix", "ok": False},
                {"signal": "hunt-trust", "ok": False},
                {"signal": "coverage-map", "ok": True},
            ],
        }))
        led = Path(tempfile.mkdtemp()) / "led.jsonl"
        rep = RA.from_audit_complete(str(ws), ledger=led)
        self.assertEqual(set(rep["fail_gates"]), {"completeness-matrix", "hunt-trust"})
        classes = {r["subject"]: r["attribution_class"] for r in rep["recorded"]}
        self.assertEqual(classes["gate:completeness-matrix"], "task-design")
        self.assertEqual(classes["gate:hunt-trust"], "reasoning")


if __name__ == "__main__":
    unittest.main()


class TestLearningLoopWiring(unittest.TestCase):
    """P3: the admission gate is wired into agent-learning-compiler so a mined
    lesson is global-eligible only after it repeats across >=3 workspaces."""
    def _alc(self, ledger):
        import importlib.util
        p = Path(__file__).resolve().parents[1] / "agent-learning-compiler.py"
        spec = importlib.util.spec_from_file_location("agent_learning_compiler", p)
        alc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(alc)
        RA.LEDGER = ledger
        alc._review_attribution = lambda: RA
        return alc

    def test_lesson_local_until_three_workspaces(self):
        led = Path(tempfile.mkdtemp()) / "led.jsonl"
        alc = self._alc(led)
        seen = []
        for ws in ("/x/strata", "/x/polygon", "/x/beanstalk"):
            rows = [{"primary_for": "reentrancy", "terminal_kind": "hypothesis"}]
            alc._annotate_global_eligibility(rows, Path(ws), record=True)
            seen.append(rows[0]["global_eligible"])
        self.assertEqual(seen, [False, False, True])  # local, local, then global-eligible


class TestMissedFindingFeed(unittest.TestCase):
    """P3 second feed: missed findings (post-mortem) are attributed too."""
    def test_from_missed_findings(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "missed_findings.jsonl").write_text(
            json.dumps({"finding_id": "F-INSOLVENCY-LOSS-PATH", "attribution_class": "verification-artifacts",
                        "note": "harness never fuzzed the loss transition"}) + "\n" +
            json.dumps({"finding_id": "F-XFN-COMBO", "attribution_class": "task-design"}) + "\n")
        led = Path(tempfile.mkdtemp()) / "led.jsonl"
        rep = RA.from_missed_findings(str(ws), ledger=led)
        self.assertEqual(rep["missed_count"], 2)
        classes = {r["subject"]: r["attribution_class"] for r in rep["recorded"]}
        self.assertEqual(classes["miss:F-INSOLVENCY-LOSS-PATH"], "verification-artifacts")
        self.assertEqual(classes["miss:F-XFN-COMBO"], "task-design")

    def test_no_missed_findings_file_noop(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        led = Path(tempfile.mkdtemp()) / "led.jsonl"
        self.assertEqual(RA.from_missed_findings(str(ws), ledger=led)["recorded"], [])
