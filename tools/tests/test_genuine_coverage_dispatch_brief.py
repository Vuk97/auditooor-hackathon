#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-GENUINE-COVERAGE-DISPATCH-BRIEF registered via agent-pathspec-register.py -->
"""Guard: the genuine-coverage dispatch brief selects EVERY non-genuine per-function
harness as a target - not just a whitelisted subset.

Load-bearing regression (SSV loop 2026-06-23): the old inline-Makefile filter
selected only verdict in {vacuous,no-baseline,skipped,error} and so SILENTLY
DROPPED `no-property-discovered` / `no-execution` harnesses (the exact verdict the
auto-generated per-function halmos scaffolds carry) -> non_genuine_targets=[] on
every workspace -> the genuine-coverage orchestrator was a no-op while
live-engines/hollow stayed red. The fix inverts the rule: a row is a target unless
PROVEN genuine.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "gcdb", str(_TOOLS / "genuine-coverage-dispatch-brief.py"))
gcdb = importlib.util.module_from_spec(_spec)
sys.modules["gcdb"] = gcdb
_spec.loader.exec_module(gcdb)


class TestSelectNonGenuineTargets(unittest.TestCase):
    def test_no_property_discovered_is_a_target(self):
        # the exact verdict the old whitelist dropped
        v = [{"function": "registerOperator", "verdict": "no-property-discovered"}]
        self.assertEqual(len(gcdb.select_non_genuine_targets(v)), 1)

    def test_no_execution_is_a_target(self):
        v = [{"function": "withdraw", "verdict": "no-execution"}]
        self.assertEqual(len(gcdb.select_non_genuine_targets(v)), 1)

    def test_classic_vacuous_still_a_target(self):
        v = [{"function": "x", "verdict": "vacuous"},
             {"function": "y", "verdict": "error"},
             {"function": "z", "verdict": "skipped"}]
        self.assertEqual(len(gcdb.select_non_genuine_targets(v)), 3)

    def test_genuine_verdicts_excluded(self):
        v = [{"function": "a", "verdict": "non-vacuous"},
             {"function": "b", "verdict": "killed"},
             {"function": "c", "verdict": "mutation-verified"}]
        self.assertEqual(gcdb.select_non_genuine_targets(v), [])

    def test_mixed_only_non_genuine_selected(self):
        v = [{"function": "a", "verdict": "non-vacuous"},        # genuine -> excluded
             {"function": "b", "verdict": "no-property-discovered"},  # target
             {"function": "c", "verdict": "vacuous"}]            # target
        sel = gcdb.select_non_genuine_targets(v)
        self.assertEqual({t["function"] for t in sel}, {"b", "c"})

    def test_build_brief_end_to_end_populates_targets(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "genuine_coverage_manifest.json").write_text(json.dumps({
            "verdicts": [
                {"function": "initialize", "verdict": "no-property-discovered"},
                {"function": "registerOperator", "verdict": "no-execution"},
                {"function": "deposit", "verdict": "non-vacuous"},  # genuine
            ]
        }))
        brief = gcdb.build_brief(ws, ws / ".auditooor" / "genuine-coverage")
        fns = {t["function"] for t in brief["non_genuine_targets"]}
        self.assertEqual(fns, {"initialize", "registerOperator"})
        # genuine one excluded; worklist input points at the REAL jsonl artifact
        self.assertTrue(brief["inputs"]["per_function_attack_worklist"].endswith(
            "per_function_attack_worklist.jsonl"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
