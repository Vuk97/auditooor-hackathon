"""Tests for executed-refutation-negative-gate.py (LOGIC_ARSENAL_ROADMAP logic #2)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "executed-refutation-negative-gate.py"
_spec = importlib.util.spec_from_file_location("erng", TOOL)
erng = importlib.util.module_from_spec(_spec)
sys.modules["erng"] = erng
_spec.loader.exec_module(erng)


def _ws(tmp, mech=None, hq=None, poc=None):
    ws = Path(tmp)
    a = ws / ".auditooor"
    (a / "agent_mechanism_verdicts").mkdir(parents=True, exist_ok=True)
    (a / "hacker_question_verdicts").mkdir(parents=True, exist_ok=True)
    if mech:
        (a / "agent_mechanism_verdicts" / "m.json").write_text(json.dumps(mech))
    if hq:
        for i, r in enumerate(hq):
            (a / "hacker_question_verdicts" / f"hq_{i}.json").write_text(json.dumps(r))
    if poc:
        for name, rec in poc.items():
            d = ws / "poc_execution" / name
            d.mkdir(parents=True, exist_ok=True)
            (d / "execution_manifest.json").write_text(json.dumps(rec))
    return ws


class TestExecutedRefutationNegativeGate(unittest.TestCase):
    def test_grep_only_kill_on_value_mover_flagged(self):
        rec = {"verdict": "cleared", "impact": "direct-theft-of-funds",
               "mechanism": "fee-on-transfer-double-accounting",
               "source_refs": ["contracts/Withdrawal.sol:195"],
               "local_verification_cmd": "grep -n 'foo' contracts/Withdrawal.sol"}
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, mech=[rec]))
            self.assertEqual(len(res["flagged"]), 1)
            self.assertTrue(res["flagged"][0]["grep_only"])

    def test_missing_cmd_flagged(self):
        rec = {"verdict": "cleared", "impact": "insolvency",
               "mechanism": "accounting-conservation-break",
               "source_refs": ["contracts/Vault.sol:10"]}
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, mech=[rec]))
            self.assertEqual(len(res["flagged"]), 1)

    def test_hacker_question_kill_flagged(self):
        hq = [{"verdict": "KILL", "attack_class": "direct-theft",
               "function_name": "withdraw", "file_line": "payout.go:125",
               "reason": "no unvalidated field"}]
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, hq=hq))
            self.assertEqual(len(res["flagged"]), 1)
            self.assertEqual(res["flagged"][0]["store"], "hacker_question")

    def test_non_value_mover_not_considered(self):
        rec = {"verdict": "cleared", "impact": "informational-typo",
               "mechanism": "event-emission-ordering",
               "source_refs": ["contracts/Log.sol:3"],
               "local_verification_cmd": "grep foo Log.sol"}
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, mech=[rec]))
            self.assertEqual(res["considered_value_mover_negatives"], 0)
            self.assertEqual(len(res["flagged"]), 0)

    def test_positive_verdict_not_considered(self):
        rec = {"verdict": "finding", "impact": "direct-theft-of-funds",
               "mechanism": "drain", "source_refs": ["contracts/V.sol:1"]}
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, mech=[rec]))
            self.assertEqual(res["considered_value_mover_negatives"], 0)

    def test_executed_refutation_with_guard_neutralization_is_honest(self):
        rec = {"verdict": "cleared", "impact": "direct-theft-of-funds",
               "mechanism": "principal-theft",
               "source_refs": ["keeper/interest.go:95"],
               "local_verification_cmd": "GOTOOLCHAIN=go1.24.1 go test ./keeper/ -run TestX"}
        poc = {"nuva-interest-theft": {
            "candidate_id": "nuva-interest-theft-principal",
            "poc_dir": "src/vault",
            "commands_attempted": [{"status": "pass", "exit_code": 0}],
            "notes": "guard-neutralization mutant: removed SafeSub require, hypothesis reachable"}}
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, mech=[rec], poc=poc))
            self.assertEqual(len(res["honest"]), 1)
            self.assertEqual(len(res["flagged"]), 0)

    def test_executed_but_no_guard_neutralization_flagged(self):
        rec = {"verdict": "cleared", "impact": "direct-theft-of-funds",
               "mechanism": "principal-theft",
               "source_refs": ["keeper/interest.go:95"],
               "local_verification_cmd": "go test ./keeper/"}
        poc = {"nuva-interest-theft": {
            "candidate_id": "nuva-interest-theft-principal",
            "commands_attempted": [{"status": "pass", "exit_code": 0}],
            "notes": "ran the PoC, it passed"}}  # no guard-neutralization marker
        with tempfile.TemporaryDirectory() as tmp:
            res = erng.scan(_ws(tmp, mech=[rec], poc=poc))
            self.assertEqual(len(res["flagged"]), 1)
            self.assertTrue(res["flagged"][0]["has_executed_refutation"])
            self.assertFalse(res["flagged"][0]["has_guard_neutralization"])

    def test_is_grep_only_helper(self):
        self.assertTrue(erng.is_grep_only(None))
        self.assertTrue(erng.is_grep_only(""))
        self.assertTrue(erng.is_grep_only("grep -rn foo a.sol; grep bar b.sol"))
        self.assertTrue(erng.is_grep_only("cat a.go | grep x | wc -l"))
        self.assertFalse(erng.is_grep_only("go test ./keeper/"))
        self.assertFalse(erng.is_grep_only("grep foo; forge test --match X"))

    def test_strict_exit_code(self):
        rec = {"verdict": "cleared", "impact": "direct-theft-of-funds",
               "mechanism": "drain", "source_refs": ["V.sol:1"],
               "local_verification_cmd": "grep foo V.sol"}
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, mech=[rec])
            self.assertEqual(erng.main([str(ws), "--json"]), 0)      # advisory default
            self.assertEqual(erng.main([str(ws), "--strict", "--json"]), 1)


if __name__ == "__main__":
    unittest.main()
