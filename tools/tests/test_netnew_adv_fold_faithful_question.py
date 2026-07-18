#!/usr/bin/env python3
"""Regression: NETNEW-ADV advisory rows must fold into per_fn_hacker_questions
with a FAITHFUL question (their own capability/class), NOT the fall-through
`[CRC]` callback-reentrancy question.

Before the fix, every net-new general-logic advisory screen (A1-A5, EL1-EL6,
R1/R3/R5, GEN-D, GEN-4B, ...) had NO branch in the fold's question-synthesis
chain, so its rows fell through to `else: # CRC` and reached the hunt / L37
hacker-questions gate carrying a nonsensical `[CRC] Can an attacker re-enter ?`
question + empty attack_class - a silent BROKEN FLOW (wired feeds-to, garbage
content). This test locks in the faithful NETNEW-ADV branch.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parent.parent / "auto-coverage-closer.py"
_spec = importlib.util.spec_from_file_location("auto_coverage_closer", _MOD)
acc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acc)


class TestNetnewAdvFold(unittest.TestCase):
    def _run_fold(self, sidecar_rel, row, return_ws=False):
        d = tempfile.mkdtemp()
        ws = Path(d)
        (ws / "src").mkdir()
        (ws / "src" / "Foo.sol").write_text("contract Foo {}\n")
        (ws / ".auditooor").mkdir()
        # no inscope_units.jsonl -> lenient exists-check (Foo.sol exists)
        (ws / ".auditooor" / sidecar_rel).write_text(json.dumps(row) + "\n")
        self._summary = acc._fold_lane_hypotheses_into_corpus(ws, "run-test")
        out = ws / acc.PER_FN_HACKER_QUESTIONS_REL
        recs = [json.loads(l) for l in out.read_text().splitlines()
                if l.strip()] if out.exists() else []
        got = [r for r in recs if r.get("source") == "NETNEW-ADV"]
        if return_ws:
            return got, ws
        import shutil
        shutil.rmtree(d, ignore_errors=True)
        return got

    def test_gen4b_row_folds_faithful_not_crc(self):
        row = {
            "schema": "auditooor.division_rounds_against_beneficiary_hypotheses.v1",
            "capability": "GEN_4B", "file": "src/Foo.sol", "line": 42,
            "function": "convertToShares", "lang": "solidity",
            "arm": "divide-before-multiply", "conserved_hint": "shares",
            "severity": "high",
            "why_severity_anchored": "a/b*c amplifies the truncated residual on a "
                                     "conserved assets<->shares split",
            "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
        }
        got = self._run_fold("division_rounds_against_beneficiary_hypotheses.jsonl",
                             row)
        self.assertEqual(len(got), 1, "GEN-4B row should fold exactly once")
        rec = got[0]
        # faithful: the question carries the capability + its own arm, NOT [CRC]
        self.assertIn("GEN_4B", rec["question"])
        self.assertIn("divide-before-multiply", rec["question"])
        self.assertNotIn("[CRC]", rec["question"])
        self.assertNotIn("re-enter", rec["question"])
        # attack_class is derived from the row's own class, never empty
        self.assertTrue(rec["attack_class"])
        self.assertEqual(rec["attack_class"], "divide-before-multiply")
        self.assertEqual(rec["verdict"], "needs-fuzz")
        self.assertEqual(rec["unit_id"], "convertToShares")

    def test_gend_consensus_row_uses_return_sink_class(self):
        # a row with no attack_class/arm but a return_sink hint (GEN-D shape)
        row = {
            "capability": "GEN_D", "file": "src/Foo.sol", "line": 10,
            "function": "EndBlocker", "lang": "go",
            "return_sink": "validator-update", "severity": "high",
            "why_severity_anchored": "map-range append to a consensus return "
                                     "with no dominating sort",
            "verdict": "needs-fuzz",
        }
        got = self._run_fold("consensus_map_order_return_hypotheses.jsonl", row)
        self.assertEqual(len(got), 1)
        rec = got[0]
        self.assertIn("GEN_D", rec["question"])
        self.assertIn("validator-update", rec["question"])
        self.assertNotIn("[CRC]", rec["question"])
        # classified by the specific defect (return_sink), not the tool name
        self.assertEqual(rec["attack_class"], "validator-update")


    def test_fired_advisory_row_becomes_enforced_open_obligation(self):
        # ENFORCEMENT: a folded advisory row must ALSO create an OPEN hacker-
        # question obligation so audit-complete's fail-open-hacker-questions gate
        # fail-closes until it is resolved with a cited verdict - i.e. advisory
        # can no longer mean "silently skipped".
        row = {
            "capability": "GEN_D", "file": "src/Foo.sol", "line": 10,
            "function": "EndBlocker", "lang": "go",
            "return_sink": "validator-update", "severity": "high",
            "why_severity_anchored": "map-range append to a consensus return "
                                     "with no dominating sort",
            "verdict": "needs-fuzz",
        }
        import shutil
        got, ws = self._run_fold(
            "consensus_map_order_return_hypotheses.jsonl", row, return_ws=True)
        try:
            self.assertEqual(len(got), 1)
            # the fold reports it seeded an obligation
            self.assertGreaterEqual(self._summary.get("obligations_seeded", 0), 1)
            # and an OPEN obligation now exists in the enforced file
            obl = ws / ".auditooor" / "hacker_question_obligations.jsonl"
            self.assertTrue(obl.is_file(), "obligations file must be written")
            rows = [json.loads(l) for l in obl.read_text().splitlines()
                    if l.strip()]
            open_rows = [r for r in rows if r.get("state") == "open"]
            self.assertGreaterEqual(len(open_rows), 1)
            self.assertTrue(any(r.get("function_name") == "EndBlocker"
                                for r in open_rows))
        finally:
            shutil.rmtree(str(ws), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
