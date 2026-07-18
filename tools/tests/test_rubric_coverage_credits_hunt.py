#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-rubric-credits-hunt registered via agent-pathspec-register.py -->
"""Guard: rubric-coverage credits ADJUDICATED hunt sidecars as candidates.

The candidate enumeration previously read only exploit_queue + submissions, so a
rubric impact class the LLM hunt rigorously investigated and ruled out (a
source-cited FP-DEFENDED sidecar) was scored UNATTEMPTED. This guards that an
adjudicated hunt sidecar IS enumerated as a candidate, while a raw un-adjudicated
seed (no verdict) is NOT.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "rubric_cov_under_test", str(_TOOLS / "rubric-coverage-workspace-check.py")
)
rc = importlib.util.module_from_spec(spec)
sys.modules["rubric_cov_under_test"] = rc
spec.loader.exec_module(rc)


def _ws_with_sidecars(sidecars: dict) -> Path:
    ws = Path(tempfile.mkdtemp())
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True)
    for name, obj in sidecars.items():
        (d / name).write_text(json.dumps(obj), encoding="utf-8")
    return ws


class TestRubricCreditsHunt(unittest.TestCase):
    def test_adjudicated_sidecar_is_enumerated(self):
        ws = _ws_with_sidecars({
            "fp.json": {
                "verdict": "FP-DEFENDED",
                "hypothesis": "merkle eip-712 offer-ratification bypass consuming an unauthorized offer",
                "analysis": "isAuthorized + merkle proof bind the maker; defended",
            },
        })
        cands = rc._enumerate_hunt_sidecars(ws)
        self.assertEqual(len(cands), 1, "an adjudicated FP-DEFENDED sidecar must be a candidate")
        blob, label, raw = cands[0]
        self.assertIn("offer-ratification", blob)
        self.assertEqual(raw.get("verdict"), "FP-DEFENDED")

    def test_raw_seed_without_verdict_not_counted(self):
        ws = _ws_with_sidecars({
            # finding content but NO verdict/disposition/applies_to_target -> seed, not adjudicated
            "seed.json": {"hypothesis": "maybe a rounding issue, not yet investigated"},
        })
        self.assertEqual(rc._enumerate_hunt_sidecars(ws), [],
                         "a raw un-adjudicated seed must NOT be counted as a candidate")

    def test_enumerate_candidates_includes_hunt_sidecars(self):
        ws = _ws_with_sidecars({
            "a.json": {"verdict": "CONFIRMED", "hypothesis": "auth bypass drains funds"},
        })
        all_c = rc.enumerate_candidates(ws)
        self.assertTrue(any("auth bypass" in blob for blob, _l, _r in all_c),
                        "enumerate_candidates must include adjudicated hunt sidecars")

    def test_dict_form_result_sidecar_enumerated_with_rubric_class(self):
        # r36-rebuttal: lane L37-RUBRIC-DICT-RESULT-FIX
        # The spawn-worker Sonnet residual schema nests applies_to_target +
        # rubric_class inside a DICT result. Such a sidecar must (a) pass the
        # adjudication gate and (b) surface its nested rubric_class +
        # candidate_finding in the blob - else a fully-hunted impact class
        # scores 0 candidates (the beanstalk false-red).
        ws = _ws_with_sidecars({
            "dictres.json": {
                "task_id": "residual_fc_b1_0",
                "status": "ok",
                "function_anchor": {"file": "Foo.sol", "function": "bar", "line": 10},
                "result": {
                    "applies_to_target": "no",
                    "rubric_class": "moves another user's funds without authorization",
                    "candidate_finding": "transfer requires explicit allowance",
                    "defending_lines": "Foo.sol:12 spendAllowance",
                },
            },
        })
        cands = rc._enumerate_hunt_sidecars(ws)
        self.assertEqual(len(cands), 1, "a dict-form result sidecar must be enumerated")
        blob = cands[0][0]
        self.assertIn("moves another user's funds", blob,
                      "nested result.rubric_class must enter the candidate blob")
        self.assertIn("allowance", blob,
                      "nested result.candidate_finding must enter the blob")

    def test_dict_form_result_without_signal_skipped(self):
        # A dict result with NO verdict-bearing signal (no applies_to_target /
        # verdict) is a raw seed and must NOT be enumerated.
        ws = _ws_with_sidecars({
            "seed.json": {"status": "ok", "result": {"note": "not yet investigated"}},
        })
        self.assertEqual(rc._enumerate_hunt_sidecars(ws), [],
                         "a dict-result sidecar with no verdict signal must be skipped")


class TestRubricCreditsResidualVerdicts(unittest.TestCase):
    """Guard: rubric-coverage credits ADJUDICATED residual / unhunted terminal
    verdicts as candidates. A source-cited refuted residual verdict for an impact
    class (e.g. "Theft-of-gas (Medium) impact class WAS attempted ...") IS an
    attempt; before this it sat in residual_hunt_verdicts.json uncredited, so a
    genuinely-attempted row scored 0 candidates (the SSV Theft-of-gas false-red).
    Never-false-pass: only verdict-bearing entries count, and the downstream
    load-bearing-noun match still gates which row each can cover."""

    def _ws_with_residual(self, name: str, verdicts: list) -> Path:
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor"
        d.mkdir(parents=True)
        (d / name).write_text(json.dumps({"verdicts": verdicts}), encoding="utf-8")
        return ws

    def test_refuted_residual_verdict_is_enumerated(self):
        ws = self._ws_with_residual("residual_hunt_verdicts.json", [{
            "lead_id": "0e293a9ca2",
            "function": "removeOperator",
            "verdict": "refuted",
            "reason": "Theft-of-gas (Medium) impact class WAS attempted across the 217 per-fn hunt: no function lets an unprivileged caller force gas costs onto a victim",
        }])
        cands = rc._enumerate_residual_verdicts(ws)
        self.assertEqual(len(cands), 1, "an adjudicated refuted residual verdict must be a candidate")
        blob = cands[0][0]
        self.assertIn("theft-of-gas", blob)

    def test_residual_without_verdict_not_counted(self):
        ws = self._ws_with_residual("residual_hunt_verdicts.json", [
            {"lead_id": "seed", "reason": "maybe look at gas later"},  # no verdict
        ])
        self.assertEqual(rc._enumerate_residual_verdicts(ws), [],
                         "a residual entry with no verdict signal must NOT be counted")

    def test_enumerate_candidates_includes_residual_verdicts(self):
        ws = self._ws_with_residual("unhunted_terminal_verdicts.json", [{
            "lead_id": "CJP-013", "verdict": "refuted",
            "reason": "griefing via 1-wei deposit is the documented OOS known-issue",
        }])
        all_c = rc.enumerate_candidates(ws)
        self.assertTrue(any("griefing" in blob for blob, _l, _r in all_c),
                        "enumerate_candidates must include adjudicated residual verdicts")


if __name__ == "__main__":
    unittest.main(verbosity=2)
