"""F2 fix (polygon loop tick-4): ADVISORY corpus_mined_finding obligations are resolved
by a non-vacuous corpus-driven-hunt (grounding), NOT per-question source sidecars (their
`file` is the corpus artifact, never a source unit). The DONE gate must:
  - PASS when advisory corpus-mined obligations exist AND the grounding ran;
  - FAIL (stay open) when they exist but the grounding did NOT run (not a free pass);
  - still FAIL on a genuinely BINDING (non-advisory) open obligation (H4 intent).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _ws(obligations, *, grounded):
    ws = Path(tempfile.mkdtemp()).resolve()
    (ws / ".auditooor").mkdir(parents=True)
    with (ws / ".auditooor" / "hacker_question_obligations.jsonl").open("w") as fh:
        for o in obligations:
            fh.write(json.dumps(o) + "\n")
    if grounded:
        (ws / ".auditooor" / "corpus_driven_hunt.json").write_text(json.dumps({
            "hypotheses": [{"invariant_id": "INV-A-1",
                            "in_target_evidence": [{"file": "src/V.sol", "line": 9}]}]
        }))
    return ws


_ADVISORY = {"obligation_id": "a1", "advisory_only": True,
             "source_kind": "corpus_mined_finding", "state": "open",
             "file": "<workspace>/.auditooor/mined_findings_hunter_bridge.json",
             "function_name": "mined_findings_hunter_bridge"}
_BINDING = {"obligation_id": "b1", "advisory_only": False, "state": "open",
            "file": "src/Vault.sol", "function_name": "withdraw"}


class TestAdvisoryCorpusObligations(unittest.TestCase):
    def setUp(self):
        self.acc = _load("acc_adv", "audit-completeness-check.py")
        self.guard = _load("guard_adv", "audit-done-guard.py")

    def test_advisory_resolved_when_grounded(self):
        ws = _ws([_ADVISORY, dict(_ADVISORY, obligation_id="a2")], grounded=True)
        r = self.acc.check_hacker_questions_resolved(ws)
        self.assertTrue(r.ok)
        self.assertEqual(r.detail["resolved_by_grounding"], 2)
        self.assertEqual(r.detail["open"], 0)
        self.assertEqual(self.guard._count_open_obligations(ws)["open"], 0)

    def test_advisory_open_when_not_grounded(self):
        ws = _ws([_ADVISORY], grounded=False)
        import os
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            r = self.acc.check_hacker_questions_resolved(ws)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.assertFalse(r.ok)  # no grounding -> advisory lessons unchecked -> open
        self.assertEqual(self.guard._count_open_obligations(ws)["open"], 1)

    def test_agent_artifact_lesson_resolved_when_grounded(self):
        # agent_artifact_lesson_candidate is the SAME advisory artifact-file class as
        # corpus_mined_finding (file = .auditooor artifact, never a source unit) and
        # must resolve via grounding too (near-intents 2026-06-26: 36 false-open).
        aal = {"obligation_id": "aal1", "advisory_only": True,
               "source_kind": "agent_artifact_lesson_candidate", "state": "open",
               "file": "<workspace>/.auditooor/mined_findings_hunter_bridge.json",
               "function_name": "mined_findings_hunter_bridge"}
        ws = _ws([aal, dict(aal, obligation_id="aal2")], grounded=True)
        r = self.acc.check_hacker_questions_resolved(ws)
        self.assertTrue(r.ok)
        self.assertEqual(r.detail["resolved_by_grounding"], 2)
        self.assertEqual(r.detail["open"], 0)
        # done-guard parallel counter must agree
        self.assertEqual(self.guard._count_open_obligations(ws)["open"], 0)

    def test_agent_artifact_lesson_open_when_not_grounded(self):
        aal = {"obligation_id": "aal1", "advisory_only": True,
               "source_kind": "agent_artifact_lesson_candidate", "state": "open",
               "file": "<workspace>/.auditooor/mined_findings_hunter_bridge.json",
               "function_name": "mined_findings_hunter_bridge"}
        ws = _ws([aal], grounded=False)
        self.assertEqual(self.guard._count_open_obligations(ws)["open"], 1)

    def test_binding_obligation_still_open_even_when_grounded(self):
        # H4 intent: a genuine non-advisory obligation is NOT excused by grounding.
        ws = _ws([_BINDING], grounded=True)
        self.assertEqual(self.guard._count_open_obligations(ws)["open"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
