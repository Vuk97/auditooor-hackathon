#!/usr/bin/env python3
"""Regression: corpus-driven-hunt must be an ENFORCED required runbook step.

The bug (axelar 2026-07-12): corpus-driven-hunt was only a soft `|| WARN`
sub-stage of the audit-pipeline-full driver and NOT a first-class required step
in readme_runbook_steps.json, so the per-tick audit-next-step loop never named
it and it was silently skipped - the exploit_queue was never grounded (on
axelar it produced +7116 proof obligations only once finally run by hand).
step-4c makes it un-skippable and correctly ordered before step-5.
"""
import json
import unittest
from pathlib import Path

_RUNBOOK = Path(__file__).resolve().parent.parent / "readme_runbook_steps.json"


def _steps():
    d = json.loads(_RUNBOOK.read_text())
    return d if isinstance(d, list) else d.get("steps", [])


class TestStep4cCorpusHuntEnforced(unittest.TestCase):
    def test_step4c_present_required_and_ordered(self):
        # B1 (2026-07-14) single-source-order re-band: step-4c corpus-driven-hunt was
        # moved UP into the reasoning band so it GROUNDS the exploit_queue + emits the
        # per-fn hacker-Q obligations BEFORE the step-3 hunt consumes them (the deeper
        # intent of this step, stronger than the old "before step-5" position). It is
        # therefore now BEFORE step-3 (and step-4b, which authors economic invariants in
        # the drive band after the hunt).
        steps = _steps()
        ids = [s.get("step_id") for s in steps]
        self.assertIn("step-4c", ids, "step-4c must exist in the runbook")
        i3, i4c, i5 = ids.index("step-3"), ids.index("step-4c"), ids.index("step-5")
        self.assertLess(i4c, i3, "step-4c must come BEFORE step-3 (grounds the queue the hunt consumes)")
        self.assertLess(i4c, i5, "step-4c must come BEFORE step-5 (grounds the queue first)")

    def test_step4c_is_required(self):
        s4c = next(s for s in _steps() if s.get("step_id") == "step-4c")
        self.assertTrue(s4c.get("required") is True, "step-4c must be required (un-skippable)")

    def test_step4c_verifies_corpus_hunt_artifact(self):
        s4c = next(s for s in _steps() if s.get("step_id") == "step-4c")
        checks = (s4c.get("how_to_verify_done", {}) or {}).get("artifact_checks", []) or []
        paths = " ".join(str(c.get("path", "")) for c in checks)
        self.assertIn("corpus_driven_hunt.json", paths,
                      "step-4c verify must key on the corpus_driven_hunt.json artifact")

    def test_step4c_names_the_remediation_command(self):
        s4c = next(s for s in _steps() if s.get("step_id") == "step-4c")
        self.assertIn("corpus-driven-hunt", s4c.get("what_must_be_done", ""))
        self.assertIn("EMIT_PROOF_QUEUE=1", s4c.get("what_must_be_done", ""))

    def test_step4c_requires_a_current_validated_awareness_ledger(self):
        manifest = json.loads(_RUNBOOK.read_text())
        s4c = next(s for s in manifest["steps"] if s.get("step_id") == "step-4c")
        self.assertIn("artifact.step-0d-awareness", s4c.get("consumes", []))
        contracts = {row["id"]: row for row in manifest["artifact_contracts"]}
        ledger = contracts["artifact.step-0d-awareness"]
        self.assertIn("step-4c", ledger["consumer_step_ids"])
        self.assertEqual(ledger["validators"], ["awareness_ledger"])


if __name__ == "__main__":
    unittest.main()
