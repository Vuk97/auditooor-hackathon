#!/usr/bin/env python3
"""Regression: program-intake-check validates a workspace has ingested a bounty program's
own rules (program_rules.json + prior_audits/known_issues.jsonl with a per-finding
fix_verified_at_pin 'is-it-live' flag). Strata 2026-07-07: the program's PoC requirements +
per-program eligibility + known-issue fix-status were never captured, so findings violated
them and dedup was ad hoc."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("pic", _HERE.parent / "program-intake-check.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["pic"] = _m
_spec.loader.exec_module(_m)


class TestProgramIntakeCheck(unittest.TestCase):
    def _ws(self, rules=None, known=None):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "prior_audits").mkdir(parents=True)
        if rules is not None:
            (ws / ".auditooor" / "program_rules.json").write_text(json.dumps(rules))
        if known is not None:
            (ws / "prior_audits" / "known_issues.jsonl").write_text(
                "\n".join(json.dumps(r) for r in known))
        return ws

    def test_no_artifacts_fails(self):
        ws = self._ws()
        self.assertEqual(_m.check(ws)["verdict"], "fail-intake-incomplete")

    def test_full_intake_passes(self):
        rules = {"program": "X",
                 "poc_seeding": {"min_assets_per_entity": 10, "floor_constant": "ONE_ASSET"},
                 "invalid_impact_conditions": ["x"],
                 "eligibility": {"disclosed_unpatched_eligible": False,
                                 "audits": ["Cyfrin (2025)"]}}
        known = [{"id": "H-01", "title": "t", "fix_verified_at_pin": True, "dedup_class": "c"}]
        r = _m.check(ws := self._ws(rules, known))
        self.assertEqual(r["verdict"], "pass-intake-complete", r)

    def test_unknown_fix_status_warns(self):
        rules = {"program": "X",
                 "poc_seeding": {"min_assets_per_entity": 10},
                 "eligibility": {"disclosed_unpatched_eligible": True, "audits": ["a"]}}
        known = [{"id": "H-01", "fix_verified_at_pin": "unknown"},
                 {"id": "H-02", "fix_verified_at_pin": True}]
        r = _m.check(self._ws(rules, known))
        self.assertEqual(r["verdict"], "warn-unverified-known-issues")

    def test_audits_in_legacy_block_still_ok(self):
        # audits under legacy `ineligible_if_disclosed` must not false-red prior_audits
        rules = {"program": "X", "poc_seeding": {"min_assets_per_entity": 10},
                 "ineligible_if_disclosed": {"enforced": True, "audits": ["a"]}}
        known = [{"id": "H-01", "fix_verified_at_pin": True}]
        r = _m.check(self._ws(rules, known))
        pa = [i for i in r["items"] if i["artifact"] == "program_rules.prior_audits"][0]
        self.assertEqual(pa["status"], "ok")


if __name__ == "__main__":
    unittest.main()
