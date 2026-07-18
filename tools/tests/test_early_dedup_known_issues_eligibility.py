#!/usr/bin/env python3
"""Regression: early-prior-audit-dedup-gate reads the CURATED known_issues.jsonl
rows + the program's per-program disclosed-unpatched eligibility, not just the
free-text audit prose.

Strata 2026-07-07: known_issues.jsonl carried per-finding dedup_class +
fix_verified_at_pin ("is it still live"), and program_rules.json declared
disclosed_unpatched_eligible=false (ANY disclosed vuln, fixed OR live, is
ineligible). The early gate ignored both, so a candidate landing in a disclosed
class only got caught at pre-submit R47/R53 - after PoC spend. This wires the
structured pass so:
  - disclosed_unpatched_eligible=false -> any disclosed-class match KILLS
  - =true + fix present   -> KILLS (fixed dupe)
  - =true + fix ABSENT    -> LIVE-DISCLOSED-ELIGIBLE (fileable reverted-fix lead, NOT killed)
  - =true + fix UNKNOWN    -> NEEDS-EXTENSION-DISTINCT (verify live-vs-fixed first)
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "edg", _HERE.parent / "early-prior-audit-dedup-gate.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["edg"] = _m
_spec.loader.exec_module(_m)


class TestEarlyDedupKnownIssues(unittest.TestCase):
    def _ws(self, elig_block, known):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "prior_audits").mkdir(parents=True)
        (ws / ".auditooor" / "program_rules.json").write_text(
            json.dumps({"program": "T", **elig_block}))
        (ws / "prior_audits" / "known_issues.jsonl").write_text(
            "\n".join(json.dumps(r) for r in known))
        return ws

    _ROW = {"id": "H-1/H-01", "title": "Withdraw griefing DoS",
            "file": "UnstakeCooldown.sol:46-105",
            "dedup_class": "cooldown-slot-exhaustion-griefing"}

    def test_disclosed_unpatched_ineligible_kills_regardless_of_fix(self):
        # Strata rule: disclosed_unpatched_eligible=false -> even a LIVE (unfixed)
        # disclosed class match is a hard KILL.
        ws = self._ws({"eligibility": {"disclosed_unpatched_eligible": False}},
                      [{**self._ROW, "fix_verified_at_pin": False}])
        r = _m.run_gate(ws, ["cooldown", "slot", "exhaustion"])
        self.assertEqual(r["verdict"], "KILLED", r)
        self.assertEqual(r["structured_dedup_verdict"], "KILLED")
        self.assertTrue(any(m["id"] == "H-1/H-01" for m in r["known_issue_matches"]))

    def test_eligible_program_fixed_issue_kills(self):
        ws = self._ws({"eligibility": {"disclosed_unpatched_eligible": True}},
                      [{**self._ROW, "fix_verified_at_pin": True}])
        r = _m.run_gate(ws, ["cooldown", "slot", "exhaustion"])
        self.assertEqual(r["verdict"], "KILLED", r)

    def test_eligible_program_live_issue_is_fileable_not_killed(self):
        # disclosed-but-LIVE on a program that allows disclosed-unpatched = lead.
        ws = self._ws({"eligibility": {"disclosed_unpatched_eligible": True}},
                      [{**self._ROW, "fix_verified_at_pin": False}])
        r = _m.run_gate(ws, ["cooldown", "slot", "exhaustion"])
        self.assertNotEqual(r["verdict"], "KILLED", r)
        self.assertEqual(r["structured_dedup_verdict"], "LIVE-DISCLOSED-ELIGIBLE")
        self.assertTrue(any("LIVE DISCLOSED LEAD" in w for w in r["warnings"]))

    def test_eligible_program_unknown_status_needs_verify(self):
        ws = self._ws({"eligibility": {"disclosed_unpatched_eligible": True}},
                      [{**self._ROW, "fix_verified_at_pin": "unknown"}])
        r = _m.run_gate(ws, ["cooldown", "slot", "exhaustion"])
        self.assertEqual(r["verdict"], "NEEDS-EXTENSION-DISTINCT", r)
        self.assertEqual(r["structured_dedup_verdict"], "NEEDS-FIX-STATUS-VERIFY")

    def test_no_match_passes(self):
        ws = self._ws({"eligibility": {"disclosed_unpatched_eligible": False}},
                      [{**self._ROW, "fix_verified_at_pin": False}])
        r = _m.run_gate(ws, ["reentrancy", "oracle", "manipulation"])
        self.assertEqual(r["known_issue_matches"], [])
        self.assertNotEqual(r["verdict"], "KILLED")

    def test_generic_token_alone_does_not_match(self):
        # dedup_class "maxwithdraw-dos" -> "withdraw" is generic and filtered;
        # only "maxwithdraw"/"dos" anchor. A candidate keyworded solely "withdraw"
        # must NOT false-KILL.
        ws = self._ws({"eligibility": {"disclosed_unpatched_eligible": False}},
                      [{"id": "M-03", "file": "Accounting.sol:124-131",
                        "dedup_class": "maxwithdraw-dos", "fix_verified_at_pin": True}])
        r = _m.run_gate(ws, ["withdraw"])
        self.assertEqual(r["known_issue_matches"], [], r)

    def test_legacy_ineligible_if_disclosed_block_enforced(self):
        # program that used the legacy ineligible_if_disclosed.enforced=true block
        ws = self._ws({"ineligible_if_disclosed": {"enforced": True, "audits": ["a"]}},
                      [{**self._ROW, "fix_verified_at_pin": False}])
        r = _m.run_gate(ws, ["cooldown", "slot", "exhaustion"])
        self.assertEqual(r["verdict"], "KILLED", r)


if __name__ == "__main__":
    unittest.main()
