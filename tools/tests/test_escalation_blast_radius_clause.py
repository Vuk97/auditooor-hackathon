"""Escalation planner: crash/halt/liveness escalation lanes carry a mandatory
PROCESS-COLOCATION / BLAST-RADIUS clause (SEI evmrpc filter-DoS 2026-07-05).

Root lesson: an RPC-node-crash was bounded to Medium on the deployment ASSUMPTION that
'validators do not expose the endpoint', without first checking the CODE FACT that the
RPC server runs in the SAME OS process as the consensus engine (app.go NewEVM*Server) - a
co-located crash kills consensus too, and the only honest bound on the higher tier is then
the rubric's OWN qualifier, cited, not a bare topology guess. The planner now forces the
verifier to establish process blast-radius before accepting a deployment-assumption
proof-of-impossibility, for any crash/halt/liveness/chain-split escalation target.
"""
import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "ewp", str(Path(__file__).resolve().parents[1] / "escalation-workflow-planner.py")
)
ewp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ewp)


def _cand(ic, row, tier="high"):
    return {"impact_class": ic, "severity_row": row, "tier": tier}


class BlastRadiusClauseTest(unittest.TestCase):
    def test_fires_for_validator_crash(self):
        self.assertTrue(ewp._is_crash_escalation(_cand(
            "validator_crash",
            "Crash or halt of >= 1/3 of validators (assuming no direct network access)")))

    def test_fires_for_rpc_crash_high(self):
        self.assertTrue(ewp._is_crash_escalation(_cand(
            "rpc_crash_high",
            "Crash of RPC nodes running default configuration without assuming direct network access")))

    def test_fires_for_chain_split_and_liveness(self):
        self.assertTrue(ewp._is_crash_escalation(_cand(
            "chain-split-fork", "Unintended permanent chain split requiring hard fork")))
        self.assertTrue(ewp._is_crash_escalation(_cand(
            None, "resulting in loss of network liveness")))

    def test_fires_by_row_keyword_even_if_class_unmapped(self):
        # a row that mentions "halt"/"validator" triggers even without a mapped class
        self.assertTrue(ewp._is_crash_escalation(_cand(
            None, "Block production delay exceeding 2.5 seconds")))

    def test_does_NOT_fire_for_fund_tiers(self):
        self.assertFalse(ewp._is_crash_escalation(_cand(
            "bc-direct-loss-of-funds", "Direct loss of funds of USD $5,000 or more")))
        self.assertFalse(ewp._is_crash_escalation(_cand(
            "fund_freeze", "Permanent freezing of funds of USD $5,000 or more")))

    def test_clause_text_demands_colocation_code_fact_and_rubric_qualifier(self):
        clause = ewp._blast_radius_clause(_cand(
            "validator_crash",
            "Crash or halt of >= 1/3 of validators (assuming no direct network access)"))
        self.assertIn("PROCESS-COLOCATION / BLAST-RADIUS", clause)
        self.assertIn("CODE FACT", clause)
        self.assertIn("rubric", clause.lower())
        # bare deployment assumption is explicitly rejected
        self.assertIn("REJECTED", clause)

    def test_brief_embeds_clause_for_crash_target_not_fund_target(self):
        crash_brief = ewp._lane_brief(
            1, _cand("validator_crash", "Crash or halt of >= 1/3 of validators"),
            {}, "finding", "/ws")
        fund_brief = ewp._lane_brief(
            1, _cand("fund_freeze", "Permanent freezing of funds"),
            {}, "finding", "/ws")
        self.assertIn("PROCESS-COLOCATION / BLAST-RADIUS", crash_brief)
        self.assertNotIn("PROCESS-COLOCATION / BLAST-RADIUS", fund_brief)

    def test_general_proof_discipline_clause_on_EVERY_lane(self):
        # the universal no-assumption-only proof rule applies to ALL tiers, incl. fund
        for cand in (_cand("fund_freeze", "Permanent freezing of funds"),
                     _cand("bc-direct-loss-of-funds", "Direct loss of funds of USD $5,000 or more"),
                     _cand("validator_crash", "Crash or halt of >= 1/3 of validators")):
            brief = ewp._lane_brief(1, cand, {}, "finding", "/ws")
            self.assertIn("PROOF-OF-IMPOSSIBILITY DISCIPLINE", brief)
            self.assertIn("FORBIDDEN", brief)
            self.assertIn("DEPLOYMENT/TOPOLOGY", brief)


if __name__ == "__main__":
    unittest.main()
