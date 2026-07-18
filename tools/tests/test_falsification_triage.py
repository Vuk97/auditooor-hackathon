#!/usr/bin/env python3
"""Tests for falsification-triage: a fuzz falsification that re-discovers a
documented known/acknowledged issue is caught BEFORE a verification agent is spent;
a genuinely novel one routes to full verification."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "falsification_triage",
    Path(__file__).resolve().parent.parent / "falsification-triage.py",
)
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)

_REG = {
    "schema": "auditooor.known_issues.v1",
    "issues": [
        {
            "id": "SSV-KI-e",
            "title": "delayed-liquidation bad-debt",
            "status": "acknowledged-oos",
            "source": "Quantstamp + Immunefi 77910",
            "keywords": ["liquidation", "delayed", "insolven", "minimumLiquidationCollateral",
                         "solvency", "advance_time", "bad-debt"],
            "invariant_hints": ["eth_balance_accounting", "cluster_solvency"],
            "rule": "R47/R45/R35",
        }
    ],
}


def _mk_ws(tmp, registry=_REG, prior_audit_text=None):
    ws = Path(tmp)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    if registry is not None:
        (ws / ".auditooor" / "known_issues.json").write_text(json.dumps(registry))
    if prior_audit_text:
        (ws / "prior_audits").mkdir(exist_ok=True)
        (ws / "prior_audits" / "audit.txt").write_text(prior_audit_text)
    return ws


class TestTriage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_known_issue_rediscovery_by_invariant_hint(self):
        ws = _mk_ws(self.tmp)
        rep = mod.triage(ws, "echidna_eth_balance_accounting",
                         mod._norm_tokens("liquidation advance_time withdraw deposit"))
        self.assertEqual(rep["disposition"], "known-issue-rediscovery")
        self.assertEqual(rep["matches"][0]["id"], "SSV-KI-e")
        self.assertGreaterEqual(rep["matches"][0]["confidence"], 0.7)

    def test_novel_invariant_routes_to_full_verification(self):
        ws = _mk_ws(self.tmp)
        rep = mod.triage(ws, "echidna_merkle_root_unique",
                         mod._norm_tokens("register validator pubkey"))
        self.assertEqual(rep["disposition"], "candidate-novel")
        self.assertEqual(rep["matches"], [])

    def test_keyword_overlap_partial_match(self):
        ws = _mk_ws(self.tmp)
        # different invariant name but shares solvency/liquidation keywords
        rep = mod.triage(ws, "echidna_pool_consistency",
                         mod._norm_tokens("solvency liquidation"))
        self.assertIn(rep["disposition"], ("possible-known-issue", "known-issue-rediscovery"))
        self.assertTrue(rep["matches"])

    def test_prior_audit_scan_elevates(self):
        ws = _mk_ws(self.tmp, registry={"issues": []},
                    prior_audit_text="Delayed liquidation results in insolvency and bad-debt "
                                     "when minimumLiquidationCollateral is low. Acknowledged.")
        rep = mod.triage(ws, "echidna_eth_balance_accounting",
                         mod._norm_tokens("liquidation insolven minimumLiquidationCollateral"))
        self.assertTrue(rep["prior_audit_hits"])

    def test_registry_absent_is_safe(self):
        ws = Path(tempfile.mkdtemp())
        rep = mod.triage(ws, "echidna_x", mod._norm_tokens("foo bar"))
        self.assertFalse(rep["registry_present"])
        self.assertEqual(rep["disposition"], "candidate-novel")


class TestSeededSSVRegistry(unittest.TestCase):
    def test_real_ssv_registry_matches_eth_balance_accounting(self):
        ws = Path("/Users/wolf/audits/ssv-network")
        if not (ws / ".auditooor" / "known_issues.json").is_file():
            self.skipTest("SSV registry not present in this environment")
        rep = mod.triage(ws, "echidna_eth_balance_accounting",
                         mod._norm_tokens("liquidation advance_time withdraw deposit dust"))
        self.assertEqual(rep["disposition"], "known-issue-rediscovery")
        self.assertEqual(rep["matches"][0]["id"], "SSV-KI-e-cluster-insolvency-liquidator-liveness")


if __name__ == "__main__":
    unittest.main()
