"""test_anomaly_escalation_guard.py

The gate blocks a NOT-a-bug / down-tier verdict that rests on an UNEXPLAINED
anomaly the analysis itself admitted (R80). Regression = the strata MIN_SHARES
worker: it closed the finding not-fileable/LOW while writing "logically impossible"
and "spent enough cycles" about the mechanism its severity rests on.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "anomaly-escalation-guard.py"


def _load():
    spec = importlib.util.spec_from_file_location("anomaly_escalation_guard", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["anomaly_escalation_guard"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


G = _load()

# Representative excerpt of the real strata MIN_SHARES worker verdict.
_MINSHARES_REPORT = (
    "The redeem(8e17) burns 8e17 leaving 2e17, but STILL reverts MinSharesViolation. "
    "0.2e18 < 0.1e18 = FALSE, yet it reverts. This is logically impossible unless "
    "totalSupply() returns something else. I've spent enough cycles on the exact "
    "constant; the precise magnitude does not matter to the finding class. "
    "DECISION: NOT-FILEABLE (bounded-dust permanent freeze). Honest tier: LOW."
)


class TestAnomalyEscalationGuard(unittest.TestCase):
    def test_minshares_report_is_flagged(self):
        res = G.evaluate(_MINSHARES_REPORT)
        self.assertEqual(res["verdict"], "flag-escalate-for-root-cause")
        self.assertFalse(G._permits(res["verdict"]))
        self.assertTrue(res["anomaly_hits"])
        self.assertTrue(res["close_hits"])

    def test_clean_not_fileable_passes(self):
        text = ("DECISION: NOT-FILEABLE. SharesCooldown.sol is out of scope (not one of "
                "the 13 enumerated targets); impact stays in the OOS file; funds "
                "owner-recoverable via finalizeWithOverrides. Disposition recorded.")
        res = G.evaluate(text)
        self.assertTrue(G._permits(res["verdict"]))
        self.assertEqual(res["verdict"], "pass-no-unexplained-close")

    def test_open_finding_with_loose_end_passes(self):
        text = ("This is a candidate FINDING. I could not fully reconcile the 10x factor "
                "yet - flagging it OPEN for follow-up. No verdict; needs a PoC.")
        res = G.evaluate(text)
        self.assertEqual(res["verdict"], "pass-anomaly-but-open")
        self.assertTrue(G._permits(res["verdict"]))

    def test_rebuttal_permits(self):
        text = (_MINSHARES_REPORT +
                "\nanomaly-escalation-rebuttal: 10x root-caused to fee-share mint in "
                "accrueFee (Accounting.sol:304); magnitude confirmed fixed via PoC.")
        res = G.evaluate(text)
        self.assertEqual(res["verdict"], "pass-rebuttal")

    def test_clean_confirmed_finding_passes(self):
        text = ("CONFIRMED permanent freeze. Root cause: the >0 arm was dropped at "
                "Tranche.sol:453; the extra burn is the accrueFee mint at L304 "
                "(explained + PoC-verified). Severity: Medium. Drive to paste-ready.")
        res = G.evaluate(text)
        self.assertTrue(G._permits(res["verdict"]))


if __name__ == "__main__":
    unittest.main()
