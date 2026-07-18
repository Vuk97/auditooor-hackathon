#!/usr/bin/env python3
"""Regression: IMPACT-FIRST availability/consensus attach in render_impact_questions.

THE GAP (SEI 2026-07-04): a Blockchain/DLT program's DOMINANT impact surface is
AVAILABILITY/CONSENSUS (chain halt / chain split / RPC-node crash / consensus
liveness / block stuffing), not fund theft. Those attack surfaces live on
functions whose impact is triggered by their POSITION on the block-production /
node / p2p / mempool / rpc path (ABCI++ Begin/EndBlocker, CheckTx, consensus
vote/timeout, evmrpc/gRPC handlers) - NOT by a value-moving verb. Before the fix
the shape arm missed those (the classifier gives them a benign
`external-state-mutating-fn` shape) and the DeFi `kind_rescue` arm suppressed them
(it required `not classes AND value_moving_ish`), so the chain-halt / chain-split
/ consensus-transient / node-resource / RPC-crash playbooks attached to ZERO
consensus units - the impact-first-not-symbol-first miss.

The fix adds an INFRA-KIND availability arm: an AVAILABILITY-PRIMARY Blockchain/DLT
playbook (chain-*/bc-*/griefing) attaches to a NODE-LANGUAGE (go/rust/c/cpp/...)
target whose contract-kind is an infra family (consensus / cosmos-module),
regardless of shape or a value-moving verb, plus availability-first ordering + a
per-playbook breadth cap so distinct availability frames survive the per-fn cap.

These assertions FAIL if the arm is reverted (consensus units get NO availability
methodology) OR if it over-fires (a pure solidity Smart-Contract target inherits
availability methodology it cannot realize).

GENERIC + LANGUAGE-AGNOSTIC: nothing here is workspace-specific; every signal is
derived from the impact-hunting-methodology corpus + the kind/language families.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hacker_question_renderer.py"
_s = importlib.util.spec_from_file_location("hqr_avail", _T)
hqr = importlib.util.module_from_spec(_s)
sys.modules["hqr_avail"] = hqr
_s.loader.exec_module(hqr)

# A Blockchain/DLT SEVERITY.md-shaped scope: halt / split / RPC-crash / block-
# delay / block-stuffing rows. The literal "block production" phrase makes the
# scope-driven contract-kind classifier resolve `consensus` for units in this
# program (the real SEI shape).
_BC_SCOPE = (
    "Blockchain/DLT: >=1/3 validator halt of block production, unintended chain "
    "split requiring hard fork, crash of RPC nodes, block-production delay "
    "exceeding 2.5s, block stuffing. Consensus / ABCI / tendermint / cosmos node."
)

# A pure Smart-Contract SEVERITY.md-shaped scope: NO availability/consensus rows.
_SC_SCOPE = (
    "ERC-4626 vault: direct theft of user funds, permanent freeze of funds, "
    "share-price manipulation, unauthorized mint. Solidity DeFi lending market."
)

_AVAIL = {
    "chain-halt-shutdown", "chain-split-fork", "bc-consensus-transient-failure",
    "bc-node-resource-exhaustion", "bc-rpc-api-crash", "bc-permanent-freeze-hardfork",
    "bc-direct-loss-of-funds", "griefing-dos-blockstuffing",
}


def _ids(fn, sig="", *, language="go", scope="", kind="", cap=0):
    return [
        r.get("impact_id")
        for r in hqr.render_impact_questions(
            function_name=fn, function_signature=sig, language=language,
            scope_text=scope, contract_kind=kind, max_questions=cap,
        )
    ]


class AvailabilityFirstAttachTest(unittest.TestCase):
    def test_consensus_blocker_gets_availability_despite_benign_shape(self):
        # EndBlocker: benign `external-state-mutating-fn` shape, NO value-moving
        # verb. Under the OLD predicate it got fund-theft / a generic fallback and
        # ZERO availability methodology. It must now carry the availability suite.
        for fn in ("EndBlocker", "BeginBlock", "CheckTx", "ProcessProposal"):
            ids = set(_ids(fn, language="go", scope=_BC_SCOPE))
            self.assertTrue(
                ids & _AVAIL,
                f"{fn} (go/consensus) must attach availability methodology; got {sorted(ids)}",
            )

    def test_availability_frames_are_diverse_under_a_small_cap(self):
        # The per-fn cap is small in production (min(3, ...)). The breadth cap must
        # make the first 3 rows span 3 DISTINCT availability impacts, not 3 copies
        # of one - so the hunter SEES halt vs split vs rpc-crash vs node-resource.
        ids = _ids("EndBlocker", language="go", scope=_BC_SCOPE, cap=3)
        self.assertEqual(len(ids), 3)
        self.assertTrue(set(ids) <= _AVAIL, f"cap-3 rows must be availability: {ids}")
        self.assertEqual(len(set(ids)), 3, f"cap-3 availability frames must be DISTINCT: {ids}")

    def test_rust_consensus_also_covered(self):
        # Language-agnostic: a rust node target is covered too (not go-only).
        ids = set(_ids("finalize_block", language="rust", scope=_BC_SCOPE))
        self.assertTrue(ids & _AVAIL, f"rust consensus must attach availability; got {sorted(ids)}")

    def test_pure_smart_contract_ws_is_unaffected(self):
        # A pure Smart-Contract (solidity) target must NOT inherit availability /
        # consensus methodology - it cannot halt a chain. Even under a scope whose
        # text mentions block production, the node-language gate excludes solidity.
        for scope in (_SC_SCOPE, _BC_SCOPE):
            ids = set(_ids("transferFrom",
                           "function transferFrom(address f,address t,uint256 id) external",
                           language="solidity", scope=scope))
            leaked = ids & {"chain-halt-shutdown", "chain-split-fork",
                            "bc-consensus-transient-failure", "bc-node-resource-exhaustion",
                            "bc-rpc-api-crash", "bc-permanent-freeze-hardfork",
                            "bc-direct-loss-of-funds"}
            self.assertFalse(
                leaked,
                f"a solidity Smart-Contract target leaked availability impacts {sorted(leaked)} "
                f"under scope prefix {scope[:30]!r}",
            )

    def test_infra_arm_does_not_spray_fund_theft(self):
        # The infra arm attaches ONLY availability-primary playbooks. A fund-theft
        # playbook that merely lists `cosmos-module` (direct-theft-funds /
        # access-control-bypass) must NOT attach to a benign consensus unit via the
        # infra arm (it still attaches only via shape / value-moving rescue).
        ids = _ids("sumTotalFrac", language="go", scope=_BC_SCOPE, cap=3)
        # first-visited rows are availability-primary, not fund-theft
        self.assertTrue(set(ids) <= _AVAIL, f"infra unit cap-3 must be availability-only: {ids}")

    def test_helpers(self):
        self.assertTrue(hqr._impact_is_availability_primary("chain-halt-shutdown"))
        self.assertTrue(hqr._impact_is_availability_primary("bc-rpc-api-crash"))
        self.assertTrue(hqr._impact_is_availability_primary("griefing-dos-blockstuffing"))
        self.assertFalse(hqr._impact_is_availability_primary("direct-theft-funds"))
        self.assertFalse(hqr._impact_is_availability_primary("access-control-bypass"))
        self.assertTrue(hqr._impact_is_infrastructure_playbook({"consensus"}))
        self.assertTrue(hqr._impact_is_infrastructure_playbook({"cosmos-module", "vault"}))
        self.assertFalse(hqr._impact_is_infrastructure_playbook({"vault", "lending"}))
        # node-language gate constants
        self.assertIn("go", hqr._INFRA_ATTACH_LANGUAGES)
        self.assertIn("rust", hqr._INFRA_ATTACH_LANGUAGES)
        self.assertNotIn("solidity", hqr._INFRA_ATTACH_LANGUAGES)
        self.assertNotIn("vyper", hqr._INFRA_ATTACH_LANGUAGES)


if __name__ == "__main__":
    unittest.main()
