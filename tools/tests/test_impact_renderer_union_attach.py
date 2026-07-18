#!/usr/bin/env python3
"""Regression: render_impact_questions UNION attach (shape OR contract-kind).

Catches the half-integration bug found by the live-render proof on
2026-06-28: the original predicate REQUIRED a shape-class match (plus an early
`if not classes: return []`), so a DeFi value-mover the shape classifier does
not tag (a plain `deposit`) attached NOTHING - the entire DeFi/EVM half of the
impact methodology silently never reached the hunter, while the Go/consensus
half worked. The fix makes attach a UNION: shape-class intersect OR the known
contract-kind is in applies_to_contract_kinds (language stays an exclusion
guard). These assertions FAIL if the union is reverted to shape-only.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hacker_question_renderer.py"
_s = importlib.util.spec_from_file_location("hacker_question_renderer", _T)
_m = importlib.util.module_from_spec(_s)
sys.modules["hacker_question_renderer"] = _m
_s.loader.exec_module(_m)


def _ids(rows):
    return sorted({r.get("impact_id") for r in rows if isinstance(r, dict)})


class UnionAttachTest(unittest.TestCase):
    def test_defi_vault_attaches_via_contract_kind(self):
        # A plain deposit the shape classifier does NOT tag must still attach
        # the DeFi impacts via contract_kind=vault (the bug: returned []).
        rows = _m.render_impact_questions(
            "deposit",
            "function deposit(uint256 a, address r) external returns(uint256)",
            language="solidity",
            contract_kind="vault",
        )
        ids = _ids(rows)
        self.assertTrue(ids, "vault deposit must attach >=1 impact playbook (union via kind)")
        self.assertIn("direct-theft-funds", ids)
        # contract-kind partition: a vault is NOT a consensus target.
        self.assertFalse(
            any("chain-halt" in i for i in ids),
            "a solidity vault must NOT receive chain-halt methodology",
        )

    def test_go_consensus_attaches_chain_halt(self):
        rows = _m.render_impact_questions(
            "Finalize",
            "func Finalize(ctx sdk.Context) error",
            language="go",
            contract_kind="consensus",
        )
        ids = _ids(rows)
        self.assertTrue(
            any("chain-halt" in i for i in ids),
            "a go/consensus target must receive chain-halt methodology",
        )

    def test_language_still_excludes(self):
        # Language stays an exclusion guard: a zk-only playbook must not attach
        # to a solidity target. (Assert no impact whose langs exclude solidity
        # leaks in - proxy: chain-split-fork/consensus blocks are go/rust.)
        rows = _m.render_impact_questions(
            "deposit",
            "function deposit(uint256 a) external",
            language="solidity",
            contract_kind="vault",
        )
        ids = _ids(rows)
        self.assertNotIn("chain-split-fork", ids)


class GenericShapeDoesNotDropKindImpactsTest(unittest.TestCase):
    """Regression for the 2026-07-04 `and not classes` coverage loss: a
    value-moving function the classifier tags with ONLY generic/structural shapes
    (external-state-mutating-fn / cross-contract-call) must still attach its
    contract-kind-listed impacts. The buggy gate disabled the whole kind arm the
    instant ANY shape existed, silently dropping 93 (impact,kind) pairs incl.
    direct-theft-funds across vault/lending/amm/bridge/gov. FAILS if `not (classes
    - _GENERIC_ONLY_SHAPES)` is reverted to `not classes`.
    """

    # (function, signature, kind, impacts that MUST attach). Each function is
    # value-moving AND classifies to only-generic shapes ({cross-contract-call,
    # external-state-mutating-fn} - `deposit` is a value verb the classifier does
    # NOT give a sharp value shape, and the address param adds only cross-contract-
    # call), so these impacts attach ONLY via the contract-kind arm - exactly the
    # path the `not classes` bug disabled. (A fn with a SHARP shape - e.g.
    # relayMessage -> cross-chain-message-fn - is deliberately governed by
    # shape_match instead, a separate concern, so it is NOT asserted here.)
    _CASES = [
        ("deposit", "function deposit(uint256 a, address r) external", "vault",
         ["direct-theft-funds", "protocol-insolvency", "share-supply-inflation",
          "permanent-freeze-funds"]),
        ("deposit", "function deposit(uint256 a, address r) external", "lending",
         ["direct-theft-funds", "protocol-insolvency", "share-supply-inflation",
          "permanent-freeze-funds"]),
    ]

    def test_value_mover_generic_shape_keeps_kind_impacts(self):
        for fn, sig, kind, must in self._CASES:
            ids = _ids(_m.render_impact_questions(fn, sig, language="solidity", contract_kind=kind))
            for imp in must:
                self.assertIn(imp, ids, f"{fn}/{kind} dropped kind-listed impact {imp}: {sorted(ids)}")

    def test_specific_shape_still_governs_no_spray(self):
        # A function with a SHARP shape (access-controlled-setter) must NOT be
        # sprayed with theft/custody via the kind arm - its real shape governs.
        ids = _ids(_m.render_impact_questions(
            "registerValidator", "function registerValidator(bytes pk, uint64[] ids) external payable",
            language="solidity", contract_kind="staking"))
        self.assertNotIn("direct-theft-funds", ids)
        self.assertNotIn("theft-unclaimed-yield", ids)

    def test_view_getter_stays_clean(self):
        # A pure view must not receive fund-theft methodology (value-moving gate).
        ids = _ids(_m.render_impact_questions(
            "balanceOf", "function balanceOf(address a) external view returns(uint256)",
            language="solidity", contract_kind="vault"))
        self.assertNotIn("direct-theft-funds", ids)


class ValueConductingSharpShapeAttachTest(unittest.TestCase):
    """Regression for the 2026-07-04 SHARP-shape residual: a value-mover whose
    sharp shape is value-CONDUCTING (funds flow through it) must attach its
    contract-kind's value-impacts even when the specific impact's
    applies_to_shape_classes omits that sharp shape. Witness: a bridge relayMessage
    (cross-chain-message-fn, no value verb) dropped direct-theft-funds /
    bridge-cross-chain-drain; a lending borrow (collateral-liquidation-fn) dropped
    its theft/freeze impacts. FAILS if the value-conducting 2nd kind_rescue arm is
    removed - or if it is widened to admin/upgrade shapes (anti-spray).
    """

    # (fn, sig, kind, impacts that MUST attach) - the fn's ONLY sharp shape is
    # value-conducting, with no value verb/param (so the generic-only arm cannot
    # fire; the shape itself is the value signal).
    _MUST_ATTACH = [
        ("relayMessage", "function relayMessage(address t, bytes calldata d) external", "bridge",
         ["direct-theft-funds", "bridge-cross-chain-drain"]),
        ("borrow", "function borrow(uint256 a, address c) external", "lending",
         ["direct-theft-funds", "permanent-freeze-funds"]),
        ("liquidate", "function liquidate(address u, uint256 r) external", "lending",
         ["direct-theft-funds", "liquidation-abuse"]),
    ]

    # (fn, sig, kind) whose sharp shape is admin/config/upgrade/oracle/pause - the
    # value-conducting arm must NOT fire (anti-spray).
    _MUST_STAY_CLEAN = [
        ("registerValidator", "function registerValidator(bytes pk, uint64[] ids) external payable", "staking"),
        ("upgradeTo", "function upgradeTo(address newImpl) external", "proxy"),
        ("pause", "function pause() external", "vault"),
        ("grantRole", "function grantRole(bytes32 role, address a) external", "vault"),
    ]

    def test_value_conducting_sharp_shape_attaches_kind_impacts(self):
        for fn, sig, kind, must in self._MUST_ATTACH:
            ids = _ids(_m.render_impact_questions(fn, sig, language="solidity", contract_kind=kind))
            for imp in must:
                self.assertIn(imp, ids, f"{fn}/{kind} dropped value-conducting kind impact {imp}: {sorted(ids)}")

    def test_admin_upgrade_shapes_not_sprayed_via_value_conducting_arm(self):
        # These get NO direct-theft via the KIND arm. (registerValidator/upgradeTo/
        # pause/grantRole classify to access-controlled-setter / upgrade-init-fn /
        # pausable-emergency-fn - none value-conducting, none value-moving-generic.)
        for fn, sig, kind in self._MUST_STAY_CLEAN:
            ids = _ids(_m.render_impact_questions(fn, sig, language="solidity", contract_kind=kind))
            self.assertNotIn("direct-theft-funds", ids, f"{fn}/{kind} sprayed direct-theft: {sorted(ids)}")
            self.assertNotIn("theft-unclaimed-yield", ids, f"{fn}/{kind} sprayed theft-yield: {sorted(ids)}")

    def test_value_conducting_set_excludes_imprecise_token_transfer_path(self):
        # token-transfer-path is classifier-imprecise (matches transferOwnership),
        # so it MUST NOT be in the value-conducting set (else transferOwnership would
        # gain theft via the kind arm on top of any shape_match).
        self.assertNotIn("token-transfer-path", _m._VALUE_CONDUCTING_SHARP_SHAPES)
        # sanity: the set is non-empty and disjoint from the generic-only set
        self.assertTrue(_m._VALUE_CONDUCTING_SHARP_SHAPES)
        self.assertFalse(_m._VALUE_CONDUCTING_SHARP_SHAPES & _m._GENERIC_ONLY_SHAPES)


if __name__ == "__main__":
    unittest.main()
