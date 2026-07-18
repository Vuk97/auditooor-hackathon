#!/usr/bin/env python3
"""Regression: token-transfer-path classifier precision on the ownership family.

`classify_function_shape` keyed the sharp `token-transfer-path` shape on the
bare "transfer" substring in the function NAME, so it false-matched the
OWNERSHIP / ROLE / ADMIN transfer family (transferOwnership / transferAdmin /
transferRole / accept*) - none of which move a VALUE token. Via shape_match
(and, downstream, the value-moving kind_rescue arm) that leaked the value-impact
playbooks (direct-theft-funds) onto e.g. transferOwnership at a vault.

Root fix (2026-07-04): token-transfer-path matches a VALUE token transfer only -
the value-transfer verb PLUS (an amount-ish param uint/uint256/amount/value/
shares/assets in the signature OR a name outside the ownership/role/admin/
operator/accept* family). The value-moving heuristic that feeds the kind_rescue
arm carries the same exclusion so transferOwnership is not treated as a value
mover either.

These assertions FAIL if the precision guard is reverted:
  - transfer / transferFrom / safeTransfer / safeTransferFrom / send KEEP
    token-transfer-path AND (vault) attach direct-theft-funds.
  - transferOwnership / acceptOwnership / transferAdmin / transferRole are
    EXCLUDED from token-transfer-path AND (vault) do NOT attach direct-theft-funds.
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


# (name, signature) probes.
_VALUE_TRANSFERS = [
    ("transfer", "function transfer(address to, uint256 amount) external"),
    ("transferFrom",
     "function transferFrom(address from, address to, uint256 amount) external"),
    ("safeTransfer", "function safeTransfer(address to, uint256 amount) external"),
    ("safeTransferFrom",
     "function safeTransferFrom(address from, address to, uint256 id, uint256 amount) external"),
    ("send", "function send(address to, uint256 amount) external"),
]

_OWNERSHIP_ADMIN_ROLE = [
    ("transferOwnership", "function transferOwnership(address n) external"),
    ("acceptOwnership", "function acceptOwnership() external"),
    ("transferAdmin", "function transferAdmin(address a) external"),
    ("transferRole", "function transferRole(bytes32 r, address a) external"),
]


def _impact_ids(rows):
    return {r.get("impact_id") for r in rows if isinstance(r, dict)}


class TokenTransferPathClassifierPrecisionTest(unittest.TestCase):
    def test_value_transfers_keep_token_transfer_path(self):
        for name, sig in _VALUE_TRANSFERS:
            classes = _m.classify_function_shape(name, sig)
            self.assertIn(
                "token-transfer-path", classes,
                f"{name} lost token-transfer-path (should be a VALUE transfer): {classes}",
            )

    def test_ownership_role_admin_excluded_from_token_transfer_path(self):
        for name, sig in _OWNERSHIP_ADMIN_ROLE:
            classes = _m.classify_function_shape(name, sig)
            self.assertNotIn(
                "token-transfer-path", classes,
                f"{name} wrongly got token-transfer-path (not a VALUE transfer): {classes}",
            )

    def test_value_transfers_attach_direct_theft_at_vault(self):
        for name, sig in _VALUE_TRANSFERS:
            rows = _m.render_impact_questions(
                name, sig, language="solidity", contract_kind="vault"
            )
            self.assertIn(
                "direct-theft-funds", _impact_ids(rows),
                f"{name} must still attach direct-theft-funds at a vault",
            )

    def test_ownership_role_admin_do_not_attach_direct_theft_at_vault(self):
        for name, sig in _OWNERSHIP_ADMIN_ROLE:
            rows = _m.render_impact_questions(
                name, sig, language="solidity", contract_kind="vault"
            )
            self.assertNotIn(
                "direct-theft-funds", _impact_ids(rows),
                f"{name} must NOT attach direct-theft-funds (privilege transfer, not value)",
            )

    def test_ownership_with_amount_param_is_still_value_transfer(self):
        # An amount-ish param is the structural value signal - if a transfer verb
        # DOES carry one, it stays a value transfer even with an admin-ish name.
        classes = _m.classify_function_shape(
            "transferWeighted",
            "function transferWeighted(bytes32 role, uint256 amount) external",
        )
        self.assertIn("token-transfer-path", classes)


if __name__ == "__main__":
    unittest.main()
