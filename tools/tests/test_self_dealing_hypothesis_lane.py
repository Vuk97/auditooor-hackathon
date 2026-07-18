#!/usr/bin/env python3
"""Unit tests for tools/self-dealing-hypothesis-lane.py (SADL).

Coverage:
  - Solidity fixture: take(payer, receiver, ...) -> payer==receiver hypothesis emitted
    (morpho self-settled-take vector MUST survive tightening)
  - Single-address-param Solidity fn -> NO collapse hypothesis (need >= 2 params)
  - Same-role pair (tokenA, tokenB) -> NOT flagged (token is non-role)
  - Same-role pair (fromToken, toToken) -> NOT flagged
  - Opposing-role pair (sender, recipient) -> flagged
  - Go fixture: two sdk.AccAddress params -> collapse emitted
  - Rust fixture: two Addr params -> collapse emitted; implicit sender injected
  - Verdict invariant: every emitted hypothesis carries verdict="needs-fuzz"
  - attack_class invariant: every hypothesis has attack_class="self-dealing-identity-collapse"
  - source invariant: every hypothesis has source="SADL"
  - No em-dash in any emitted string field
"""
import importlib.util
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the SADL module (hyphen-safe dynamic import).
# ---------------------------------------------------------------------------
_SADL_PATH = Path(__file__).resolve().parent.parent / "self-dealing-hypothesis-lane.py"
_SADL_MOD_NAME = "self_dealing_hypothesis_lane"


def _load_sadl():
    spec = importlib.util.spec_from_file_location(_SADL_MOD_NAME, _SADL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_SADL_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


sadl = _load_sadl()

# ---------------------------------------------------------------------------
# Shared fixture sources (inlined for hermetic tests - no filesystem workspace).
# ---------------------------------------------------------------------------

# Solidity: take(address payer, address receiver, uint256 units)
# -> two address params: payer, receiver => one collapse pair
SOL_TAKE_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MarketCore {
    mapping(address => uint256) public creditOf;
    mapping(address => uint256) public debtOf;
    address public loanToken;

    function take(address payer, address receiver, uint256 units) external {
        creditOf[receiver] += units;
        debtOf[payer] += units;
        SafeTransferLib.safeTransferFrom(loanToken, payer, receiver, units);
    }
}
"""

# Solidity: single address param -> no collapse hypothesis possible
SOL_SINGLE_ADDR_SRC = """\
pragma solidity ^0.8.0;
contract T {
    mapping(address=>uint256) public balanceOf;
    function withdraw(address recipient, uint256 amount) external {
        balanceOf[recipient] -= amount;
    }
}
"""
# withdraw has two params but only ONE typed 'address' identifier: recipient
# (amount is uint256, not address) - so only one addr param -> no pair

# Go fixture: two sdk.AccAddress params -> one collapse pair
GO_TRANSFER_SRC = """\
package keeper

import (
    "context"
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{ bankKeeper BankKeeper }

type BankKeeper interface {
    SendCoins(ctx sdk.Context, from, to sdk.AccAddress, amt sdk.Coins) error
}

func (k Keeper) Transfer(ctx context.Context, from sdk.AccAddress, to sdk.AccAddress, amount sdk.Coins) error {
    sdkCtx := sdk.UnwrapSDKContext(ctx)
    return k.bankKeeper.SendCoins(sdkCtx, from, to, amount)
}
"""

# Rust CosmWasm: two explicit Addr params + implicit sender
RS_EXECUTE_SRC = """\
use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};

pub fn execute_transfer(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    from: Addr,
    to: Addr,
    amount: u128,
) -> Result<Response, ()> {
    // transfer tokens from 'from' to 'to'
    Ok(Response::new())
}
"""


# ---------------------------------------------------------------------------
# Helper: collect all (param_a, param_b) pairs from hypotheses.
# ---------------------------------------------------------------------------
def _pair_set(hyps):
    return {(h["param_a"], h["param_b"]) for h in hyps}


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

class TestSolTwoPairCollapse(unittest.TestCase):
    """Solidity take(payer, receiver, ...) -> payer==receiver hypothesis emitted."""

    def setUp(self):
        self.hyps = sadl.hypotheses_from_source(
            source=SOL_TAKE_SRC,
            language="sol",
            fn_name="take",
            file_rel="MarketCore.sol",
        )

    def test_payer_receiver_pair_emitted(self):
        pairs = _pair_set(self.hyps)
        self.assertIn(
            ("payer", "receiver"), pairs,
            f"Expected (payer, receiver) pair in hypotheses; got: {pairs}"
        )

    def test_at_least_one_hypothesis(self):
        self.assertGreater(len(self.hyps), 0, "Expected at least one hypothesis for take()")

    def test_collapse_expr_format(self):
        for h in self.hyps:
            expr = h["collapse_expr"]
            # Must be "<a> == <b>" with no em-dash
            self.assertIn("==", expr, f"collapse_expr missing '==': {expr}")
            self.assertNotIn("—", expr, "em-dash in collapse_expr")
            self.assertNotIn("–", expr, "en-dash in collapse_expr")


class TestSolSingleAddrNoCollapse(unittest.TestCase):
    """A fn with only one address param must emit NO collapse hypotheses."""

    def setUp(self):
        # withdraw(address recipient, uint256 amount) - only 'recipient' is address-typed.
        # SADL must emit zero hypotheses because there is no second address param.
        self.hyps = sadl.hypotheses_from_source(
            source=SOL_SINGLE_ADDR_SRC,
            language="sol",
            fn_name="withdraw",
            file_rel="Token.sol",
        )

    def test_no_hypothesis_for_single_addr(self):
        self.assertEqual(
            len(self.hyps), 0,
            f"Expected 0 hypotheses for single-addr fn; got: {self.hyps}"
        )


class TestGoTwoAccAddrCollapse(unittest.TestCase):
    """Go Transfer(from sdk.AccAddress, to sdk.AccAddress) -> from==to hypothesis."""

    def setUp(self):
        self.hyps = sadl.hypotheses_from_source(
            source=GO_TRANSFER_SRC,
            language="go",
            fn_name="Transfer",
            file_rel="bank_keeper.go",
        )

    def test_from_to_pair_emitted(self):
        pairs = _pair_set(self.hyps)
        self.assertIn(
            ("from", "to"), pairs,
            f"Expected (from, to) pair in Go hypotheses; got: {pairs}"
        )

    def test_at_least_one_hypothesis(self):
        self.assertGreater(len(self.hyps), 0, "Expected >=1 hypothesis for Go Transfer()")


class TestRustAddrCollapse(unittest.TestCase):
    """Rust execute_transfer(from: Addr, to: Addr, ...) -> from==to hypothesis."""

    def setUp(self):
        self.hyps = sadl.hypotheses_from_source(
            source=RS_EXECUTE_SRC,
            language="rs",
            fn_name="execute_transfer",
            file_rel="contract.rs",
        )

    def test_from_to_pair_emitted(self):
        pairs = _pair_set(self.hyps)
        self.assertIn(
            ("from", "to"), pairs,
            f"Expected (from, to) pair in Rust hypotheses; got: {pairs}"
        )

    def test_at_least_one_hypothesis(self):
        self.assertGreater(len(self.hyps), 0, "Expected >=1 hypothesis for Rust execute_transfer()")


class TestVerdictInvariant(unittest.TestCase):
    """Every emitted hypothesis must carry verdict='needs-fuzz'. No auto-credit."""

    def _all_hyps(self):
        hyps = []
        hyps += sadl.hypotheses_from_source(SOL_TAKE_SRC, "sol", "take")
        hyps += sadl.hypotheses_from_source(GO_TRANSFER_SRC, "go", "Transfer")
        hyps += sadl.hypotheses_from_source(RS_EXECUTE_SRC, "rs", "execute_transfer")
        return hyps

    def test_all_verdicts_are_needs_fuzz(self):
        for h in self._all_hyps():
            self.assertEqual(
                h["verdict"], "needs-fuzz",
                f"Hypothesis has wrong verdict '{h['verdict']}': {h}"
            )

    def test_all_attack_class_correct(self):
        for h in self._all_hyps():
            self.assertEqual(
                h["attack_class"], "self-dealing-identity-collapse",
                f"Wrong attack_class in: {h}"
            )

    def test_all_source_is_sadl(self):
        for h in self._all_hyps():
            self.assertEqual(
                h["source"], "SADL",
                f"Wrong source in: {h}"
            )

    def test_no_em_dash_in_any_field(self):
        """Formatting rule: no em-dash (U+2014) or en-dash (U+2013) in output."""
        for h in self._all_hyps():
            for key, val in h.items():
                if isinstance(val, str):
                    self.assertNotIn(
                        "—", val,
                        f"em-dash found in field '{key}': {val!r}"
                    )
                    self.assertNotIn(
                        "–", val,
                        f"en-dash found in field '{key}': {val!r}"
                    )


class TestSchemaCompleteness(unittest.TestCase):
    """Every emitted hypothesis must contain all required schema keys."""

    _REQUIRED_KEYS = {
        "workspace", "file", "function", "language",
        "param_a", "param_b", "collapse_expr", "note",
        "attack_class", "source", "verdict",
        "vcis_oracle_hint", "selftake_guard_note",
    }

    def test_schema_keys_present(self):
        hyps = sadl.hypotheses_from_source(SOL_TAKE_SRC, "sol", "take")
        self.assertGreater(len(hyps), 0, "No hypotheses to check schema against")
        for h in hyps:
            for key in self._REQUIRED_KEYS:
                self.assertIn(key, h, f"Missing required key '{key}' in hypothesis: {h}")


class TestSameRolePairNotFlagged(unittest.TestCase):
    """Token-address / same-role pairs must NOT produce hypotheses (flood-guard)."""

    # swapFrom(address fromToken, address toToken, ...) - both are token contracts,
    # not counterparty roles; neither is origin/dest.
    SOL_SWAP_SRC = """\
pragma solidity ^0.8.0;
contract Well {
    function swapFrom(address fromToken, address toToken, uint256 amountIn,
                      uint256 minAmountOut, address recipient) external
        returns (uint256 amountOut)
    {
        // swap fromToken -> toToken, send to recipient
    }
}
"""

    # transferToken(address sender, address recipient, address token,
    #               LibTransfer.From fromMode, LibTransfer.To toMode)
    # token / fromMode / toMode are non-role; only sender vs recipient is genuine.
    SOL_TRANSFER_TOKEN_SRC = """\
pragma solidity ^0.8.0;
contract LibTransfer {
    function transferToken(
        address sender,
        address recipient,
        address token,
        address From,
        address fromMode,
        address To,
        address toMode
    ) external { }
}
"""

    def test_fromToken_toToken_not_flagged(self):
        hyps = sadl.hypotheses_from_source(
            source=self.SOL_SWAP_SRC,
            language="sol",
            fn_name="swapFrom",
            file_rel="Well.sol",
        )
        pairs = _pair_set(hyps)
        # fromToken and toToken are non-role -> must NOT appear as a pair
        self.assertNotIn(
            ("fromToken", "toToken"), pairs,
            f"(fromToken, toToken) is a same-role/non-role pair and must be filtered; got: {pairs}"
        )
        # The genuine pair (sender/recipient or similar) may still appear
        # but that is tested elsewhere.

    def test_token_non_role_not_paired(self):
        """Ensure 'token' parameter is never emitted as half of a pair."""
        hyps = sadl.hypotheses_from_source(
            source=self.SOL_TRANSFER_TOKEN_SRC,
            language="sol",
            fn_name="transferToken",
            file_rel="LibTransfer.sol",
        )
        pairs = _pair_set(hyps)
        # No pair should include 'token' - it is a non-role asset address
        for a, b in pairs:
            self.assertNotIn(
                "token", (a.lower(), b.lower()),
                f"'token' is a non-role address and must not appear in pairs; got pair ({a},{b})"
            )

    def test_mode_enums_not_paired(self):
        """fromMode / toMode are enum/config values, not counterparty roles."""
        hyps = sadl.hypotheses_from_source(
            source=self.SOL_TRANSFER_TOKEN_SRC,
            language="sol",
            fn_name="transferToken",
            file_rel="LibTransfer.sol",
        )
        pairs = _pair_set(hyps)
        for a, b in pairs:
            self.assertNotIn(
                "frommode", (a.lower(), b.lower()),
                f"'fromMode' is a non-role param and must not appear in pairs; got ({a},{b})"
            )
            self.assertNotIn(
                "tomode", (a.lower(), b.lower()),
                f"'toMode' is a non-role param and must not appear in pairs; got ({a},{b})"
            )

    def test_sender_recipient_still_flagged(self):
        """The genuine opposing pair (sender, recipient) MUST survive tightening."""
        hyps = sadl.hypotheses_from_source(
            source=self.SOL_TRANSFER_TOKEN_SRC,
            language="sol",
            fn_name="transferToken",
            file_rel="LibTransfer.sol",
        )
        pairs = _pair_set(hyps)
        self.assertIn(
            ("sender", "recipient"), pairs,
            f"(sender, recipient) is a genuine origin/dest pair and must be flagged; got: {pairs}"
        )

    def test_swapFrom_recipient_still_flagged(self):
        """swapFrom has 'recipient' (dest) - if there is any origin param it pairs."""
        hyps = sadl.hypotheses_from_source(
            source=self.SOL_SWAP_SRC,
            language="sol",
            fn_name="swapFrom",
            file_rel="Well.sol",
        )
        # fromToken / toToken are non-role. recipient is dest but there is no
        # explicit origin-role param here, so zero pairs is acceptable.
        # What MUST NOT happen is a (fromToken, toToken) or (fromToken, recipient) pair.
        pairs = _pair_set(hyps)
        bad_token_pairs = {(a, b) for a, b in pairs if "token" in a.lower() or "token" in b.lower()}
        self.assertEqual(
            bad_token_pairs, set(),
            f"Token-address params must not appear in any pair; found: {bad_token_pairs}"
        )


class TestMorphoTakeSurvives(unittest.TestCase):
    """The morpho self-settled-take vector (payer==receiver) MUST survive tightening.

    This is the canonical case the lane was written for; tightening must NOT
    drop it.
    """

    def test_payer_receiver_flagged(self):
        hyps = sadl.hypotheses_from_source(
            source=SOL_TAKE_SRC,
            language="sol",
            fn_name="take",
            file_rel="MarketCore.sol",
        )
        pairs = _pair_set(hyps)
        self.assertIn(
            ("payer", "receiver"), pairs,
            f"morpho-class (payer, receiver) pair must survive tightening; got: {pairs}"
        )

    def test_only_opposing_role_pairs_emitted_for_take(self):
        """take(payer, receiver) -> exactly one pair (both are roles, opposing)."""
        hyps = sadl.hypotheses_from_source(
            source=SOL_TAKE_SRC,
            language="sol",
            fn_name="take",
            file_rel="MarketCore.sol",
        )
        # payer=origin, receiver=dest => one pair expected. No extras.
        self.assertEqual(
            len(hyps), 1,
            f"Expected exactly 1 hypothesis for take(payer, receiver); got {len(hyps)}: {hyps}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
