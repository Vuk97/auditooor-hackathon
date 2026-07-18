#!/usr/bin/env python3
"""Unit tests for tools/share-inflation-lane.py (SIDL).

Coverage matrix
---------------
SOL_DEPOSIT_SRC     - ERC-4626-style deposit() with shares=assets*supply/totalAssets
                      (round-down mulDiv) -> SIDL MUST flag both donation +
                      first-depositor hypotheses + 1 invariant spec.

SOL_TRANSFER_SRC    - plain safeTransfer with NO share minting -> 0 hypotheses.

SOL_PROTECTED_SRC   - ERC-4626 deposit() WITH virtualShares mitigation ->
                      mitigation present so SIDL MUST emit 0 hypotheses.

GO_SHARE_MINT_SRC   - Go LP share-minting fn with totalSupply arithmetic ->
                      SIDL MUST flag it.

RS_SHARE_MINT_SRC   - Rust fn with total_supply mul_div and mint_to() call ->
                      SIDL MUST flag it.

Invariant checks
----------------
- Every emitted hypothesis has verdict="needs-fuzz"
- Every emitted hypothesis has source="SIDL"
- attack_class is "share-inflation-donation" or "share-inflation-first-depositor"
- No em-dash (U+2014) or en-dash (U+2013) in any string field
- Invariant spec has invariant_class="share-price-integrity" and verdict="needs-fuzz"
"""
import importlib.util
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the SIDL module (hyphen-safe dynamic import).
# ---------------------------------------------------------------------------
_SIDL_PATH = Path(__file__).resolve().parent.parent / "share-inflation-lane.py"
_SIDL_MOD_NAME = "share_inflation_lane"


def _load_sidl():
    spec = importlib.util.spec_from_file_location(_SIDL_MOD_NAME, _SIDL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_SIDL_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


sidl = _load_sidl()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Solidity ERC-4626-style deposit: shares = assets * totalSupply / totalAssets
# Round-down mulDiv. No mitigations.
SOL_DEPOSIT_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleVault {
    mapping(address => uint256) public shareOf;
    uint256 public totalSupply;
    address public asset;

    function deposit(uint256 assets, address recipient) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        uint256 total = IERC20(asset).balanceOf(address(this));
        if (supply == 0) {
            shares = assets;
        } else {
            shares = assets.mulDiv(supply, total);
        }
        totalSupply += shares;
        shareOf[recipient] += shares;
        _mint(recipient, shares);
        IERC20(asset).safeTransferFrom(msg.sender, address(this), assets);
    }
}
"""

# Solidity plain transfer - no share minting at all.
SOL_TRANSFER_SRC = """\
pragma solidity ^0.8.0;
contract Router {
    function sendTokens(address token, address to, uint256 amount) external {
        IERC20(token).safeTransfer(to, amount);
    }
}
"""

# Solidity ERC-4626 deposit WITH virtualShares mitigation (OZ ERC-4626 style).
# SIDL should emit 0 hypotheses because the mitigation is present.
SOL_PROTECTED_SRC = """\
pragma solidity ^0.8.0;
contract SafeVault {
    uint8 internal constant _decimalsOffset = 9;
    uint256 public totalSupply;
    address public asset;

    function deposit(uint256 assets, address recipient) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        uint256 total = IERC20(asset).balanceOf(address(this));
        // virtualShares offset prevents inflation
        shares = assets.mulDiv(supply + 10 ** _decimalsOffset, total + 1);
        totalSupply += shares;
        _mint(recipient, shares);
    }
}
"""

# Go share-minting function using totalSupply arithmetic.
GO_SHARE_MINT_SRC = """\
package keeper

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{ bankKeeper BankKeeper }

func (k Keeper) AddLiquidity(ctx sdk.Context, provider sdk.AccAddress, assets sdk.Int) (sdk.Int, error) {
    totalSupply := k.GetTotalShares(ctx)
    totalAssets := k.GetTotalAssets(ctx)
    var shares sdk.Int
    if totalSupply.IsZero() {
        shares = assets
    } else {
        shares = assets.MulDiv(totalSupply, totalAssets)
    }
    k.MintCoins(ctx, provider, shares)
    return shares, nil
}
"""

# Rust share-minting with total_supply and mul_div + mint_to.
RS_SHARE_MINT_SRC = """\
use cosmwasm_std::{Deps, DepsMut, MessageInfo, Response, Uint128};

pub fn deposit(
    deps: DepsMut,
    info: MessageInfo,
    assets: Uint128,
) -> Result<Response, ()> {
    let total_supply = TOTAL_SUPPLY.load(deps.storage)?;
    let total_assets = TOTAL_ASSETS.load(deps.storage)?;
    let shares = if total_supply.is_zero() {
        assets
    } else {
        assets.mul_div(total_supply, total_assets)
    };
    TOTAL_SUPPLY.save(deps.storage, &(total_supply + shares))?;
    mint_to(deps.storage, &info.sender, shares)?;
    Ok(Response::new())
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _attack_classes(hyps):
    return {h["attack_class"] for h in hyps}


def _no_dashes(hyps):
    """Return the first field+value that contains an em-dash or en-dash, or None."""
    for h in hyps:
        for k, v in h.items():
            if isinstance(v, str):
                if "—" in v:
                    return f"em-dash in field '{k}': {v!r}"
                if "–" in v:
                    return f"en-dash in field '{k}': {v!r}"
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSolERC4626Deposit(unittest.TestCase):
    """ERC-4626-style deposit() -> SIDL flags donation + first-depositor hypotheses."""

    def setUp(self):
        self.hyps, self.invs = sidl.hypotheses_from_source(
            source=SOL_DEPOSIT_SRC,
            language="sol",
            fn_name="deposit",
            file_rel="SimpleVault.sol",
        )

    def test_two_hypotheses_emitted(self):
        self.assertEqual(
            len(self.hyps), 2,
            f"Expected exactly 2 hypotheses (donation + first-depositor); got {len(self.hyps)}: {self.hyps}"
        )

    def test_donation_hypothesis_emitted(self):
        classes = _attack_classes(self.hyps)
        self.assertIn(
            "share-inflation-donation", classes,
            f"Missing share-inflation-donation hypothesis; classes={classes}"
        )

    def test_first_depositor_hypothesis_emitted(self):
        classes = _attack_classes(self.hyps)
        self.assertIn(
            "share-inflation-first-depositor", classes,
            f"Missing share-inflation-first-depositor hypothesis; classes={classes}"
        )

    def test_one_invariant_spec_emitted(self):
        self.assertEqual(
            len(self.invs), 1,
            f"Expected exactly 1 invariant spec; got {len(self.invs)}"
        )

    def test_invariant_class(self):
        inv = self.invs[0]
        self.assertEqual(
            inv["invariant_class"], "share-price-integrity",
            f"Wrong invariant_class: {inv['invariant_class']}"
        )

    def test_invariant_verdict(self):
        inv = self.invs[0]
        self.assertEqual(
            inv["verdict"], "needs-fuzz",
            f"Wrong invariant verdict: {inv['verdict']}"
        )

    def test_invariant_source(self):
        inv = self.invs[0]
        self.assertEqual(inv["source"], "SIDL")


class TestSolPlainTransfer(unittest.TestCase):
    """Plain safeTransfer with no share minting -> 0 hypotheses."""

    def setUp(self):
        self.hyps, self.invs = sidl.hypotheses_from_source(
            source=SOL_TRANSFER_SRC,
            language="sol",
            fn_name="sendTokens",
            file_rel="Router.sol",
        )

    def test_zero_hypotheses(self):
        self.assertEqual(
            len(self.hyps), 0,
            f"Expected 0 hypotheses for plain transfer; got {self.hyps}"
        )

    def test_zero_invariants(self):
        self.assertEqual(
            len(self.invs), 0,
            f"Expected 0 invariant specs for plain transfer; got {self.invs}"
        )


class TestSolProtectedVault(unittest.TestCase):
    """Deposit WITH _decimalsOffset virtualShares mitigation -> 0 hypotheses."""

    def setUp(self):
        self.hyps, self.invs = sidl.hypotheses_from_source(
            source=SOL_PROTECTED_SRC,
            language="sol",
            fn_name="deposit",
            file_rel="SafeVault.sol",
        )

    def test_zero_hypotheses(self):
        self.assertEqual(
            len(self.hyps), 0,
            f"Expected 0 hypotheses when mitigation present; got {self.hyps}"
        )


class TestGoShareMint(unittest.TestCase):
    """Go AddLiquidity with MulDiv(totalSupply, totalAssets) + MintCoins -> flagged."""

    def setUp(self):
        self.hyps, self.invs = sidl.hypotheses_from_source(
            source=GO_SHARE_MINT_SRC,
            language="go",
            fn_name="AddLiquidity",
            file_rel="keeper.go",
        )

    def test_hypotheses_emitted(self):
        self.assertGreater(
            len(self.hyps), 0,
            f"Expected >=1 hypothesis for Go share-mint; got 0"
        )

    def test_donation_class_present(self):
        classes = _attack_classes(self.hyps)
        self.assertIn(
            "share-inflation-donation", classes,
            f"Missing donation hypothesis for Go; classes={classes}"
        )

    def test_first_depositor_class_present(self):
        classes = _attack_classes(self.hyps)
        self.assertIn(
            "share-inflation-first-depositor", classes,
            f"Missing first-depositor hypothesis for Go; classes={classes}"
        )

    def test_all_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz", f"Wrong verdict: {h}")


class TestRustShareMint(unittest.TestCase):
    """Rust deposit with mul_div(total_supply, total_assets) + mint_to -> flagged."""

    def setUp(self):
        self.hyps, self.invs = sidl.hypotheses_from_source(
            source=RS_SHARE_MINT_SRC,
            language="rs",
            fn_name="deposit",
            file_rel="contract.rs",
        )

    def test_hypotheses_emitted(self):
        self.assertGreater(
            len(self.hyps), 0,
            f"Expected >=1 hypothesis for Rust share-mint; got 0"
        )

    def test_donation_class_present(self):
        classes = _attack_classes(self.hyps)
        self.assertIn(
            "share-inflation-donation", classes,
            f"Missing donation hypothesis for Rust; classes={classes}"
        )

    def test_first_depositor_class_present(self):
        classes = _attack_classes(self.hyps)
        self.assertIn(
            "share-inflation-first-depositor", classes,
            f"Missing first-depositor hypothesis for Rust; classes={classes}"
        )

    def test_all_needs_fuzz(self):
        for h in self.hyps:
            self.assertEqual(h["verdict"], "needs-fuzz", f"Wrong verdict: {h}")


class TestVerdictAndSourceInvariant(unittest.TestCase):
    """Every emitted hypothesis must carry verdict='needs-fuzz' and source='SIDL'."""

    def _all_hyps(self):
        hyps = []
        hyps += sidl.hypotheses_from_source(SOL_DEPOSIT_SRC, "sol", "deposit")[0]
        hyps += sidl.hypotheses_from_source(GO_SHARE_MINT_SRC, "go", "AddLiquidity")[0]
        hyps += sidl.hypotheses_from_source(RS_SHARE_MINT_SRC, "rs", "deposit")[0]
        return hyps

    def test_all_verdict_needs_fuzz(self):
        for h in self._all_hyps():
            self.assertEqual(
                h["verdict"], "needs-fuzz",
                f"Hypothesis has wrong verdict '{h['verdict']}': {h}"
            )

    def test_all_source_sidl(self):
        for h in self._all_hyps():
            self.assertEqual(
                h["source"], "SIDL",
                f"Wrong source in: {h}"
            )

    def test_no_em_dash_in_any_field(self):
        result = _no_dashes(self._all_hyps())
        self.assertIsNone(result, f"Dash found: {result}")

    def test_attack_class_is_valid(self):
        valid = {"share-inflation-donation", "share-inflation-first-depositor"}
        for h in self._all_hyps():
            self.assertIn(
                h["attack_class"], valid,
                f"Unknown attack_class '{h['attack_class']}': {h}"
            )


class TestSchemaCompleteness(unittest.TestCase):
    """Every hypothesis must have all required schema keys."""

    _REQUIRED_HYPOTHESIS_KEYS = {
        "workspace", "file", "function", "language",
        "attack_class", "source", "verdict", "note",
        "mint_evidence", "ratio_evidence", "vcis_miss_reason",
        "suggested_invariant",
    }

    _REQUIRED_INVARIANT_KEYS = {
        "workspace", "file", "function", "language",
        "invariant_id", "invariant_class", "invariant_text",
        "fuzz_property", "mitigations_absent", "source", "verdict",
    }

    def test_hypothesis_schema(self):
        hyps, _ = sidl.hypotheses_from_source(SOL_DEPOSIT_SRC, "sol", "deposit")
        self.assertGreater(len(hyps), 0, "No hypotheses to check schema against")
        for h in hyps:
            for key in self._REQUIRED_HYPOTHESIS_KEYS:
                self.assertIn(key, h, f"Missing required key '{key}' in hypothesis: {h}")

    def test_invariant_schema(self):
        _, invs = sidl.hypotheses_from_source(SOL_DEPOSIT_SRC, "sol", "deposit")
        self.assertGreater(len(invs), 0, "No invariant specs to check schema against")
        for inv in invs:
            for key in self._REQUIRED_INVARIANT_KEYS:
                self.assertIn(key, inv, f"Missing required key '{key}' in invariant: {inv}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
