#!/usr/bin/env python3
"""Unit tests for tools/mev-ordering-lane.py (MOL).

Coverage matrix
---------------
Test groups:

1.  SOL_AMM_UNPROTECTED       - Solidity swap using getReserves(), no slippage bound,
                                 no deadline -> MUST flag >= 1 hypothesis.
2.  SOL_AMM_PROTECTED_MINOUT  - Same swap structure WITH minAmountOut param and
                                 deadline -> 0 hypotheses (protected).
3.  SOL_AMM_PROTECTED_TWAP    - Swap with TWAP consult() -> 0 hypotheses (protected).
4.  SOL_FIXED_TICK            - Solidity function using offer.tick / tickToPrice()
                                 (fixed-price orderbook) -> 0 hypotheses (not ordering-sensitive).
5.  SOL_SLOT0_UNPROTECTED     - Uniswap V3 slot0() read, no protection -> MUST flag.
6.  SOL_SLOT0_DEADLINE        - Same slot0 read WITH deadline -> 0 hypotheses.
7.  GO_MARKET_PRICE_UNPROTECTED - Go Cosmos fn calling GetMarkPrice() with no slippage
                                   protection -> MUST flag.
8.  GO_MARKET_PRICE_PROTECTED  - Same fn WITH MinAmountOut -> 0 hypotheses (protected).
9.  RS_COMPUTE_SWAP_UNPROTECTED - Rust fn calling compute_swap(), no slippage
                                   -> MUST flag.
10. RS_COMPUTE_SWAP_PROTECTED   - Same fn WITH min_amount_out -> 0 hypotheses.
11. RS_SPOT_PRICE_UNPROTECTED   - Rust fn calling spot_price() -> MUST flag.
12. SOL_GETAMOUNTOUT_UNPROTECTED - Solidity fn calling getAmountOut() no protection
                                    -> MUST flag.

Invariant checks (ALL groups)
------------------------------
- Every emitted hypothesis has verdict="needs-fuzz"
- Every emitted hypothesis has attack_class="sandwich-front-run-ordering"
- Every emitted hypothesis has source="MOL"
- Every emitted hypothesis has protection_check="UNPROTECTED"
- No em-dash (U+2014, U+2013) in any string field
- sensitive_read_site field is "<file>:<line>"
- fuzz_oracle_hint is non-empty on every emitted record
- generic_no_literals: no workspace-specific literals; all patterns are generic regex
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load MOL module.
# ---------------------------------------------------------------------------
_MOL_PATH = Path(__file__).resolve().parent.parent / "mev-ordering-lane.py"
_MOL_MOD_NAME = "mev_ordering_lane"


def _load_mol():
    spec = importlib.util.spec_from_file_location(_MOL_MOD_NAME, _MOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MOL_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


mol = _load_mol()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(source: str, lang: str, fn_name: str) -> list[dict]:
    return mol.detect_ordering_sensitive(
        source=source,
        language=lang,
        fn_name=fn_name,
        file_rel=f"fixture_{fn_name}.{lang}",
        ws_abs="/tmp/mol_test_ws",
    )


def _assert_invariants(tc: unittest.TestCase, results: list[dict]) -> None:
    """Check all cross-cutting invariants on emitted records."""
    em_dash = "—"
    en_dash = "–"
    for r in results:
        tc.assertEqual(r["verdict"], "needs-fuzz", f"verdict must be needs-fuzz: {r}")
        tc.assertEqual(r["attack_class"], "sandwich-front-run-ordering",
                       f"attack_class must be sandwich-front-run-ordering: {r}")
        tc.assertEqual(r["source"], "MOL", f"source must be MOL: {r}")
        tc.assertEqual(r["protection_check"], "UNPROTECTED",
                       f"protection_check must be UNPROTECTED: {r}")
        site = r.get("sensitive_read_site", "")
        tc.assertIn(":", site, f"sensitive_read_site must contain ':': {r}")
        tc.assertTrue(r.get("fuzz_oracle_hint", ""), f"fuzz_oracle_hint must be non-empty: {r}")
        # No em-dash / en-dash in any string field.
        for k, v in r.items():
            if isinstance(v, str):
                tc.assertNotIn(em_dash, v, f"em-dash in field '{k}': {r}")
                tc.assertNotIn(en_dash, v, f"en-dash in field '{k}': {r}")


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

# 1 / 2 / 3: Solidity AMM swap (getReserves)
_SOL_AMM_UNPROTECTED = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }

contract BadSwap {
    IPair pair;
    IERC20 token;

    function doSwap(uint256 amountIn, address to) external {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 amountOut = amountIn * uint256(r1) / uint256(r0);
        token.transfer(to, amountOut);
    }
}
"""

_SOL_AMM_PROTECTED_MINOUT = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }

contract GoodSwap {
    IPair pair;
    IERC20 token;

    function doSwap(uint256 amountIn, uint256 minAmountOut, uint256 deadline, address to) external {
        require(block.timestamp <= deadline, "expired");
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 amountOut = amountIn * uint256(r1) / uint256(r0);
        require(amountOut >= minAmountOut, "slippage");
        token.transfer(to, amountOut);
    }
}
"""

_SOL_AMM_PROTECTED_TWAP = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IOracleLib { function consult(address pool, uint32 secondsAgo) external view returns (uint256); }

contract TwapSwap {
    IOracleLib oracle;
    IERC20 token;

    function doSwap(uint256 amountIn, address to) external {
        uint256 price = oracle.consult(address(this), 1800);
        uint256 amountOut = amountIn * price / 1e18;
        token.transfer(to, amountOut);
    }
}
"""

# 4: Fixed-tick orderbook (morpho-midnight style)
_SOL_FIXED_TICK = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }

library TickLib {
    function tickToPrice(int24 tick) internal pure returns (uint256) {
        return uint256(int256(tick));
    }
}

struct Offer { int24 tick; uint256 amount; }

contract FixedTickBook {
    IERC20 collateral;

    function take(Offer memory offer, uint256 collateralAmount) external {
        uint256 offerPrice = TickLib.tickToPrice(offer.tick);
        uint256 creditAmount = collateralAmount * offerPrice / 1e18;
        collateral.transfer(msg.sender, creditAmount);
    }
}
"""

# 5 / 6: Uniswap V3 slot0
_SOL_SLOT0_UNPROTECTED = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IPool { function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 obs, uint16 obsCard, uint16 obsCardNext, uint8 feeProto, bool unlocked); }

contract V3BadSwap {
    IPool pool;
    IERC20 token;

    function swapAtSpot(uint256 amountIn, address to) external {
        (uint160 sqrtPriceX96,,,,,, ) = pool.slot0();
        uint256 price = uint256(sqrtPriceX96) ** 2 / (1 << 192);
        uint256 amountOut = amountIn * price / 1e18;
        token.transfer(to, amountOut);
    }
}
"""

_SOL_SLOT0_DEADLINE = """
pragma solidity ^0.8.0;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
interface IPool { function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 obs, uint16 obsCard, uint16 obsCardNext, uint8 feeProto, bool unlocked); }

contract V3GoodSwap {
    IPool pool;
    IERC20 token;

    function swapAtSpot(uint256 amountIn, uint256 minAmountOut, uint256 deadline, address to) external {
        require(block.timestamp <= deadline, "expired");
        (uint160 sqrtPriceX96,,,,,, ) = pool.slot0();
        uint256 price = uint256(sqrtPriceX96) ** 2 / (1 << 192);
        uint256 amountOut = amountIn * price / 1e18;
        require(amountOut >= minAmountOut, "slippage");
        token.transfer(to, amountOut);
    }
}
"""

# 7 / 8: Go Cosmos market order
_GO_MARK_UNPROTECTED = """
package exchange

func (k Keeper) ExecuteMarketOrder(ctx sdk.Context, order Order) error {
    markPrice, err := k.GetMarkPrice(ctx, order.MarketId)
    if err != nil {
        return err
    }
    value := order.Quantity.Mul(markPrice)
    return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, order.Maker, sdk.NewCoin("usdt", value.TruncateInt()))
}
"""

_GO_MARK_PROTECTED = """
package exchange

func (k Keeper) ExecuteMarketOrder(ctx sdk.Context, order Order, MinAmountOut sdk.Dec) error {
    markPrice, err := k.GetMarkPrice(ctx, order.MarketId)
    if err != nil {
        return err
    }
    value := order.Quantity.Mul(markPrice)
    if value.LT(MinAmountOut) {
        return types.ErrSlippageExceeded
    }
    return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, order.Maker, sdk.NewCoin("usdt", value.TruncateInt()))
}
"""

# 9 / 10: Rust compute_swap
_RS_COMPUTE_UNPROTECTED = """
pub fn execute_swap(deps: DepsMut, env: Env, amount_in: Uint128) -> Result<Response, ContractError> {
    let pool_state = POOL_STATE.load(deps.storage)?;
    let amount_out = compute_swap(&pool_state, amount_in)?;
    let transfer_msg = BankMsg::Send {
        to_address: env.contract.address.to_string(),
        amount: coins(amount_out.u128(), "utoken"),
    };
    Ok(Response::new().add_message(transfer_msg))
}
"""

_RS_COMPUTE_PROTECTED = """
pub fn execute_swap(deps: DepsMut, env: Env, amount_in: Uint128, min_amount_out: Uint128) -> Result<Response, ContractError> {
    let pool_state = POOL_STATE.load(deps.storage)?;
    let amount_out = compute_swap(&pool_state, amount_in)?;
    if amount_out < min_amount_out {
        return Err(ContractError::Slippage {});
    }
    let transfer_msg = BankMsg::Send {
        to_address: env.contract.address.to_string(),
        amount: coins(amount_out.u128(), "utoken"),
    };
    Ok(Response::new().add_message(transfer_msg))
}
"""

# 11: Rust spot_price unprotected
_RS_SPOT_UNPROTECTED = """
pub fn execute_trade(deps: DepsMut, env: Env, amount: Uint128) -> Result<Response, ContractError> {
    let pool = POOL.load(deps.storage)?;
    let price = spot_price(&pool);
    let out = amount * price;
    let msg = BankMsg::Send {
        to_address: "recipient".to_string(),
        amount: coins(out.u128(), "base"),
    };
    Ok(Response::new().add_message(msg))
}
"""

# 12: Solidity getAmountOut unprotected
_SOL_GETAMOUNTOUT_UNPROTECTED = """
pragma solidity ^0.8.0;
interface IRouter { function getAmountOut(uint256 amountIn, address tokenIn, address tokenOut) external view returns (uint256); }
interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract RouterSwap {
    IRouter router;
    IERC20 token;

    function swapTokens(uint256 amountIn, address tokenIn, address tokenOut, address to) external {
        uint256 amountOut = router.getAmountOut(amountIn, tokenIn, tokenOut);
        token.transfer(to, amountOut);
    }
}
"""


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestMOLSolidityAMM(unittest.TestCase):

    def test_sol_amm_unprotected_flags(self):
        """getReserves() with no slippage bound or deadline -> at least 1 hypothesis."""
        results = _run(_SOL_AMM_UNPROTECTED, "sol", "doSwap")
        self.assertGreater(len(results), 0, "expected >= 1 hypothesis for unprotected AMM swap")
        _assert_invariants(self, results)

    def test_sol_amm_protected_minout_zero(self):
        """getReserves() WITH minAmountOut + deadline -> 0 hypotheses."""
        results = _run(_SOL_AMM_PROTECTED_MINOUT, "sol", "doSwap")
        self.assertEqual(len(results), 0, f"expected 0 hypotheses for protected swap, got: {results}")

    def test_sol_amm_protected_twap_zero(self):
        """TWAP consult() present -> 0 hypotheses."""
        results = _run(_SOL_AMM_PROTECTED_TWAP, "sol", "doSwap")
        self.assertEqual(len(results), 0, f"expected 0 for TWAP-guarded swap, got: {results}")


class TestMOLSolidityFixedTick(unittest.TestCase):

    def test_sol_fixed_tick_zero(self):
        """Fixed-tick orderbook (offer.tick / tickToPrice) -> 0 hypotheses (not ordering-sensitive)."""
        results = _run(_SOL_FIXED_TICK, "sol", "take")
        self.assertEqual(len(results), 0,
                         f"fixed-tick function must not be flagged, got: {results}")


class TestMOLSoliditySlot0(unittest.TestCase):

    def test_sol_slot0_unprotected_flags(self):
        """Uniswap V3 slot0() with no protection -> at least 1 hypothesis."""
        results = _run(_SOL_SLOT0_UNPROTECTED, "sol", "swapAtSpot")
        self.assertGreater(len(results), 0, "expected >= 1 hypothesis for unprotected slot0 swap")
        _assert_invariants(self, results)

    def test_sol_slot0_with_deadline_and_minout_zero(self):
        """slot0() WITH minAmountOut + deadline -> 0 hypotheses."""
        results = _run(_SOL_SLOT0_DEADLINE, "sol", "swapAtSpot")
        self.assertEqual(len(results), 0, f"expected 0 for protected slot0 swap, got: {results}")


class TestMOLGoCosmosMarkPrice(unittest.TestCase):

    def test_go_mark_price_unprotected_flags(self):
        """GetMarkPrice() with no MinAmountOut -> at least 1 hypothesis."""
        results = _run(_GO_MARK_UNPROTECTED, "go", "ExecuteMarketOrder")
        self.assertGreater(len(results), 0, "expected >= 1 hypothesis for unprotected Go market order")
        _assert_invariants(self, results)

    def test_go_mark_price_protected_zero(self):
        """GetMarkPrice() WITH MinAmountOut check -> 0 hypotheses."""
        results = _run(_GO_MARK_PROTECTED, "go", "ExecuteMarketOrder")
        self.assertEqual(len(results), 0, f"expected 0 for protected Go market order, got: {results}")


class TestMOLRustComputeSwap(unittest.TestCase):

    def test_rs_compute_swap_unprotected_flags(self):
        """compute_swap() with no min_amount_out -> at least 1 hypothesis."""
        results = _run(_RS_COMPUTE_UNPROTECTED, "rs", "execute_swap")
        self.assertGreater(len(results), 0, "expected >= 1 hypothesis for unprotected Rust compute_swap")
        _assert_invariants(self, results)

    def test_rs_compute_swap_protected_zero(self):
        """compute_swap() WITH min_amount_out -> 0 hypotheses."""
        results = _run(_RS_COMPUTE_PROTECTED, "rs", "execute_swap")
        self.assertEqual(len(results), 0, f"expected 0 for protected Rust swap, got: {results}")

    def test_rs_spot_price_unprotected_flags(self):
        """spot_price() with no protection -> at least 1 hypothesis."""
        results = _run(_RS_SPOT_UNPROTECTED, "rs", "execute_trade")
        self.assertGreater(len(results), 0, "expected >= 1 hypothesis for unprotected Rust spot_price")
        _assert_invariants(self, results)


class TestMOLGetAmountOut(unittest.TestCase):

    def test_sol_getamountout_unprotected_flags(self):
        """getAmountOut() with no slippage bound -> at least 1 hypothesis."""
        results = _run(_SOL_GETAMOUNTOUT_UNPROTECTED, "sol", "swapTokens")
        self.assertGreater(len(results), 0, "expected >= 1 hypothesis for unprotected getAmountOut")
        _assert_invariants(self, results)


class TestMOLNeedsFuzzOnly(unittest.TestCase):
    """ALL emitted hypotheses must be needs-fuzz (no auto-confirmed findings)."""

    def _collect_all(self) -> list[dict]:
        out = []
        for src, lang, fn in [
            (_SOL_AMM_UNPROTECTED, "sol", "doSwap"),
            (_SOL_SLOT0_UNPROTECTED, "sol", "swapAtSpot"),
            (_GO_MARK_UNPROTECTED, "go", "ExecuteMarketOrder"),
            (_RS_COMPUTE_UNPROTECTED, "rs", "execute_swap"),
            (_RS_SPOT_UNPROTECTED, "rs", "execute_trade"),
            (_SOL_GETAMOUNTOUT_UNPROTECTED, "sol", "swapTokens"),
        ]:
            out.extend(_run(src, lang, fn))
        return out

    def test_all_verdict_needs_fuzz(self):
        for r in self._collect_all():
            self.assertEqual(r["verdict"], "needs-fuzz",
                             f"all hypotheses must be needs-fuzz, got {r['verdict']}")

    def test_no_em_dash_in_any_field(self):
        em = "—"
        en = "–"
        for r in self._collect_all():
            for k, v in r.items():
                if isinstance(v, str):
                    self.assertNotIn(em, v, f"em-dash in field '{k}'")
                    self.assertNotIn(en, v, f"en-dash in field '{k}'")

    def test_attack_class_constant(self):
        for r in self._collect_all():
            self.assertEqual(r["attack_class"], "sandwich-front-run-ordering")

    def test_source_mol(self):
        for r in self._collect_all():
            self.assertEqual(r["source"], "MOL")

    def test_fuzz_oracle_hint_nonempty(self):
        for r in self._collect_all():
            self.assertTrue(r.get("fuzz_oracle_hint"), "fuzz_oracle_hint must be non-empty")

    def test_read_site_has_colon(self):
        for r in self._collect_all():
            self.assertIn(":", r.get("sensitive_read_site", ""),
                          "sensitive_read_site must be file:line")


class TestMOLGenericNoLiterals(unittest.TestCase):
    """Verify patterns are generic regex, not workspace-specific hardcoded strings."""

    def test_no_workspace_specific_literals(self):
        """MOL patterns must not contain paths or workspace-specific contract names."""
        import re as _re
        src = Path(__file__).resolve().parent.parent / "mev-ordering-lane.py"
        text = src.read_text()
        # Must not reference real audit paths
        banned = [
            "/Users/wolf/audits/",
            "beanstalk",
            "morpho",
            "Midnight",
            "Basin",
            "Well.sol",
        ]
        for term in banned:
            self.assertNotIn(term, text, f"workspace literal '{term}' found in MOL source")


if __name__ == "__main__":
    unittest.main(verbosity=2)
