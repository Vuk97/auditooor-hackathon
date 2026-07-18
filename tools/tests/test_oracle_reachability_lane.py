#!/usr/bin/env python3
"""Unit tests for tools/oracle-reachability-lane.py (ORL).

Coverage matrix
---------------
SOL_RAW_RESERVES_SRC     - Solidity fn using raw getReserves() as price for
                           collateral valuation (no TWAP) -> MUST flag 1 hypothesis.

SOL_TWAP_GUARDED_SRC     - SAME function structure but wrapped with a TWAP consult()
                           call and secondsAgo -> 0 hypotheses (guarded).

SOL_CHAINLINK_STALE_SRC  - Solidity fn using latestAnswer() with no freshness check
                           -> MUST flag 1 hypothesis.

SOL_CHAINLINK_FRESH_SRC  - Solidity fn using latestRoundData() WITH updatedAt
                           staleness check -> 0 hypotheses (guarded).

SOL_IORACLE_PRICE_SRC    - Solidity fn using IOracle.price() (Morpho-style) with no
                           guard -> MUST flag 1 hypothesis.

SOL_VIEW_ONLY_SRC        - Solidity fn using .price() but the fn is a pure view with
                           no value transfer/ledger write. Note: ORL's API does not
                           gate on VMF classification here - it is the caller (run_orl)
                           that filters non-VMF fns. In the direct detect_oracle_reads
                           API the fn is examined regardless. The test verifies the
                           API emits a hypothesis - the VMF gating is a workspace-level
                           concern. This test therefore just confirms the read IS found.
                           (Updated per design: detect_oracle_reads is shape-only;
                           VMF-filter is run_orl.)

SOL_SLOT0_NO_GUARD_SRC   - Solidity fn using slot0() directly -> MUST flag 1 hypothesis.

GO_MARKER_NAV_SRC        - Go fn using GetNetAssetValue consumed in valuation -> MUST flag.

GO_GUARDED_BAND_SRC      - Go fn using GetReferencePrice WITH staleness check (MaxAge)
                           -> 0 hypotheses (guarded).

RS_PYTH_UNCHECKED_SRC    - Rust fn using get_price_unchecked() -> MUST flag 1 hypothesis.

Invariant checks
----------------
- Every emitted hypothesis has verdict="needs-fuzz"
- Every emitted hypothesis has attack_class="oracle-price-manipulation"
- Every emitted hypothesis has source="ORL"
- No em-dash (U+2014) or en-dash (U+2013) in any string field
- read_site field is "<file>:<line>"
- read_kind is non-empty string
"""
import importlib.util
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load the ORL module (hyphen-safe dynamic import).
# ---------------------------------------------------------------------------
_ORL_PATH = Path(__file__).resolve().parent.parent / "oracle-reachability-lane.py"
_ORL_MOD_NAME = "oracle_reachability_lane"


def _load_orl():
    spec = importlib.util.spec_from_file_location(_ORL_MOD_NAME, _ORL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_ORL_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


orl = _load_orl()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(source: str, lang: str, fn_name: str) -> list[dict]:
    return orl.detect_oracle_reads(
        source=source,
        language=lang,
        fn_name=fn_name,
        file_rel=f"fixture_{fn_name}.{lang}",
        ws_abs="/tmp/orl_test_ws",
    )


def _assert_invariants(tc: unittest.TestCase, hyp: dict) -> None:
    tc.assertEqual(hyp["verdict"], "needs-fuzz")
    tc.assertEqual(hyp["attack_class"], "oracle-price-manipulation")
    tc.assertEqual(hyp["source"], "ORL")
    tc.assertIn(":", hyp["read_site"])   # "<file>:<line>" format
    tc.assertTrue(hyp["read_kind"])
    # No em-dash or en-dash in any string field
    for v in hyp.values():
        if isinstance(v, str):
            tc.assertNotIn("—", v, f"em-dash found in field: {v!r}")
            tc.assertNotIn("–", v, f"en-dash found in field: {v!r}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Solidity: uses raw getReserves() as price for collateral valuation, no TWAP.
SOL_RAW_RESERVES_SRC = """\
pragma solidity ^0.8.0;

contract LendingPool {
    mapping(address => uint256) public collateralOf;

    function depositCollateral(address pair, uint256 amount) external {
        (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pair).getReserves();
        uint256 price = uint256(reserve1) * 1e18 / uint256(reserve0);
        uint256 maxDebt = amount * price / 1e18;
        collateralOf[msg.sender] += maxDebt;
        IERC20(pair).safeTransferFrom(msg.sender, address(this), amount);
    }
}
"""

# Solidity: same shape but uses TWAP consult() with secondsAgo -> guarded.
SOL_TWAP_GUARDED_SRC = """\
pragma solidity ^0.8.0;

contract LendingPool {
    mapping(address => uint256) public collateralOf;

    function depositCollateral(address pool, uint256 amount) external {
        uint32 secondsAgo = 1800;
        (int24 meanTick,) = OracleLibrary.consult(pool, secondsAgo);
        uint256 price = OracleLibrary.getQuoteAtTick(meanTick, 1e18, token0, token1);
        uint256 maxDebt = amount * price / 1e18;
        collateralOf[msg.sender] += maxDebt;
        IERC20(pool).safeTransferFrom(msg.sender, address(this), amount);
    }
}
"""

# Solidity: uses Chainlink latestAnswer() with no freshness check.
SOL_CHAINLINK_STALE_SRC = """\
pragma solidity ^0.8.0;

contract PriceConsumer {
    mapping(address => uint256) public debtOf;
    AggregatorV3Interface public feed;

    function borrow(uint256 collateral) external {
        int256 price = feed.latestAnswer();
        uint256 debt = collateral * uint256(price) / 1e8;
        debtOf[msg.sender] += debt;
        IERC20(loanToken).safeTransfer(msg.sender, debt);
    }
}
"""

# Solidity: uses latestRoundData() WITH updatedAt freshness check -> guarded.
SOL_CHAINLINK_FRESH_SRC = """\
pragma solidity ^0.8.0;

contract SafePriceConsumer {
    mapping(address => uint256) public debtOf;
    AggregatorV3Interface public feed;
    uint256 public constant MAX_DELAY = 3600;

    function borrow(uint256 collateral) external {
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(block.timestamp - updatedAt < MAX_DELAY, "stale");
        uint256 debt = collateral * uint256(price) / 1e8;
        debtOf[msg.sender] += debt;
        IERC20(loanToken).safeTransfer(msg.sender, debt);
    }
}
"""

# Solidity: uses IOracle.price() (Morpho-style), no guard.
SOL_IORACLE_PRICE_SRC = """\
pragma solidity ^0.8.0;

contract Midnight {
    struct CollateralParam { address oracle; uint256 lltv; }
    mapping(address => CollateralParam) public params;
    mapping(address => uint256) public debtOf;

    function isHealthy(address user, address token) public view returns (bool) {
        CollateralParam memory cp = params[token];
        uint256 price = IOracle(cp.oracle).price();
        uint256 maxDebt = collateralOf[user].mulDivDown(price, ORACLE_PRICE_SCALE)
                          .mulDivDown(cp.lltv, WAD);
        return debtOf[user] <= maxDebt;
    }
}
"""

# Solidity: slot0() used directly (no TWAP).
SOL_SLOT0_NO_GUARD_SRC = """\
pragma solidity ^0.8.0;

contract SpotPricing {
    mapping(address => uint256) public creditOf;

    function mint(address pool, uint256 amount) external {
        (uint160 sqrtPriceX96, , , , , , ) = IUniswapV3Pool(pool).slot0();
        uint256 price = uint256(sqrtPriceX96) ** 2 / (2**192);
        uint256 credit = amount * price / 1e18;
        creditOf[msg.sender] += credit;
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }
}
"""

# Go: marker NAV GetNetAssetValue consumed in valuation, no bounds/freshness guard.
GO_MARKER_NAV_SRC = """\
package keeper

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{}

func (k Keeper) ComputeCollateral(ctx sdk.Context, marker string, amount sdk.Int) sdk.Int {
    nav := k.GetNetAssetValue(ctx, marker)
    collateral := amount.Mul(nav)
    k.SetCollateral(ctx, collateral)
    return collateral
}
"""

# Go: GetReferencePrice WITH MaxAge check -> guarded.
GO_GUARDED_BAND_SRC = """\
package keeper

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
    "time"
)

type Keeper struct{}

func (k Keeper) GetSafePrice(ctx sdk.Context, base string) (sdk.Dec, error) {
    price := k.GetReferencePrice(ctx, base)
    if ctx.BlockTime().Sub(price.LastUpdatedTime) > MaxAge {
        return sdk.ZeroDec(), ErrStalePrice
    }
    k.bankKeeper.SendCoins(ctx, from, to, coins)
    return price.Value, nil
}
"""

# Go: order.GetPrice() called inside a value-moving fn - NOT an oracle call.
# This is the injective false-positive class: order/market struct method, NOT keeper oracle.
GO_ORDER_GETPRICE_FP_SRC = """\
package keeper

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type DerivativeKeeper struct{}

func (k DerivativeKeeper) HandleDerivativeFeeDecrease(ctx sdk.Context, orders []Order) {
    for _, order := range orders {
        feeRefund := feeRefundRate.Mul(order.GetFillable()).Mul(order.GetPrice())
        chainFormatRefund := market.NotionalToChainFormat(feeRefund)
        k.subaccount.IncrementAvailableBalanceOrBank(ctx, subaccountID, market.GetQuoteDenom(), chainFormatRefund)
    }
}
"""

# Go: oracle keeper GetPrice on oracle receiver - IS a real oracle call, should flag.
GO_ORACLE_KEEPER_GETPRICE_SRC = """\
package keeper

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type ExchangeKeeper struct{}

func (k ExchangeKeeper) ValuatePosition(ctx sdk.Context, market Market, amount sdk.Dec) sdk.Dec {
    price := k.oracleKeeper.GetPrice(ctx, market.OracleBase, market.OracleQuote)
    collateralValue := amount.Mul(price)
    k.bank.SendCoins(ctx, from, to, sdk.NewCoins(sdk.NewCoin(denom, collateralValue.TruncateInt())))
    return collateralValue
}
"""

# Rust: get_price_unchecked() - explicit skip of validation.
RS_PYTH_UNCHECKED_SRC = """\
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

pub fn execute_liquidate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    borrower: String,
) -> Result<Response, ContractError> {
    let price = PRICE_FEED.load(deps.storage)?.get_price_unchecked();
    let collateral_value = borrower_collateral * price.price as u128;
    let coins = vec![Coin { denom: DENOM.to_string(), amount: collateral_value.into() }];
    let msg = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: coins,
    };
    Ok(Response::new().add_message(msg))
}
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestORL(unittest.TestCase):

    def test_sol_raw_reserves_flagged(self):
        """Raw getReserves() as price for collateral valuation -> flagged."""
        hyps = _run(SOL_RAW_RESERVES_SRC, "sol", "depositCollateral")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for raw getReserves()")
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("uniswap-v2-spot-reserves", kinds)

    def test_sol_twap_guarded_zero(self):
        """TWAP-guarded fn (consult + secondsAgo) -> 0 hypotheses."""
        hyps = _run(SOL_TWAP_GUARDED_SRC, "sol", "depositCollateral")
        self.assertEqual(len(hyps), 0, f"Expected 0 hypotheses for TWAP-guarded fn, got {hyps}")

    def test_sol_chainlink_stale_flagged(self):
        """latestAnswer() without freshness check -> flagged."""
        hyps = _run(SOL_CHAINLINK_STALE_SRC, "sol", "borrow")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for stale latestAnswer()")
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("chainlink-latestAnswer", kinds)

    def test_sol_chainlink_fresh_zero(self):
        """latestRoundData() WITH updatedAt freshness check -> 0 hypotheses."""
        hyps = _run(SOL_CHAINLINK_FRESH_SRC, "sol", "borrow")
        self.assertEqual(len(hyps), 0, f"Expected 0 hypotheses for fresh latestRoundData(), got {hyps}")

    def test_sol_ioracle_price_flagged(self):
        """IOracle.price() with no guard on value-loss path -> flagged."""
        hyps = _run(SOL_IORACLE_PRICE_SRC, "sol", "isHealthy")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for IOracle.price()")
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("ioracle-single-price", kinds)

    def test_sol_slot0_flagged(self):
        """slot0() used directly (no TWAP) -> flagged."""
        hyps = _run(SOL_SLOT0_NO_GUARD_SRC, "sol", "mint")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for raw slot0()")
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("uniswap-v3-slot0-spot", kinds)

    def test_go_marker_nav_flagged(self):
        """Go marker NAV consumed in valuation -> flagged."""
        hyps = _run(GO_MARKER_NAV_SRC, "go", "ComputeCollateral")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for GetNetAssetValue")
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("cosmos-marker-NAV", kinds)

    def test_go_guarded_band_zero(self):
        """GetReferencePrice WITH MaxAge check -> 0 hypotheses."""
        hyps = _run(GO_GUARDED_BAND_SRC, "go", "GetSafePrice")
        self.assertEqual(len(hyps), 0, f"Expected 0 hypotheses for guarded Band price, got {hyps}")

    def test_rs_pyth_unchecked_flagged(self):
        """get_price_unchecked() -> flagged."""
        hyps = _run(RS_PYTH_UNCHECKED_SRC, "rs", "execute_liquidate")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for get_price_unchecked()")
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("pyth-rs-unchecked", kinds)

    def test_all_flagged_have_needs_fuzz(self):
        """Every emitted hypothesis across all fixture cases has verdict=needs-fuzz."""
        flagged_cases = [
            (SOL_RAW_RESERVES_SRC, "sol", "depositCollateral"),
            (SOL_CHAINLINK_STALE_SRC, "sol", "borrow"),
            (SOL_IORACLE_PRICE_SRC, "sol", "isHealthy"),
            (SOL_SLOT0_NO_GUARD_SRC, "sol", "mint"),
            (GO_MARKER_NAV_SRC, "go", "ComputeCollateral"),
            (RS_PYTH_UNCHECKED_SRC, "rs", "execute_liquidate"),
        ]
        for src, lang, fn in flagged_cases:
            with self.subTest(fn=fn, lang=lang):
                hyps = _run(src, lang, fn)
                for h in hyps:
                    self.assertEqual(
                        h["verdict"], "needs-fuzz",
                        f"{fn}: expected needs-fuzz, got {h['verdict']!r}",
                    )

    def test_no_em_dash_in_any_output(self):
        """No em-dash or en-dash in any hypothesis string field."""
        all_cases = [
            (SOL_RAW_RESERVES_SRC, "sol", "depositCollateral"),
            (SOL_TWAP_GUARDED_SRC, "sol", "depositCollateral"),
            (SOL_CHAINLINK_STALE_SRC, "sol", "borrow"),
            (SOL_CHAINLINK_FRESH_SRC, "sol", "borrow"),
            (SOL_IORACLE_PRICE_SRC, "sol", "isHealthy"),
            (SOL_SLOT0_NO_GUARD_SRC, "sol", "mint"),
            (GO_MARKER_NAV_SRC, "go", "ComputeCollateral"),
            (GO_GUARDED_BAND_SRC, "go", "GetSafePrice"),
            (RS_PYTH_UNCHECKED_SRC, "rs", "execute_liquidate"),
        ]
        for src, lang, fn in all_cases:
            hyps = _run(src, lang, fn)
            for h in hyps:
                for v in h.values():
                    if isinstance(v, str):
                        self.assertNotIn("—", v, f"em-dash in {fn}")
                        self.assertNotIn("–", v, f"en-dash in {fn}")

    def test_read_site_format(self):
        """read_site field has format '<file>:<line>'."""
        hyps = _run(SOL_RAW_RESERVES_SRC, "sol", "depositCollateral")
        self.assertTrue(hyps)
        for h in hyps:
            parts = h["read_site"].split(":")
            self.assertGreaterEqual(len(parts), 2, f"read_site malformed: {h['read_site']!r}")
            self.assertTrue(parts[-1].isdigit(), f"read_site line not an integer: {h['read_site']!r}")

    def test_go_order_getprice_not_flagged(self):
        """order.GetPrice() inside a value-moving fn -> 0 hypotheses (not an oracle call).

        Regression guard for the injective false-positive class where
        order/market struct methods named GetPrice() were matched by
        the generic GetPrice pattern.
        """
        hyps = _run(GO_ORDER_GETPRICE_FP_SRC, "go", "HandleDerivativeFeeDecrease")
        self.assertEqual(
            len(hyps), 0,
            f"order.GetPrice() must NOT be flagged as oracle read, got {hyps}",
        )

    def test_go_oracle_keeper_getprice_flagged(self):
        """oracleKeeper.GetPrice() on oracle receiver -> flagged."""
        hyps = _run(GO_ORACLE_KEEPER_GETPRICE_SRC, "go", "ValuatePosition")
        self.assertGreater(
            len(hyps), 0,
            "oracleKeeper.GetPrice() on oracle receiver should be flagged",
        )
        for h in hyps:
            _assert_invariants(self, h)
        kinds = {h["read_kind"] for h in hyps}
        self.assertIn("cosmos-oracle-generic-GetPrice", kinds)


# ---------------------------------------------------------------------------
# Sub-class fixtures
# ---------------------------------------------------------------------------

# ORACLE-DECIMAL-MISMATCH: latestRoundData() result divided by hardcoded 1e8.
# No feed.decimals() call -> must be flagged with sub_class=decimal-mismatch.
SOL_DECIMAL_MISMATCH_SRC = """\
pragma solidity ^0.8.0;

contract PriceScaler {
    mapping(address => uint256) public balances;
    AggregatorV3Interface public feed;

    function deposit(uint256 amount) external {
        (, int256 rawPrice, , , ) = feed.latestRoundData();
        uint256 price = uint256(rawPrice) * amount / 1e8;
        balances[msg.sender] += price;
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }
}
"""

# Same structure but calls feed.decimals() to obtain the scale -> NOT a mismatch.
SOL_DECIMAL_SAFE_SRC = """\
pragma solidity ^0.8.0;

contract SafeScaler {
    mapping(address => uint256) public balances;
    AggregatorV3Interface public feed;

    function deposit(uint256 amount) external {
        (, int256 rawPrice, , uint256 updatedAt, ) = feed.latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        uint8 dec = feed.decimals();
        uint256 price = uint256(rawPrice) * amount / (10 ** uint256(dec));
        balances[msg.sender] += price;
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }
}
"""

# L2-SEQUENCER-GRACE: latestRoundData on L2 without sequencerUptimeFeed check.
# Must be flagged with sub_class=l2-sequencer-grace.
SOL_L2_NO_SEQUENCER_SRC = """\
pragma solidity ^0.8.0;

contract L2Lending {
    mapping(address => uint256) public debtOf;
    AggregatorV3Interface public priceFeed;

    function borrow(uint256 collateral) external {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 debt = collateral * uint256(price);
        debtOf[msg.sender] += debt;
        IERC20(loanToken).safeTransfer(msg.sender, debt);
    }
}
"""

# Same L2 context but includes sequencerUptimeFeed + GRACE_PERIOD_TIME check.
# The body still has no staleness guard so it IS flagged - but NOT as l2-sequencer-grace.
# It should get decimal-mismatch (no 1e8 constant here either) or movable-spot.
# We test that sub_class != l2-sequencer-grace.
SOL_L2_WITH_SEQUENCER_SRC = """\
pragma solidity ^0.8.0;

contract L2LendingSafe {
    mapping(address => uint256) public debtOf;
    AggregatorV3Interface public priceFeed;
    AggregatorV2V3Interface public sequencerUptimeFeed;
    uint256 private constant GRACE_PERIOD_TIME = 3600;

    function borrow(uint256 collateral) external {
        (, int256 answer, , uint256 startedAt, ) = sequencerUptimeFeed.latestRoundData();
        bool isSequencerUp = answer == 0;
        require(isSequencerUp, "Sequencer is down");
        uint256 timeSinceUp = block.timestamp - startedAt;
        require(timeSinceUp > GRACE_PERIOD_TIME, "Grace period not over");
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        uint256 debt = collateral * uint256(price);
        debtOf[msg.sender] += debt;
        IERC20(loanToken).safeTransfer(msg.sender, debt);
    }
}
"""


# ---------------------------------------------------------------------------
# Sub-class tests
# ---------------------------------------------------------------------------

class TestORLSubClass(unittest.TestCase):

    def test_decimal_mismatch_flagged(self):
        """latestRoundData + hardcoded 1e8 scale without feed.decimals() -> decimal-mismatch."""
        hyps = _run(SOL_DECIMAL_MISMATCH_SRC, "sol", "deposit")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for decimal-mismatch fixture")
        chainlink_hyps = [h for h in hyps if h["read_kind"] == "chainlink-latestRoundData"]
        self.assertTrue(
            chainlink_hyps,
            "Expected a chainlink-latestRoundData hypothesis; got read_kinds: "
            f"{[h['read_kind'] for h in hyps]}",
        )
        for h in chainlink_hyps:
            _assert_invariants(self, h)
            self.assertEqual(
                h["sub_class"], "decimal-mismatch",
                f"Expected sub_class=decimal-mismatch, got {h['sub_class']!r}",
            )

    def test_decimal_safe_not_flagged_as_mismatch(self):
        """latestRoundData + feed.decimals() call -> NOT flagged as decimal-mismatch.

        The fixture has updatedAt staleness check so it is GUARDED entirely (0 hyps).
        The key assertion is that if any hypothesis were emitted its sub_class would
        NOT be decimal-mismatch.  We also assert 0 hyps because the guarded path wins.
        """
        hyps = _run(SOL_DECIMAL_SAFE_SRC, "sol", "deposit")
        # The fn has updatedAt -> guarded -> 0 hypotheses.
        self.assertEqual(
            len(hyps), 0,
            f"Expected 0 hypotheses for feed.decimals()-guarded fn, got {hyps}",
        )

    def test_l2_missing_sequencer_flagged(self):
        """latestRoundData on L2 without sequencerUptimeFeed -> l2-sequencer-grace."""
        hyps = _run(SOL_L2_NO_SEQUENCER_SRC, "sol", "borrow")
        self.assertGreater(len(hyps), 0, "Expected >=1 hypothesis for L2 missing sequencer check")
        chainlink_hyps = [h for h in hyps if h["read_kind"] == "chainlink-latestRoundData"]
        self.assertTrue(
            chainlink_hyps,
            "Expected a chainlink-latestRoundData hypothesis",
        )
        for h in chainlink_hyps:
            _assert_invariants(self, h)
            self.assertEqual(
                h["sub_class"], "l2-sequencer-grace",
                f"Expected sub_class=l2-sequencer-grace, got {h['sub_class']!r}",
            )

    def test_l2_with_sequencer_not_l2_sequencer_grace(self):
        """latestRoundData with sequencerUptimeFeed + GRACE_PERIOD_TIME -> not l2-sequencer-grace.

        The fixture also has updatedAt staleness check so it is fully guarded (0 hyps).
        The key property is sub_class != l2-sequencer-grace.
        """
        hyps = _run(SOL_L2_WITH_SEQUENCER_SRC, "sol", "borrow")
        # The fn has updatedAt -> fully guarded -> 0 hypotheses.
        self.assertEqual(
            len(hyps), 0,
            f"Expected 0 hypotheses for fully guarded L2 fn, got {hyps}",
        )

    def test_sub_class_field_present_on_all_hypotheses(self):
        """Every emitted hypothesis has a non-empty sub_class field."""
        all_cases = [
            (SOL_RAW_RESERVES_SRC, "sol", "depositCollateral"),
            (SOL_CHAINLINK_STALE_SRC, "sol", "borrow"),
            (SOL_IORACLE_PRICE_SRC, "sol", "isHealthy"),
            (SOL_SLOT0_NO_GUARD_SRC, "sol", "mint"),
            (GO_MARKER_NAV_SRC, "go", "ComputeCollateral"),
            (RS_PYTH_UNCHECKED_SRC, "rs", "execute_liquidate"),
            (SOL_DECIMAL_MISMATCH_SRC, "sol", "deposit"),
            (SOL_L2_NO_SEQUENCER_SRC, "sol", "borrow"),
        ]
        for src, lang, fn in all_cases:
            with self.subTest(fn=fn, lang=lang):
                hyps = _run(src, lang, fn)
                for h in hyps:
                    self.assertIn(
                        "sub_class", h,
                        f"{fn}: sub_class field missing from hypothesis",
                    )
                    self.assertTrue(
                        h["sub_class"],
                        f"{fn}: sub_class field is empty",
                    )
                    self.assertIn(
                        h["sub_class"],
                        {"movable-spot", "decimal-mismatch", "l2-sequencer-grace"},
                        f"{fn}: unknown sub_class value {h['sub_class']!r}",
                    )

    def test_amm_reads_always_movable_spot(self):
        """AMM reads (getReserves, slot0) always get sub_class=movable-spot."""
        cases = [
            (SOL_RAW_RESERVES_SRC, "sol", "depositCollateral", "uniswap-v2-spot-reserves"),
            (SOL_SLOT0_NO_GUARD_SRC, "sol", "mint", "uniswap-v3-slot0-spot"),
        ]
        for src, lang, fn, expected_kind in cases:
            with self.subTest(fn=fn):
                hyps = _run(src, lang, fn)
                amm_hyps = [h for h in hyps if h["read_kind"] == expected_kind]
                self.assertTrue(amm_hyps, f"Expected {expected_kind} hypothesis for {fn}")
                for h in amm_hyps:
                    self.assertEqual(
                        h["sub_class"], "movable-spot",
                        f"{fn} AMM read got sub_class={h['sub_class']!r} instead of movable-spot",
                    )


if __name__ == "__main__":
    unittest.main()
