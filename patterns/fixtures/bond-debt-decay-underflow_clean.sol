// SPDX-License-Identifier: MIT
// Fixture: bond-debt-decay-underflow — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

/// @notice Clean reproduction of the same BondBaseSDA-style market, with
/// saturating decay writes. The body contains one of the saturation
/// tokens (`Math.min`, a `? : 0` ternary, or an `if (debt >= …)` gate)
/// so the pattern's body_not_contains_regex guard fires and the
/// detector skips each function.
contract BondMarketClean {
    struct Market {
        uint256 totalDebt;
        uint256 lastDecay;
        uint256 decayInterval;
        uint256 price;
    }

    mapping(uint256 => Market) public markets;

    function openMarket(uint256 id, uint256 initialDebt, uint256 decayInterval, uint256 price) external {
        markets[id] = Market({
            totalDebt: initialDebt,
            lastDecay: block.timestamp,
            decayInterval: decayInterval,
            price: price
        });
    }

    // CLEAN: saturating subtraction via ternary floor `? 0 : lastDebt - decay`.
    function _currentDebt(uint256 id) public view returns (uint256) {
        Market memory market = markets[id];
        uint256 secondsSinceDecay = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * secondsSinceDecay) / market.decayInterval;
        uint256 lastDebt = market.totalDebt;
        return decay > lastDebt ? 0 : lastDebt - decay;
    }

    // CLEAN: Math.min saturation on the compound assign.
    function _updateDebt(uint256 id) external {
        Market storage market = markets[id];
        uint256 secondsSinceDecay = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * secondsSinceDecay) / market.decayInterval;
        uint256 applied = Math.min(market.totalDebt, decay);
        market.totalDebt -= applied;
        market.lastDecay = block.timestamp;
    }

    // CLEAN: explicit `if (debt >= decay)` precondition on the
    // decrement path.
    function _decayDebt(uint256 id, uint256 decay) external {
        Market storage market = markets[id];
        if (market.totalDebt >= decay) {
            market.totalDebt -= decay;
        } else {
            market.totalDebt = 0;
        }
    }

    function marketPrice(uint256 id) external view returns (uint256) {
        uint256 debt = _currentDebt(id);
        return markets[id].price + debt;
    }
}
