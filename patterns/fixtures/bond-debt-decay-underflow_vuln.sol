// SPDX-License-Identifier: MIT
// Fixture: bond-debt-decay-underflow — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

/// @notice Minimal reproduction of cluster C0041
/// (BondBaseSDA / Olympus bond-market family). DO NOT DEPLOY.
///
/// The helper decays the bond market's totalDebt via raw subtraction
/// with no saturation floor. After a long idle period the computed
/// decay can exceed totalDebt and the function panic-reverts,
/// permanently bricking every code path that calls _currentDebt
/// (marketPrice, findMarketFor, purchaseBond, etc.).
contract BondMarketVuln {
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

    // VULN: raw `lastDebt - decay` without any saturation guard. If the
    // decay term overtakes lastDebt (long idle period, admin bumps
    // decayInterval via setDefaults, etc.) this panic-reverts on
    // underflow and the market is dead.
    function _currentDebt(uint256 id) public view returns (uint256) {
        Market memory market = markets[id];
        uint256 secondsSinceDecay = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * secondsSinceDecay) / market.decayInterval;
        uint256 lastDebt = market.totalDebt;
        return lastDebt - decay;
    }

    // VULN: same shape, compound assign form — totalDebt -= decay with
    // no floor.
    function _updateDebt(uint256 id) external {
        Market storage market = markets[id];
        uint256 secondsSinceDecay = block.timestamp - market.lastDecay;
        uint256 decay = (market.totalDebt * secondsSinceDecay) / market.decayInterval;
        market.totalDebt -= decay;
        market.lastDecay = block.timestamp;
    }

    // VULN: marketPrice cascades into _currentDebt, which reverts on
    // underflow, so every caller of marketPrice (findMarketFor,
    // purchaseBond) also dies.
    function marketPrice(uint256 id) external view returns (uint256) {
        uint256 debt = _currentDebt(id);
        return markets[id].price + debt;
    }

    function findMarketFor(uint256 id) external view returns (uint256) {
        return this.marketPrice(id);
    }
}
