// SPDX-License-Identifier: MIT
// Fixture: oracle-atomic-front-run-manipulation — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IPyth {
    function updatePriceFeeds(bytes[] calldata updateData) external payable;
    function getPrice(bytes32 id) external view returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

contract LendingVuln {
    // precondition: state var named like a pull-based oracle.
    IPyth public pythOracle;
    bytes32 public priceId;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address pyth, bytes32 id) {
        pythOracle = IPyth(pyth);
        priceId = id;
    }

    // VULN: attacker supplies a fresh signed price update and atomically
    // liquidates in the same transaction. No time-lag gate, no TWAP —
    // pure atomic front-run shape.
    function liquidate(address victim, bytes[] calldata priceUpdate) external payable {
        pythOracle.updatePriceFeeds{value: msg.value}(priceUpdate);
        (int64 price, , , ) = pythOracle.getPrice(priceId);
        require(price > 0, "bad-price");
        uint256 p = uint256(uint64(price));
        uint256 collateralUsd = collateral[victim] * p;
        uint256 debtUsd = debt[victim] * 1e8;
        require(collateralUsd * 100 < debtUsd * 150, "healthy");
        // atomic settlement against the just-pushed price
        collateral[victim] = 0;
        debt[victim] = 0;
    }
}
