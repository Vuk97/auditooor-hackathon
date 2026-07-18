// SPDX-License-Identifier: MIT
// Fixture: oracle-atomic-front-run-manipulation — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IPyth {
    function updatePriceFeeds(bytes[] calldata updateData) external payable;
    function getPrice(bytes32 id) external view returns (int64 price, uint64 conf, int32 expo, uint256 publishTime);
}

contract LendingClean {
    IPyth public pythOracle;
    bytes32 public priceId;

    uint256 public lastPriceUpdate;
    uint256 public constant minDelayBetween = 60; // 1 minute lag between update and settlement

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address pyth, bytes32 id) {
        pythOracle = IPyth(pyth);
        priceId = id;
    }

    // Keeper-only price push, separate from settlement.
    function pushPrice(bytes[] calldata priceUpdate) external payable {
        pythOracle.updatePriceFeeds{value: msg.value}(priceUpdate);
        lastPriceUpdate = block.timestamp;
    }

    // CLEAN: liquidation consumes cached TWAP-style price AND enforces a
    // time-lag gate against lastPriceUpdate. Both `twap` token and
    // `block.timestamp - updatedAt` form are present so the
    // body_not_contains_regex predicate rejects the match.
    function liquidate(address victim) external {
        require(block.timestamp - lastPriceUpdate >= minDelayBetween, "fresh-update");
        uint256 p = getTWAP();
        require(p > 0, "bad-price");
        uint256 collateralUsd = collateral[victim] * p;
        uint256 debtUsd = debt[victim] * 1e8;
        require(collateralUsd * 100 < debtUsd * 150, "healthy");
        collateral[victim] = 0;
        debt[victim] = 0;
    }

    function getTWAP() public view returns (uint256) {
        (int64 price, , , ) = pythOracle.getPrice(priceId);
        return uint256(uint64(price));
    }
}
