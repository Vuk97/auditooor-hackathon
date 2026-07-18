// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: createMarket calls IRM even when irm == address(0), causing revert for zero-IRM markets.
// Source: morpho-org/morpho-blue@b9fe01c (post-cantina fix)
// Vulnerability: Morpho supports markets with irm == address(0) (fixed-rate / zero-interest markets).
// Without the guard, createMarket always calls IIrm(address(0)).borrowRate(...), which reverts
// (call to address 0 returns failure), making zero-IRM markets impossible to create.

interface IIrm {
    function borrowRate(bytes calldata marketParams, bytes calldata market) external returns (uint256);
}

contract Fix {
    struct MarketParams {
        address irm;
        address loanToken;
        address collateralToken;
    }

    mapping(bytes32 => MarketParams) public idToMarketParams;
    mapping(bytes32 => uint128) public lastUpdate;

    // VULNERABLE: calls IRM even when irm == address(0), always reverts for zero-IRM markets
    function createMarket(MarketParams memory marketParams) external {
        bytes32 id = keccak256(abi.encode(marketParams));
        require(lastUpdate[id] == 0, "already created");

        lastUpdate[id] = uint128(block.timestamp);
        idToMarketParams[id] = marketParams;

        // BUG: if marketParams.irm == address(0) this call reverts
        IIrm(marketParams.irm).borrowRate(abi.encode(marketParams), "");
    }
}
