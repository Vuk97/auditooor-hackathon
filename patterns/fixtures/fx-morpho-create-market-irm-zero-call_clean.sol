// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed createMarket — guards IRM call with zero-address check.
// Source: morpho-org/morpho-blue@b9fe01c (post-cantina fix)

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

    // FIXED: only call IRM if irm is a real address
    function createMarket(MarketParams memory marketParams) external {
        bytes32 id = keccak256(abi.encode(marketParams));
        require(lastUpdate[id] == 0, "already created");

        lastUpdate[id] = uint128(block.timestamp);
        idToMarketParams[id] = marketParams;

        // FIXED: skip call when irm == address(0)
        if (marketParams.irm != address(0)) {
            IIrm(marketParams.irm).borrowRate(abi.encode(marketParams), "");
        }
    }
}
