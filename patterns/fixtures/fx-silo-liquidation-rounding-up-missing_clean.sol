// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — Math.mulDiv with Rounding.UP ensures at least 1 asset for dust positions.
// Source: silo-finance/silo-contracts-v2@3cc2f54

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract PartialLiquidationLib {
    error UnknownRatio();

    // FIXED: ceiling division ensures 1-wei value always returns at least 1 asset
    function valueToAssetsByRatio(
        uint256 _value,
        uint256 _totalAssets,
        uint256 _totalValue
    ) internal pure returns (uint256 assets) {
        require(_totalValue != 0, UnknownRatio());
        assets = Math.mulDiv(_value, _totalAssets, _totalValue, Math.Rounding.Ceil);
    }
}
