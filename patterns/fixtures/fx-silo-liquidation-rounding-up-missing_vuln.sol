// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — valueToAssetsByRatio uses floor division.
// Source: silo-finance/silo-contracts-v2@3cc2f54

contract PartialLiquidationLib {
    error UnknownRatio();

    // VULNERABLE: floor division → 1-wei value with totalAssets < totalValue returns 0
    function valueToAssetsByRatio(
        uint256 _value,
        uint256 _totalAssets,
        uint256 _totalValue
    ) internal pure returns (uint256 assets) {
        require(_totalValue != 0, UnknownRatio());
        assets = _value * _totalAssets / _totalValue; // floor — can be 0 for dust
    }
}
