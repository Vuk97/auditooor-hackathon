// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LowDecimalLiquidationAllocationClean {
    uint256 internal constant PRECISION_FACTOR_E18 = 1e18;
    uint8 internal constant COLLATERAL_DECIMALS = 6;

    function withdrawOrAllocateShares(uint256 rawCollateral, uint256 percent)
        external
        pure
        returns (uint256 cashoutShares)
    {
        uint256 product = rawCollateral * percent;
        cashoutShares = (product + PRECISION_FACTOR_E18 - 1) / PRECISION_FACTOR_E18;
    }
}
