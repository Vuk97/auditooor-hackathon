// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// Fixture: vulnerable — protocol fee scaled with rayDivFloor, transfer uses rounding UP.
// Source: aave-dao/aave-v3-origin@b6567d4 (Certora-12 fix)

library WadRayMath {
    uint256 constant RAY = 1e27;

    function rayDivFloor(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY) / b; // floor division
    }

    function rayDivCeil(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + b - 1) / b; // ceiling division
    }
}

contract LiquidationLogic {
    using WadRayMath for uint256;

    // VULNERABLE: floor rounding under-estimates fee shares by 1 wei in edge cases
    function _transferProtocolFee(
        address aToken,
        uint256 liquidationProtocolFeeAmount,
        uint256 liquidityIndex
    ) internal {
        // rayDivFloor may give N shares, but AToken.transfer uses ceiling → needs N+1
        uint256 scaledDownFee = liquidationProtocolFeeAmount.rayDivFloor(liquidityIndex);
        // AToken internally uses rounding UP → 1 wei mismatch causes revert
        IAToken(aToken).transferOnLiquidation(address(this), scaledDownFee);
    }
}

interface IAToken {
    function transferOnLiquidation(address treasury, uint256 scaledAmount) external;
}
