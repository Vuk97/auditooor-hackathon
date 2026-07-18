// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// Fixture: fixed — protocol fee scaled with rayDivCeil to match AToken rounding direction.
// Source: aave-dao/aave-v3-origin@b6567d4 (Certora-12 fix)

library WadRayMath {
    uint256 constant RAY = 1e27;

    function rayDivFloor(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY) / b;
    }

    function rayDivCeil(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + b - 1) / b;
    }
}

contract LiquidationLogic {
    using WadRayMath for uint256;

    // FIXED: ceiling rounding matches AToken.transferOnLiquidation direction
    function _transferProtocolFee(
        address aToken,
        uint256 liquidationProtocolFeeAmount,
        uint256 liquidityIndex
    ) internal {
        // rayDivCeil ensures share count matches what AToken's rounding-UP transfer expects
        uint256 scaledDownFee = liquidationProtocolFeeAmount.rayDivCeil(liquidityIndex);
        IAToken(aToken).transferOnLiquidation(address(this), scaledDownFee);
    }
}

interface IAToken {
    function transferOnLiquidation(address treasury, uint256 scaledAmount) external;
}
