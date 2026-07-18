// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AmmProtocolFeeTruncatesWhenLpFeeZeroClean {
    uint256 internal constant PIPS_DENOMINATOR = 1_000_000;
    uint256 public protocolFeesAccrued;

    function quote(
        uint256 amountIn,
        uint256 feeAmount,
        uint256 protocolFee,
        uint256 swapFee
    ) external returns (uint256) {
        return swapStep(amountIn, feeAmount, protocolFee, swapFee);
    }

    function swapStep(
        uint256 amountIn,
        uint256 feeAmount,
        uint256 protocolFee,
        uint256 swapFee
    ) internal returns (uint256) {
        uint256 protocolFeeAmount;
        if (swapFee == protocolFee) {
            protocolFeeAmount = feeAmount;
        } else {
            protocolFeeAmount = (amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR;
        }
        _recordProtocolFee(protocolFeeAmount);
        return protocolFeeAmount;
    }

    function _recordProtocolFee(uint256 amount) internal {
        protocolFeesAccrued += amount;
    }
}
