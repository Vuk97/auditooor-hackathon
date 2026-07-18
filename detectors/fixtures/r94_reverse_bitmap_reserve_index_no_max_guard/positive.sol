pragma solidity ^0.8.20;

contract UserConfigurationPositive {
    uint256 internal bitmapData;

    function setUsingAsCollateral(uint256 reserveIndex, bool useAsCollateral) external {
        uint256 bit = uint256(1) << (reserveIndex << 1);
        _applyBit(bit, useAsCollateral);
    }

    function _applyBit(uint256 bit, bool useAsCollateral) internal {
        if (useAsCollateral) {
            bitmapData |= bit;
        } else {
            bitmapData &= ~bit;
        }
    }
}
