pragma solidity ^0.8.20;

contract UserConfigurationClean {
    uint256 internal bitmapData;
    uint256 internal constant MAX_RESERVES = 64;

    function setUsingAsCollateral(uint256 reserveIndex, bool useAsCollateral) external {
        require(reserveIndex < MAX_RESERVES, "invalid reserve");

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
