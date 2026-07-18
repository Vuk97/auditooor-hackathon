// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IUniswapV3Pool {
    function slot0()
        external
        view
        returns (uint160 sqrtPriceX96, int24 tick, uint16, uint16, uint16, uint8, bool);
}

contract PerpRangeReallocatorPositive {
    IUniswapV3Pool public pool;
    int24 public tickLower;
    int24 public tickUpper;

    function reallocate() external {
        (, int24 currentTick, , , , , ) = pool.slot0();
        bool outOfRange = currentTick < tickLower || currentTick > tickUpper;
        if (outOfRange) {
            _repositionLiquidity(currentTick);
        }
    }

    function _repositionLiquidity(int24 nextTick) internal pure {
        nextTick;
    }
}
