// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

library OracleLibrary {
    function consult(IUniswapV3Pool pool, uint32 twapWindow) internal view returns (int24 twapTick) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapWindow;
        secondsAgos[1] = 0;
        pool.observe(secondsAgos);
        twapTick = 0;
    }
}

contract PerpRangeReallocatorClean {
    IUniswapV3Pool public pool;
    int24 public tickLower;
    int24 public tickUpper;

    function reallocate() external {
        int24 twapTick = OracleLibrary.consult(pool, 600);
        bool outOfRange = twapTick < tickLower || twapTick > tickUpper;
        if (outOfRange) {
            _repositionLiquidity(twapTick);
        }
    }

    function _repositionLiquidity(int24 nextTick) internal pure {
        nextTick;
    }
}
