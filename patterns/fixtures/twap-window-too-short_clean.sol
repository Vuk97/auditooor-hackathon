// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture but uses a 30-minute (1800s) TWAP window, which is above the
/// commonly-cited manipulation-resistance floor.
interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory, uint160[] memory);
}

contract LongTwapOracleClean {
    IUniswapV3Pool public pool;
    uint32 public constant TWAP_PERIOD = 1800;

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    // CLEAN: 30-minute TWAP — well above the flashloan-manipulation floor.
    function getTwapTick() external view returns (int24) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int56 diff = tickCumulatives[1] - tickCumulatives[0];
        return int24(diff / int56(int32(TWAP_PERIOD)));
    }
}
