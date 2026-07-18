// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// twap-window-too-short detector. DO NOT DEPLOY.
///
/// Uses a 60-second TWAP window. A flashloan-sized swap in the observed
/// Uniswap pool can move the spot price enough that even after the 1-minute
/// average the oracle still diverges materially from the honest mid-price,
/// letting an attacker mint under-collateralized debt or liquidate honest
/// positions at a manipulated valuation.
interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory, uint160[] memory);
}

contract ShortTwapOracleVuln {
    IUniswapV3Pool public pool;
    uint32 public constant TWAP_PERIOD = 60;

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    // VULN: hardcoded 60-second TWAP — flashloan-manipulable.
    function getTwapTick() external view returns (int24) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        int56 diff = tickCumulatives[1] - tickCumulatives[0];
        return int24(diff / int56(int32(TWAP_PERIOD)));
    }

    // Second surface: direct observe([0, 60]) literal — also short-window.
    function getTwapInline() external view returns (int56) {
        uint32[] memory s = new uint32[](2);
        s[0] = 0;
        s[1] = 60;
        (int56[] memory t, ) = pool.observe(s);
        return t[1] - t[0];
    }
}
