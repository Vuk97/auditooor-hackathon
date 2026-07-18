// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external view returns (int56[] memory tickCumulatives, uint160[] memory);
}

// VULN: TWAP window = 60 seconds — insufficient for manipulation resistance
// Loss ref: Indexed Finance ~$16M, October 2021
// https://rekt.news/indexed-finance-rekt/
contract TWAPOracleVuln {
    IUniswapV3Pool public pool;
    uint32 public twapWindow = 60; // 60 seconds — dangerously short, no min enforced

    constructor(address _pool) { pool = IUniswapV3Pool(_pool); }

    // VULN: uses 60s window with no minimum enforcement
    function consult() external view returns (int24 timeWeightedTick) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapWindow; // 60 — manipulable in ~2 blocks
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int56 delta = tickCumulatives[1] - tickCumulatives[0];
        timeWeightedTick = int24(delta / int56(int32(twapWindow)));
    }
}
