// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external view returns (int56[] memory tickCumulatives, uint160[] memory);
}

// CLEAN: enforces minimum TWAP window of 1800 seconds (30 minutes)
contract TWAPOracleClean {
    IUniswapV3Pool public pool;
    uint32 public twapWindow;
    uint32 public constant MIN_TWAP_WINDOW = 1800; // 30 minutes minimum

    constructor(address _pool, uint32 _window) {
        require(_window >= MIN_TWAP_WINDOW, "window too short");
        pool = IUniswapV3Pool(_pool);
        twapWindow = _window;
    }

    // CLEAN: minimum window enforced, not manipulable in a single block
    function consult() external view returns (int24 timeWeightedTick) {
        require(twapWindow >= MIN_TWAP_WINDOW, "window too short");
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapWindow;
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
        int56 delta = tickCumulatives[1] - tickCumulatives[0];
        timeWeightedTick = int24(delta / int56(int32(twapWindow)));
    }
}
