// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Curve integration with no slippage / minOut protection and
// hardcoded i=0, j=1 indices. Matches the C0068 cluster shape: contract
// trusts get_dy / exchange / add_liquidity return values without a
// caller-supplied minOut, and the fixed indices break on pools whose coin
// layout differs (e.g. pools with native ETH).

interface ICurvePool {
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external returns (uint256);
    function remove_liquidity_one_coin(uint256 token_amount, int128 i, uint256 min_amount) external returns (uint256);
}

contract CurveIntegrationVuln {
    ICurvePool public immutable pool;

    constructor(address _pool) {
        pool = ICurvePool(_pool);
    }

    // VULN shape 1: exchange with hardcoded indices and min_dy = 0 — no
    // slippage protection. The absence-of-minOut regex fires.
    function swapUsdcToUsdt(uint256 amountIn) external returns (uint256 out) {
        // Quote via get_dy then trust it — no downstream require.
        uint256 expected = pool.get_dy(0, 1, amountIn);
        out = pool.exchange(0, 1, amountIn, 0);
        // No require(out >= min…) guard. Body has no _minOut / _slippage.
        return out;
    }

    // VULN shape 2: add_liquidity with min_mint_amount = 0.
    function depositCoins(uint256 a, uint256 b) external returns (uint256 minted) {
        uint256[2] memory amounts = [a, b];
        minted = pool.add_liquidity(amounts, 0);
    }

    // VULN shape 3: remove_liquidity_one_coin with min_amount = 0 and
    // hardcoded coin index 0.
    function withdrawOneCoin(uint256 lpAmount) external returns (uint256 received) {
        received = pool.remove_liquidity_one_coin(lpAmount, 0, 0);
    }
}
