// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: Curve integration that (a) forwards a caller-supplied _minOut to
// the pool call and (b) enforces `require(received >= minOut)` after the
// call. The negative guard regex on the pattern should see the slippage
// check and suppress the match.

interface ICurvePool {
    function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external returns (uint256);
    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount) external returns (uint256);
    function remove_liquidity_one_coin(uint256 token_amount, int128 i, uint256 min_amount) external returns (uint256);
}

contract CurveIntegrationClean {
    ICurvePool public immutable pool;

    constructor(address _pool) {
        pool = ICurvePool(_pool);
    }

    // CLEAN shape 1: exchange with caller _minOut forwarded AND a
    // post-swap require. Either alone is sufficient to suppress the match.
    function swapUsdcToUsdt(uint256 amountIn, uint256 _minOut) external returns (uint256 out) {
        out = pool.exchange(0, 1, amountIn, _minOut);
        require(out >= _minOut, "curve: min out");
        return out;
    }

    // CLEAN shape 2: add_liquidity with a forwarded minReceived parameter
    // and an explicit require.
    function depositCoins(uint256 a, uint256 b, uint256 minReceived) external returns (uint256 minted) {
        uint256[2] memory amounts = [a, b];
        minted = pool.add_liquidity(amounts, minReceived);
        require(minted >= minReceived, "curve: min mint");
    }

    // CLEAN shape 3: remove_liquidity_one_coin with forwarded min_amount
    // and a require on the return.
    function withdrawOneCoin(uint256 lpAmount, uint256 _minOut) external returns (uint256 received) {
        received = pool.remove_liquidity_one_coin(lpAmount, 0, _minOut);
        require(received >= _minOut, "curve: min received");
    }
}
