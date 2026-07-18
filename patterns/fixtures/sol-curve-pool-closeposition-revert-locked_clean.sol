// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function calc_withdraw_one_coin(uint256, int128) external view returns (uint256);
    function remove_liquidity_one_coin(uint256, int128, uint256) external returns (uint256);
}

contract CurveCloseClean {
    ICurvePool public pool;
    uint256 public constant SLIPPAGE_BPS = 50; // 0.5%
    function closePosition(uint256 lp, int128 i) external returns (uint256) {
        uint256 expected = pool.calc_withdraw_one_coin(lp, i);
        uint256 minAmount = expected * (10000 - SLIPPAGE_BPS) / 10000;
        return pool.remove_liquidity_one_coin(lp, i, minAmount);
    }
}
