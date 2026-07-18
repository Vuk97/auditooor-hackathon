// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function calc_withdraw_one_coin(uint256, int128) external view returns (uint256);
    function remove_liquidity_one_coin(uint256, int128, uint256) external returns (uint256);
}

contract CurveCloseVuln {
    ICurvePool public pool;
    function closePosition(uint256 lp, int128 i) external returns (uint256) {
        uint256 expected = pool.calc_withdraw_one_coin(lp, i);
        return pool.remove_liquidity_one_coin(lp, i, expected);
    }
}
