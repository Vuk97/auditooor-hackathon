// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUnderlyingRedeemPool {
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}

contract WrapperRedeemPassesSharesPositive {
    IUnderlyingRedeemPool public immutable pool;

    constructor(IUnderlyingRedeemPool _pool) {
        pool = _pool;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = pool.redeem(shares, receiver, owner);
    }
}
