// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUnderlyingWithdrawPool {
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
}

contract WrapperRedeemConvertsAssetsClean {
    IUnderlyingWithdrawPool public immutable pool;

    constructor(IUnderlyingWithdrawPool _pool) {
        pool = _pool;
    }

    function previewRedeem(uint256 shares) public pure returns (uint256 assets) {
        return shares * 2;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = previewRedeem(shares);
        pool.withdraw(assets, receiver, owner);
    }
}
