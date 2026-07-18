// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRebasingTokenClean {
    function sharesOf(address account) external view returns (uint256);
    function getPooledEthByShares(uint256 shares) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RebasingAllowanceDriftRouterTheftFixed {
    IRebasingTokenClean public immutable token;
    mapping(address => uint256) public shareQuota;

    constructor(IRebasingTokenClean token_) {
        token = token_;
    }

    function routerDeposit(address vault, uint256 amount) external {
        uint256 shares = token.sharesOf(address(this));
        uint256 pooled = token.getPooledEthByShares(shares);
        shareQuota[vault] = pooled + amount;
        token.transferFrom(msg.sender, address(this), amount);
    }
}
