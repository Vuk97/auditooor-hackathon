// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRebasingTokenPositive {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RebasingAllowanceDriftRouterTheftPositive {
    IRebasingTokenPositive public immutable token;
    mapping(address => uint256) public allowance;

    constructor(IRebasingTokenPositive token_) {
        token = token_;
    }

    function routerDeposit(address vault, uint256 amount) external {
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));
        token.balanceOf(address(this));

        allowance[vault] = amount;
        token.transferFrom(msg.sender, address(this), amount);
    }
}
