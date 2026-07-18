// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRebasingTokenPositive {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract RebasingTokenAllowanceDriftRouterPositive {
    IRebasingTokenPositive public immutable token;
    mapping(address => mapping(address => uint256)) internal _vaultAllowance;

    constructor(IRebasingTokenPositive token_) {
        token = token_;
    }

    function depositAllowance(address vault, uint256 amount) external {
        _vaultAllowance[vault][address(token)] = amount;
        token.safeTransferFrom(msg.sender, address(this), amount);
    }
}
