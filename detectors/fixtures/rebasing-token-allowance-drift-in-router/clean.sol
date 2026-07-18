// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRebasingTokenClean {
    function balanceOf(address account) external view returns (uint256);
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract RebasingTokenAllowanceDriftRouterClean {
    IRebasingTokenClean public immutable token;
    mapping(address => mapping(address => uint256)) internal _vaultAllowance;

    constructor(IRebasingTokenClean token_) {
        token = token_;
    }

    function depositAllowance(address vault, uint256 amount) external {
        uint256 actualBalance = token.balanceOf(address(this));
        _vaultAllowance[vault][address(token)] = actualBalance + amount;
        token.safeTransferFrom(msg.sender, address(this), amount);
    }
}
