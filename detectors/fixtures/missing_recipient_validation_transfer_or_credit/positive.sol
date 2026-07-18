// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RecipientValidationPositive {
    IERC20Like public immutable asset;
    mapping(address => uint256) public credit;
    mapping(bytes32 => address) public orderOwner;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function depositFor(address receiver, uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        credit[receiver] += amount;
    }

    function claimPayout(address recipient, uint256 amount) external {
        credit[msg.sender] -= amount;
        asset.transfer(recipient, amount);
    }

    function createOrder(address account, bytes32 orderId) external {
        orderOwner[orderId] = account;
    }
}
