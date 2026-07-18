// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RecipientValidationClean {
    IERC20Like public immutable asset;
    mapping(address => uint256) public credit;
    mapping(bytes32 => address) public orderOwner;

    error InvalidRecipient();

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function depositFor(address receiver, uint256 amount) external {
        if (receiver == address(0) || receiver == address(this)) {
            revert InvalidRecipient();
        }
        asset.transferFrom(msg.sender, address(this), amount);
        credit[receiver] += amount;
    }

    function claimPayout(address recipient, uint256 amount) external {
        if (recipient == address(0) || recipient == address(this)) {
            revert InvalidRecipient();
        }
        credit[msg.sender] -= amount;
        asset.transfer(recipient, amount);
    }

    function createOrder(address account, bytes32 orderId) external {
        if (account != msg.sender) {
            revert InvalidRecipient();
        }
        orderOwner[orderId] = account;
    }
}
