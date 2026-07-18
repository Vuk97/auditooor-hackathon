// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ThirdPartyDebtMutationVulnerable {
    IERC20Like public immutable asset;
    mapping(address => uint256) public debtOf;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function drawCreditFor(address borrower, uint256 amount) external {
        debtOf[borrower] += amount;
        require(asset.transfer(msg.sender, amount), "transfer failed");
    }
}
