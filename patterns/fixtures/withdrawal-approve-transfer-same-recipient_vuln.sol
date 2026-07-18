// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract WithdrawalApproveTransferSameRecipientVuln {
    IERC20 public token;
    mapping(address => uint256) public claimable;

    function setClaim(address user, uint256 amount) external {
        claimable[user] = amount;
    }

    function claim() external {
        uint256 amount = claimable[msg.sender];
        claimable[msg.sender] = 0;

        token.approve(msg.sender, amount);
        token.transfer(msg.sender, amount);
    }
}
