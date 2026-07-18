// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract WithdrawalApproveTransferSameRecipientPushOnlyClean {
    IERC20 public token;
    mapping(address => uint256) public claimable;

    function setClaim(address user, uint256 amount) external {
        claimable[user] = amount;
    }

    function claim() external {
        uint256 amount = claimable[msg.sender];
        claimable[msg.sender] = 0;

        token.transfer(msg.sender, amount);
    }
}

contract WithdrawalApproveTransferSameRecipientDifferentSpenderClean {
    IERC20 public token;
    address public operator;
    mapping(address => uint256) public claimable;

    function setClaim(address user, uint256 amount) external {
        claimable[user] = amount;
    }

    function claim() external {
        uint256 amount = claimable[msg.sender];
        claimable[msg.sender] = 0;

        token.transfer(msg.sender, amount);
        token.approve(operator, amount);
    }
}

contract WithdrawalApproveTransferSameRecipientResetClean {
    IERC20 public token;
    mapping(address => uint256) public claimable;

    function setClaim(address user, uint256 amount) external {
        claimable[user] = amount;
    }

    function claim() external {
        uint256 amount = claimable[msg.sender];
        claimable[msg.sender] = 0;

        token.transfer(msg.sender, amount);
        token.approve(msg.sender, 0);
    }
}
