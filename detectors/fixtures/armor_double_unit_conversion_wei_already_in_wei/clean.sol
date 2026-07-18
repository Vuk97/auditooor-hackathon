// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ArmorClaimManagerClean {
    mapping(address => uint256) public maxClaim;

    function approveClaim(address user, uint256 amountWei) external {
        maxClaim[user] = amountWei;
    }

    function claim(uint256 amountWei) external {
        uint256 payment = amountWei;
        require(payment <= maxClaim[msg.sender], "too much");
        maxClaim[msg.sender] -= payment;
        payable(msg.sender).transfer(payment);
    }

    receive() external payable {}
}
