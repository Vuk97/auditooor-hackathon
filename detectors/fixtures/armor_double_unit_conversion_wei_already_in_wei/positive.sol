// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ArmorClaimManagerPositive {
    mapping(address => uint256) public approvedClaimWei;

    function approveClaim(address user, uint256 amountWei) external {
        approvedClaimWei[user] = amountWei;
    }

    function claim(uint256 amountWei) external {
        require(amountWei <= approvedClaimWei[msg.sender], "too much");
        uint256 payment = amountWei * 1e18;
        approvedClaimWei[msg.sender] -= amountWei;
        payable(msg.sender).transfer(payment);
    }

    receive() external payable {}
}
