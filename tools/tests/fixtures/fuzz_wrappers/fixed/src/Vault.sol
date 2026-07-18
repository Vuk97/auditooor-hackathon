// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
