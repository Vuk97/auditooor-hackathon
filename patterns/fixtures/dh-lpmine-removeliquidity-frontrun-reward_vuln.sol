// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LPMineRewardVuln {
    mapping(address => uint256) public userAmt;
    uint256 public accRewardPerShare;
    function updatePool() public { accRewardPerShare += 1; }
    function deposit(uint256 a) external {
        updatePool();
        userAmt[msg.sender] += a;
    }
    function withdraw(uint256 a) external {
        updatePool();
        userAmt[msg.sender] -= a;
    }
}
