// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LPMineRewardClean {
    mapping(address => uint256) public userAmt;
    mapping(address => uint256) public lastDepositBlock;
    uint256 public accRewardPerShare;
    uint256 public constant MIN_LOCK = 5;
    function updatePool() public { accRewardPerShare += 1; }
    function deposit(uint256 a) external {
        updatePool();
        userAmt[msg.sender] += a;
        lastDepositBlock[msg.sender] = block.number;
    }
    function withdraw(uint256 a) external {
        require(block.number > lastDepositBlock[msg.sender] + MIN_LOCK, "locked");
        updatePool();
        userAmt[msg.sender] -= a;
    }
}
