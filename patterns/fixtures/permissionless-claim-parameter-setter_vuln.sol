// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: ABCCApp-style — addFixedDay is an open setter for the per-user
// claim target, and claimDDDD reads it without bound. Attacker sets
// target = 1e9 and mints proportionally.
contract ClaimPoolVuln {
    IERC20 public rewardToken;
    IERC20 public depositToken;
    mapping(address => uint256) public fixedDayTarget;
    mapping(address => uint256) public depositedPlan;

    constructor(IERC20 _reward, IERC20 _deposit) {
        rewardToken = _reward;
        depositToken = _deposit;
    }

    function deposit(uint256 planId, address ref) external {
        depositToken.transferFrom(msg.sender, address(this), 1 ether);
        depositedPlan[msg.sender] = planId;
    }

    // BUG: no onlyOwner, no cap, no msg.sender == owner(target).
    function addFixedDay(uint256 target) external {
        fixedDayTarget[msg.sender] = target;
    }

    function claimDDDD() external {
        uint256 t = fixedDayTarget[msg.sender];
        fixedDayTarget[msg.sender] = 0;
        rewardToken.transfer(msg.sender, t * 1e9);
    }
}
