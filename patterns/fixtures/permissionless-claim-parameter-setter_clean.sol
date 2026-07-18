// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: addFixedDay is onlyOwner and capped. claimDDDD is bounded.
contract ClaimPoolClean {
    address public owner;
    IERC20 public rewardToken;
    IERC20 public depositToken;
    mapping(address => uint256) public fixedDayTarget;
    mapping(address => uint256) public depositedPlan;
    uint256 public constant MAX_TARGET = 1000;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor(IERC20 _reward, IERC20 _deposit) {
        owner = msg.sender;
        rewardToken = _reward;
        depositToken = _deposit;
    }

    function deposit(uint256 planId, address ref) external {
        depositToken.transferFrom(msg.sender, address(this), 1 ether);
        depositedPlan[msg.sender] = planId;
    }

    // Admin sets each user's target, bounded.
    function addFixedDay(address user, uint256 target) external onlyOwner {
        require(target <= MAX_TARGET, "target too high");
        fixedDayTarget[user] = target;
    }

    function claimDDDD() external {
        uint256 t = fixedDayTarget[msg.sender];
        fixedDayTarget[msg.sender] = 0;
        rewardToken.transfer(msg.sender, t * 1e9);
    }
}
