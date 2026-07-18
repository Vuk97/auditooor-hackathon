// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amt) external returns (bool);
    function transferFrom(address from, address to, uint256 amt) external returns (bool);
}

contract StakingRewardOverlapVuln {
    IERC20 public stakeToken;           // precondition: state var name matches
    mapping(address => uint256) public staking; // another stake-matching var
    mapping(address => uint256) public rewards;

    constructor(IERC20 _t) {
        stakeToken = _t;
    }

    function deposit(uint256 amt) external {
        stakeToken.transferFrom(msg.sender, address(this), amt);
        staking[msg.sender] += amt;
    }

    function withdraw(uint256 amt) external {
        staking[msg.sender] -= amt;
        stakeToken.transfer(msg.sender, amt);
    }

    // VULN: pays reward by transferring the stake token out of the contract's
    // balance — which also holds every user's deposited principal. Drains pool.
    function claimReward() external {
        uint256 owed = rewards[msg.sender];
        rewards[msg.sender] = 0;
        stakeToken.transfer(msg.sender, owed);
    }
}
