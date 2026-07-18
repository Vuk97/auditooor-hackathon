// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract RewardPoolRewardIntegralManipulableVuln {
    IERC20 public rewardToken;
    // This state var triggers contract-level precondition
    // (contract.has_state_var_matching: integral|rewardPerShare|...).
    uint256 public integral;
    uint256 public accRewardPerShare;
    uint256 public rewardIndex;

    mapping(address => uint256) public userBalance;
    uint256 public _totalStakedSupply;

    constructor(address _rewardToken) {
        rewardToken = IERC20(_rewardToken);
    }

    function totalSupply() public view returns (uint256) {
        return _totalStakedSupply;
    }

    // VULN: integral computed as (newRewards * 1e18) / totalSupply() with no
    // snapshot guard. Donor can donate rewardToken directly to this contract
    // to inflate `newRewards`, or flashloan-stake to inflate totalSupply().
    function _calcRewardIntegral() external {
        uint256 newRewards = rewardToken.balanceOf(address(this));
        uint256 supply = totalSupply();
        if (supply == 0) return;
        integral += (newRewards * 1e18) / supply;
    }

    // VULN: classic synthetix rewardPerToken, same shape.
    function rewardPerToken() external view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) return rewardIndex;
        return rewardIndex + (rewardToken.balanceOf(address(this)) * 1e18) / supply;
    }

    // VULN: earned() path hits totalStaked + no snapshot.
    function earned(address account) external view returns (uint256) {
        uint256 totalStaked = _totalStakedSupply;
        if (totalStaked == 0) return 0;
        return (userBalance[account] * rewardToken.balanceOf(address(this))) / totalStaked;
    }
}
