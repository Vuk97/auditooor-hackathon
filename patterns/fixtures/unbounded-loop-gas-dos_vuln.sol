// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// unbounded-loop-gas-dos detector. DO NOT DEPLOY.
///
/// `distributeRewards()` sweeps the full `stakers[]` array every call.
/// Registration via `stake()` is permissionless, costs near-zero, and has
/// no minimum. Any actor can grow `stakers` past the block gas limit and
/// permanently brick reward distribution for every honest staker.
contract UnboundedLoopVuln {
    address[] public stakers;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public rewardPerStaker;

    function stake() external payable {
        if (balances[msg.sender] == 0) {
            stakers.push(msg.sender);
        }
        balances[msg.sender] += msg.value;
    }

    /// Loops over the entire stakers array, no pagination, no cap, no
    /// break. Gas cost grows linearly with stakers.length.
    function distributeRewards() external {
        for (uint256 i = 0; i < stakers.length; i++) {
            address s = stakers[i];
            rewards[s] += rewardPerStaker;
        }
    }
}
