// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same domain as the vuln
/// fixture, but reward distribution is explicitly paginated: the caller
/// supplies `start` and `end` indices, and the function enforces a
/// `MAX_BATCH` cap. The token `MAX_BATCH` plus the `batchSize` check
/// plus the `require(... length ...)` bound all independently trip the
/// pattern's bound-regex, so the detector stays silent.
contract UnboundedLoopClean {
    uint256 public constant MAX_BATCH = 100;

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

    function distributeRewards(uint256 start, uint256 end) external {
        require(end <= stakers.length, "oob");
        uint256 batchSize = end - start;
        require(batchSize <= MAX_BATCH, "batch too large");
        for (uint256 i = start; i < end; i++) {
            address s = stakers[i];
            rewards[s] += rewardPerStaker;
        }
    }
}
