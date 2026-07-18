// SPDX-License-Identifier: MIT
// Fixture: zero-amount-transfer-revert-dos — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

// VULN: claim() transfers the pending reward without first checking
// amount > 0. If `rewardToken` is a LEND-style token that reverts on
// zero-value transfers, any claim with nothing accrued (same-block
// double-claim, dust staker) reverts and all state changes roll back.
contract RewardClaimVuln {
    IERC20 public rewardToken;
    mapping(address => uint256) public pending;

    constructor(IERC20 _rewardToken) {
        rewardToken = _rewardToken;
    }

    function claim() external {
        uint256 amount = pending[msg.sender];
        pending[msg.sender] = 0;
        // no zero-skip guard. amount may be 0.
        rewardToken.transfer(msg.sender, amount);
    }
}
