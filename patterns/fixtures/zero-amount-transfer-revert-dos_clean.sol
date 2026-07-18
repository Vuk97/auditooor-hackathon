// SPDX-License-Identifier: MIT
// Fixture: zero-amount-transfer-revert-dos — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

// CLEAN: claim() short-circuits on amount == 0 before touching the token.
// Works against LEND-style zero-revert ERC20s.
contract RewardClaimClean {
    IERC20 public rewardToken;
    mapping(address => uint256) public pending;

    constructor(IERC20 _rewardToken) {
        rewardToken = _rewardToken;
    }

    function claim() external {
        uint256 amount = pending[msg.sender];
        if (amount == 0) return;
        pending[msg.sender] = 0;
        rewardToken.transfer(msg.sender, amount);
    }
}
