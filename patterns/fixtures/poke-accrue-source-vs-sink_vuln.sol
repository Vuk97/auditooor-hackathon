// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: SINK functions (mint/deposit/redeem) write balance state
// without first invoking the accrual SOURCE. User's pending reward at
// the prior index is retired silently.
contract PokeAccrueSourceVsSinkVuln {
    uint256 public rewardPerShare;            // current accrual index
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastUserIndex;
    mapping(address => uint256) public claimed;

    // SOURCE — accrual entrypoint (correct, but never called by SINKS).
    function _accrueRewards(address user) internal {
        uint256 currentIdx = rewardPerShare;
        uint256 delta = currentIdx - lastUserIndex[user];
        claimed[user] += balances[user] * delta;
        lastUserIndex[user] = currentIdx;
    }

    // VULN — SINK: mints shares + writes balance, but does NOT
    // invoke _accrueRewards first.
    function mint(address user, uint256 amount) external {
        balances[user] += amount;
        totalSupply  += amount;
    }

    // VULN — SINK: deposit path; writes balance, no accrual.
    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalSupply  += amount;
    }

    // VULN — SINK: redeem path; writes balance, no accrual.
    function redeem(uint256 amount) external {
        balances[msg.sender] -= amount;
        totalSupply  -= amount;
    }

    // Reward index advance (admin only — not a sink).
    function setRewardPerShare(uint256 newIdx) external {
        rewardPerShare = newIdx;
    }
}
