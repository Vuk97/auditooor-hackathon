// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every SINK first invokes the accrual SOURCE so prior
// rewards are checkpointed before the balance changes. The SOURCE
// function itself does NOT need to call itself recursively.
contract PokeAccrueSourceVsSinkClean {
    uint256 public rewardPerShare;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastUserIndex;
    mapping(address => uint256) public claimed;

    // SOURCE — exempt by detector (its body sets state but does not need
    // to call itself). Detector rejects this because its name is the
    // accrual entrypoint.
    function _accrueRewards(address user) internal {
        uint256 currentIdx = rewardPerShare;
        uint256 delta = currentIdx - lastUserIndex[user];
        claimed[user] += balances[user] * delta;
        lastUserIndex[user] = currentIdx;
    }

    // CLEAN SINK — calls accrual SOURCE before writing balance.
    function mint(address user, uint256 amount) external {
        _accrueRewards(user);
        balances[user] += amount;
        totalSupply  += amount;
    }

    function deposit(uint256 amount) external {
        _accrueRewards(msg.sender);
        balances[msg.sender] += amount;
        totalSupply  += amount;
    }

    function redeem(uint256 amount) external {
        _accrueRewards(msg.sender);
        balances[msg.sender] -= amount;
        totalSupply  -= amount;
    }

    function setRewardPerShare(uint256 newIdx) external {
        rewardPerShare = newIdx;
    }
}
