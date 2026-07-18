// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - withdrawal-cei-violation-transfer-before-burn-no-reentrancy-guard
// VULN: withdraw() transfers BEFORE burning shares, no nonReentrant guard.
// ERC777 tokensReceived callback can re-enter while balances[msg.sender] is stale.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnStakingPool {
    IERC20 public token;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public shares;
    uint256 public totalAssets;

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        shares[msg.sender] += amount; // 1:1 for simplicity
        totalAssets += amount;
    }

    // VULN: CEI violated - transfer before state update, no nonReentrant.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        // EXTERNAL CALL FIRST (CEI violation)
        token.transfer(msg.sender, amount);
        // STATE UPDATE AFTER (allows reentrancy to see stale balance)
        balances[msg.sender] -= amount;
        shares[msg.sender] -= amount;
        totalAssets -= amount;
    }

    // VULN shape 2: claim rewards - transfer before balance update
    function claimRewards() external {
        uint256 rewards = _computeRewards(msg.sender);
        require(rewards > 0, "no rewards");
        token.safeTransfer(msg.sender, rewards); // transfer first
        balances[msg.sender] = 0; // state reset after
    }

    function _computeRewards(address user) internal view returns (uint256) {
        return balances[user] * 10 / 100;
    }
}
