// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - withdrawal-cei-violation-transfer-before-burn-no-reentrancy-guard
// CLEAN: state updated BEFORE transfer (CEI correct), nonReentrant guard present.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

abstract contract ReentrancyGuard {
    bool private _nonReentrantLocked;

    modifier nonReentrant() {
        require(!_nonReentrantLocked, "ReentrancyGuard: reentrant call");
        _nonReentrantLocked = true;
        _;
        _nonReentrantLocked = false;
    }
}

contract CleanStakingPool is ReentrancyGuard {
    IERC20 public token;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public shares;
    uint256 public totalAssets;

    function deposit(uint256 amount) external nonReentrant {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        shares[msg.sender] += amount;
        totalAssets += amount;
    }

    // CLEAN: CEI correct - state BEFORE transfer, nonReentrant guard present.
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");
        // STATE UPDATE FIRST (CEI correct)
        balances[msg.sender] -= amount;
        shares[msg.sender] -= amount;
        totalAssets -= amount;
        // EXTERNAL CALL LAST (safe - state already updated)
        token.transfer(msg.sender, amount);
    }

    // CLEAN: nonReentrant + state before transfer
    function claimRewards() external nonReentrant {
        uint256 rewards = _computeRewards(msg.sender);
        require(rewards > 0, "no rewards");
        balances[msg.sender] = 0; // state reset first
        token.transfer(msg.sender, rewards); // transfer after
    }

    function _computeRewards(address user) internal view returns (uint256) {
        return balances[user] * 10 / 100;
    }
}
