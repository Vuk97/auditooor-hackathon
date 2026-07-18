// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every migration entry point calls an accrue/harvest/claim
// pathway before touching the v1 balance. The negated regex
// `accrue|harvest|claimRewards|pendingReward|updateRewards|syncYield`
// matches and suppresses the detector.
contract V1V2MigrationFundsStuckClean {
    mapping(address => uint256) public v1Balance;
    mapping(address => uint256) public v2Balance;
    mapping(address => uint256) public pendingReward;
    address public migrator;
    bool public migrated;

    function deposit(uint256 amount) external {
        v1Balance[msg.sender] += amount;
        pendingReward[msg.sender] += amount / 10;
    }

    // CLEAN: accrue is called before the burn/mint swap.
    function migrate(uint256 amount) external {
        _accrue(msg.sender);
        uint256 bal = v1Balance[msg.sender];
        _burn(msg.sender, bal);
        _mint(msg.sender, bal);
        amount;
    }

    // CLEAN: harvest is called before safeTransfer.
    function migrateV1() external {
        _harvest(msg.sender);
        uint256 bal = v1Balance[msg.sender];
        v1Balance[msg.sender] = 0;
        bal;
    }

    // CLEAN: claimRewards is invoked before _redeem.
    function migrateToV2(uint256 amount) external {
        claimRewards(msg.sender);
        _redeem(msg.sender, amount);
    }

    // CLEAN: updateRewards gate.
    function upgradePosition() external {
        updateRewards(msg.sender);
        uint256 bal = v1Balance[msg.sender];
        _burn(msg.sender, bal);
        _mint(msg.sender, bal);
    }

    function _accrue(address user) internal {
        pendingReward[user] = 0;
    }

    function _harvest(address user) internal {
        pendingReward[user] = 0;
    }

    function claimRewards(address user) internal {
        pendingReward[user] = 0;
    }

    function updateRewards(address user) internal {
        pendingReward[user] = 0;
    }

    function _burn(address from, uint256 amount) internal {
        v1Balance[from] -= amount;
    }

    function _mint(address to, uint256 amount) internal {
        v2Balance[to] += amount;
    }

    function _redeem(address user, uint256 amount) internal {
        v1Balance[user] -= amount;
        v2Balance[user] += amount;
    }
}
