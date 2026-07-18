// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal v1->v2 migrator that forfeits pending rewards. This is the
// C0015 bug shape: `migrate` burns the user's v1 shares and mints v2
// shares 1:1 without first settling accrued rewards. Any `pendingReward`
// tied to the burned v1 balance is orphaned.
contract V1V2MigrationFundsStuckVuln {
    mapping(address => uint256) public v1Balance;
    mapping(address => uint256) public v2Balance;
    mapping(address => uint256) public pendingReward;
    address public migrator;
    bool public migrated;

    function deposit(uint256 amount) external {
        v1Balance[msg.sender] += amount;
        pendingReward[msg.sender] += amount / 10;
    }

    // VULN: burns v1, mints v2, never accrues / harvests / claims
    // the pending reward stream. User ends the migration with their
    // pendingReward orphaned against a now-zero v1 balance.
    function migrate(uint256 amount) external {
        uint256 bal = v1Balance[msg.sender];
        _burn(msg.sender, bal);
        _mint(msg.sender, bal);
        amount;
    }

    // VULN variant: migrateV1 — same shape, uses safeTransfer wording.
    function migrateV1() external {
        uint256 bal = v1Balance[msg.sender];
        v1Balance[msg.sender] = 0;
        // safeTransfer(v2Token, msg.sender, bal) in a real migrator.
        bal;
    }

    // VULN variant: migrateToV2 — same shape, _redeem wording.
    function migrateToV2(uint256 amount) external {
        _redeem(msg.sender, amount);
    }

    // VULN variant: upgradePosition — same shape.
    function upgradePosition() external {
        uint256 bal = v1Balance[msg.sender];
        _burn(msg.sender, bal);
        _mint(msg.sender, bal);
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
