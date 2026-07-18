// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: external `transfer` enforces the blacklist, but the internal
// helpers `_transfer`, `_batchTransfer`, `_migrateBalance`, and
// `_forceTransfer` write balances directly without consulting the list.
// Any trusted caller that funnels through these helpers (airdrop,
// migration, admin move) bypasses the compliance guarantee.
contract RestrictionListEnforcementBypassInternalTransferVuln {
    mapping(address => uint256) public balances;
    mapping(address => bool) public blacklist;
    mapping(address => bool) public restricted;
    mapping(address => bool) public frozen;
    address public admin;

    constructor() { admin = msg.sender; }

    function setBlacklist(address a, bool b) external {
        require(msg.sender == admin, "not admin");
        blacklist[a] = b;
    }

    // External path correctly enforces the list.
    function transfer(address to, uint256 amt) external returns (bool) {
        require(!blacklist[msg.sender], "sender blacklisted");
        require(!blacklist[to], "to blacklisted");
        _transfer(msg.sender, to, amt);
        return true;
    }

    // VULN: internal `_transfer` writes balances without consulting list.
    function _transfer(address from, address to, uint256 amt) internal {
        balances[from] -= amt;
        balances[to] += amt;
    }

    // VULN: bulk-airdrop path bypasses restriction.
    function _batchTransfer(address from, address[] memory to, uint256[] memory amt) internal {
        for (uint256 i = 0; i < to.length; ++i) {
            balances[from] -= amt[i];
            balances[to[i]] += amt[i];
        }
    }

    // VULN: cross-chain migration path bypasses restriction.
    function _migrateBalance(address from, address to, uint256 amt) internal {
        balances[from] -= amt;
        balances[to] += amt;
    }

    // VULN: force-move admin helper bypasses restriction.
    function _forceTransfer(address from, address to, uint256 amt) internal {
        balances[from] -= amt;
        balances[to] += amt;
    }

    // Trusted entry points that expose the bypass:
    function airdrop(address[] memory to, uint256[] memory amt) external {
        require(msg.sender == admin, "not admin");
        _batchTransfer(admin, to, amt);
    }

    function migrate(address from, address to, uint256 amt) external {
        require(msg.sender == admin, "not admin");
        _migrateBalance(from, to, amt);
    }

    function forceMove(address from, address to, uint256 amt) external {
        require(msg.sender == admin, "not admin");
        _forceTransfer(from, to, amt);
    }
}
