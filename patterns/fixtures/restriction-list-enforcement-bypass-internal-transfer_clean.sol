// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every internal balance-moving helper consults the restriction
// list, either via a direct require(!blacklist[...]) check or by
// funnelling through a shared _checkRestriction hook.
contract RestrictionListEnforcementBypassInternalTransferClean {
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

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    // CLEAN: internal _transfer consults the blacklist at the chokepoint.
    function _transfer(address from, address to, uint256 amt) internal {
        require(!blacklist[from], "from blacklisted");
        require(!blacklist[to], "to blacklisted");
        balances[from] -= amt;
        balances[to] += amt;
    }

    // CLEAN: _batchTransfer checks every recipient via isBlacklisted helper.
    function _batchTransfer(address from, address[] memory to, uint256[] memory amt) internal {
        require(!isBlacklisted(from), "from blacklisted");
        for (uint256 i = 0; i < to.length; ++i) {
            require(!isBlacklisted(to[i]), "recipient blacklisted");
            balances[from] -= amt[i];
            balances[to[i]] += amt[i];
        }
    }

    // CLEAN: _migrateBalance uses the shared _checkRestriction hook.
    function _migrateBalance(address from, address to, uint256 amt) internal {
        _checkRestriction(from);
        _checkRestriction(to);
        balances[from] -= amt;
        balances[to] += amt;
    }

    // CLEAN: _forceTransfer still enforces the restriction guard.
    function _forceTransfer(address from, address to, uint256 amt) internal {
        require(!restricted[from], "from restricted");
        require(!restricted[to], "to restricted");
        balances[from] -= amt;
        balances[to] += amt;
    }

    function isBlacklisted(address a) public view returns (bool) {
        return blacklist[a];
    }

    function _checkRestriction(address a) internal view {
        require(!restricted[a], "restricted");
        require(!frozen[a], "frozen");
    }

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
