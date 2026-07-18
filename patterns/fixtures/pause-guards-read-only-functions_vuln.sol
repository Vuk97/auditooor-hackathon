// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: view / pure functions carry `whenNotPaused`. When the contract
// is paused every integration that needs to READ protocol state
// (liquidator bots, dashboards, integrating vaults) will revert — not a
// security property, just a UX / integration break. The pause modifier
// should gate mutations only.
contract LendingVuln {
    address public owner;
    bool public paused;

    mapping(address => uint256) internal _balances;
    uint256 internal _totalSupply;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setPaused(bool v) external onlyOwner {
        paused = v;
    }

    // ---- reads guarded by pause (the bug) ----

    function balanceOf(address user) external view whenNotPaused returns (uint256) {
        return _balances[user];
    }

    function getAccountLiquidity(address user) external view whenNotPaused returns (uint256) {
        return _balances[user] * 2;
    }

    function computeExitPrice(uint256 shares) external view whenNotPaused returns (uint256) {
        return shares * 3;
    }
}
