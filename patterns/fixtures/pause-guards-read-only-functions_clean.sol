// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: view / pure read functions carry NO pause modifier. The pause
// modifier is reserved for state-mutating entry-points (deposit /
// withdraw / transfer). Integrations can still read protocol state
// while the contract is paused.
contract LendingClean {
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

    // ---- reads do NOT carry whenNotPaused ----

    function balanceOf(address user) external view returns (uint256) {
        return _balances[user];
    }

    function getAccountLiquidity(address user) external view returns (uint256) {
        return _balances[user] * 2;
    }

    function computeExitPrice(uint256 shares) external pure returns (uint256) {
        return shares * 3;
    }

    // ---- mutation IS guarded (correct use of whenNotPaused) ----

    function deposit(uint256 amount) external whenNotPaused {
        _balances[msg.sender] += amount;
        _totalSupply += amount;
    }
}
