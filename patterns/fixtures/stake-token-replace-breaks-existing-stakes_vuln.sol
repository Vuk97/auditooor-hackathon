// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal staking vault that exposes an admin setter for the stake
// token address without requiring totalStaked == 0 or running a
// migration routine. This is the C0377 "Disruption of existing
// stakes when replacing the stake token" bug shape: existing balances
// remain in the old token while user accounting now points at the new.
contract StakeTokenReplaceBreaksExistingStakesVuln {
    address public owner;
    address public stakeToken;
    address public underlying;
    address public principalToken;
    uint256 public totalStaked;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == owner, "not admin");
        _;
    }

    constructor(address _stakeToken) {
        owner = msg.sender;
        stakeToken = _stakeToken;
        underlying = _stakeToken;
        principalToken = _stakeToken;
    }

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalStaked += amount;
    }

    // VULN: overwrites stakeToken without draining or migrating in-flight
    // balances. No check on totalStaked. No migrationComplete flag.
    function setStakeToken(address newToken) external onlyOwner {
        stakeToken = newToken;
    }

    // VULN variant: underlying swap, same shape.
    function changeUnderlying(address newUnderlying) external onlyOwner {
        underlying = newUnderlying;
    }

    // VULN variant: asset re-pointer with admin gate but no migration.
    function updateAsset(address newAsset) external onlyAdmin {
        stakeToken = newAsset;
    }

    // VULN variant: setAsset alias.
    function setAsset(address newAsset) external onlyOwner {
        stakeToken = newAsset;
    }

    // VULN variant: migrateToken without the actual migration — a common
    // footgun where the function is named optimistically but skips work.
    function migrateToken(address newToken) external onlyOwner {
        stakeToken = newToken;
    }

    // VULN variant: replaceToken alias.
    function replaceToken(address newToken) external onlyOwner {
        principalToken = newToken;
    }
}
