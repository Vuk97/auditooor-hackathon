// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every admin setter that re-points stakeToken /
// underlying / principalToken either requires totalStaked == 0 or
// invokes a migration routine (_migrateStakes) before swapping. Each
// body contains at least one of the negated-regex guard tokens so the
// detector does NOT fire.
contract StakeTokenReplaceBreaksExistingStakesClean {
    address public owner;
    address public stakeToken;
    address public underlying;
    address public principalToken;
    uint256 public totalStaked;
    bool public migrationComplete;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
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

    // CLEAN: require totalStaked == 0 before swap.
    function setStakeToken(address newToken) external onlyOwner {
        require(totalStaked == 0, "drain stakes first");
        stakeToken = newToken;
    }

    // CLEAN: runs migration routine before updating pointer.
    function changeUnderlying(address newUnderlying) external onlyOwner {
        _migrateStakes(underlying, newUnderlying);
        underlying = newUnderlying;
        migrationComplete = true;
    }

    // CLEAN: gated on migrationComplete flag.
    function updateAsset(address newAsset) external onlyOwner {
        require(migrationComplete, "migrationComplete required");
        stakeToken = newAsset;
    }

    // CLEAN: totalSupply == 0 check (alt form).
    function setAsset(address newAsset) external onlyOwner {
        require(totalStaked == 0, "stakers present");
        stakeToken = newAsset;
    }

    // CLEAN: migrateToken that actually calls migrateStakes.
    function migrateToken(address newToken) external onlyOwner {
        _migrateStakes(stakeToken, newToken);
        stakeToken = newToken;
    }

    // CLEAN: replaceToken with require(totalStaked == 0).
    function replaceToken(address newToken) external onlyOwner {
        require(totalStaked == 0, "cannot replace with open stakes");
        principalToken = newToken;
    }

    function _migrateStakes(address, address) internal {
        // convert or refund every outstanding balance; elided in fixture.
        migrationComplete = true;
    }
}
