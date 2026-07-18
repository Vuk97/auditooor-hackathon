// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: same vault shape but uses a checkpointed totalAssets storage
// variable as the share-price denominator. balanceOf(address(this))
// appears only in a permissioned sync() and never inside a share-mint
// or share-redeem arithmetic.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Erc4626BalanceOfShareCalcNarrowedClean {
    IERC20 public immutable underlying;
    uint256 public totalSupply;
    uint256 public storedAssets;             // checkpointed denominator
    address public admin;

    mapping(address => uint256) public balances;

    constructor(IERC20 _u) {
        underlying = IERC20(address(_u));
        admin = msg.sender;
    }

    function _convertToShares(uint256 assets) internal view returns (uint256) {
        if (storedAssets == 0) return assets;
        return assets * totalSupply / storedAssets;   // tracked total
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = _convertToShares(assets);
        balances[msg.sender] += shares;
        totalSupply += shares;
        storedAssets += assets;                       // update checkpoint
        underlying.transferFrom(msg.sender, address(this), assets);
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        if (totalSupply == 0) return 0;
        assets = shares * storedAssets / totalSupply;
        balances[msg.sender] -= shares;
        totalSupply -= shares;
        storedAssets -= assets;
        underlying.transfer(msg.sender, assets);
    }

    // CLEAN — sync uses balanceOf(address(this)) only here (admin-gated)
    // and is NOT a deposit/mint/withdraw/redeem name → detector skips.
    function sync() external {
        require(msg.sender == admin, "auth");
        storedAssets = underlying.balanceOf(address(this));
    }
}
