// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Fixture: an ERC4626 vault with ONE real accounting-drift bug, used
// by `tools/tests/test_erc4626_campaign.py` to demonstrate the
// capv3 iter-001 T4 vault campaign surfacing a counterexample.
//
// The bug is intentionally shaped to be caught by a normal ERC4626
// code review — not tailored to match the invariant it trips. See
// `_burnAndPush` below: on the withdraw/redeem path we transfer the
// full `assets` out of the vault but only burn 90% of the shares we
// should. Remaining holders end up owning a larger slice of a smaller
// pie, which silently dilutes their redeemable assets (a classic
// share-accounting drift). A reviewer looking at share math without
// any knowledge of the campaign would flag the `9 / 10` scaling as
// wrong.

interface IERC20Mock {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract Vault {
    IERC20Mock public immutable asset;

    string public constant name = "Bad Vault Shares";
    string public constant symbol = "bVS";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 internal constant VIRTUAL_OFFSET = 1e3;

    constructor(address asset_) {
        asset = IERC20Mock(asset_);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalSupply + VIRTUAL_OFFSET)) / (totalAssets() + 1);
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + 1)) / (totalSupply + VIRTUAL_OFFSET);
    }

    function maxDeposit(address) external pure returns (uint256) { return type(uint256).max; }
    function maxMint(address) external pure returns (uint256) { return type(uint256).max; }
    function maxWithdraw(address owner) public view returns (uint256) {
        return convertToAssets(balanceOf[owner]);
    }
    function maxRedeem(address owner) public view returns (uint256) {
        return balanceOf[owner];
    }

    function previewDeposit(uint256 assets) public view returns (uint256) { return convertToShares(assets); }
    function previewMint(uint256 shares) public view returns (uint256) {
        uint256 ta = totalAssets() + 1;
        uint256 ts = totalSupply + VIRTUAL_OFFSET;
        return (shares * ta + ts - 1) / ts;
    }
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        uint256 ts = totalSupply + VIRTUAL_OFFSET;
        uint256 ta = totalAssets() + 1;
        return (assets * ts + ta - 1) / ta;
    }
    function previewRedeem(uint256 shares) public view returns (uint256) { return convertToAssets(shares); }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "pull");
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = previewMint(shares);
        require(asset.transferFrom(msg.sender, address(this), assets), "pull");
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        shares = previewWithdraw(assets);
        _burnAndPush(assets, shares, receiver, owner);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        _burnAndPush(assets, shares, receiver, owner);
    }

    function _burnAndPush(uint256 assets, uint256 shares, address receiver, address owner) internal {
        if (msg.sender != owner) {
            uint256 a = allowance[owner][msg.sender];
            require(a >= shares, "allowance");
            if (a != type(uint256).max) allowance[owner][msg.sender] = a - shares;
        }
        require(balanceOf[owner] >= shares, "balance");

        // --- BUG ---------------------------------------------------------
        // We push the full `assets` out of the vault but only burn
        // 90% of the shares that *should* be burned. Remaining
        // holders silently lose share value on every withdraw path.
        //
        // A reviewer reading this function without any campaign
        // context would flag `9 / 10` as obviously wrong — shares
        // burned must equal shares `assets` converted to, not a
        // discounted fraction.
        uint256 sharesBurned = (shares * 9) / 10;
        balanceOf[owner] -= sharesBurned;
        totalSupply -= sharesBurned;
        // -----------------------------------------------------------------

        require(asset.transfer(receiver, assets), "push");
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
