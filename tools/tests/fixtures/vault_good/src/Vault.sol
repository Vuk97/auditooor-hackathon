// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Fixture: a clean ERC4626 vault. Math mirrors OpenZeppelin's
// `ERC4626` base: shares = assets * totalSupply / totalAssets (with
// a virtual-share/virtual-asset offset to neutralise first-deposit
// inflation). Used by `tools/tests/test_erc4626_campaign.py` to
// exercise the capv3 iter-001 T4 vault campaign emitter.
//
// NOTE: Imports are deliberately absent so the detector runs on
// source alone without foundry remappings. The contract does not
// need to compile — the campaign fixture tests mock the fuzz
// runner.

interface IERC20Mock {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract Vault {
    IERC20Mock public immutable asset;

    // ERC20-like share accounting.
    string public constant name = "Good Vault Shares";
    string public constant symbol = "gVS";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Virtual-share offset (OZ-style) to neutralise first-deposit
    // inflation. Keeping it at 10 matches the OZ default decimals
    // offset rounded conservatively for a unit test.
    uint256 internal constant VIRTUAL_OFFSET = 1e3;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(
        address indexed caller,
        address indexed receiver,
        address indexed owner,
        uint256 assets,
        uint256 shares
    );

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

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return convertToShares(assets);
    }
    function previewMint(uint256 shares) public view returns (uint256) {
        // round up: caller must cover the shares
        uint256 ta = totalAssets() + 1;
        uint256 ts = totalSupply + VIRTUAL_OFFSET;
        return (shares * ta + ts - 1) / ts;
    }
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        // round up: caller burns enough shares to cover assets
        uint256 ts = totalSupply + VIRTUAL_OFFSET;
        uint256 ta = totalAssets() + 1;
        return (assets * ts + ta - 1) / ta;
    }
    function previewRedeem(uint256 shares) public view returns (uint256) {
        return convertToAssets(shares);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        _pullAndMint(assets, shares, receiver);
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = previewMint(shares);
        _pullAndMint(assets, shares, receiver);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        shares = previewWithdraw(assets);
        _burnAndPush(assets, shares, receiver, owner);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = previewRedeem(shares);
        _burnAndPush(assets, shares, receiver, owner);
    }

    function _pullAndMint(uint256 assets, uint256 shares, address receiver) internal {
        require(asset.transferFrom(msg.sender, address(this), assets), "pull failed");
        totalSupply += shares;
        balanceOf[receiver] += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function _burnAndPush(uint256 assets, uint256 shares, address receiver, address owner) internal {
        if (msg.sender != owner) {
            uint256 a = allowance[owner][msg.sender];
            require(a >= shares, "allowance");
            if (a != type(uint256).max) allowance[owner][msg.sender] = a - shares;
        }
        require(balanceOf[owner] >= shares, "balance");
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        require(asset.transfer(receiver, assets), "push failed");
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
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
