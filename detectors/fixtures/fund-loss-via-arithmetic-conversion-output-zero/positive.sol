// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract DustShareDepositVault {
    IERC20Like public immutable asset;
    uint256 public totalShareSupply = 1_000_000e18;
    uint256 public managedAssets = 10_000_000e18;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return managedAssets;
    }

    function totalSupply() public view returns (uint256) {
        return totalShareSupply;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = assets / totalAssets() * totalSupply();
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function _mint(address receiver, uint256 shares) internal {
        balanceOf[receiver] += shares;
        totalShareSupply += shares;
    }
}

contract DustRedeemVault {
    IERC20Like public immutable asset;
    uint256 public totalShareSupply = 1_000_000e18;
    uint256 public managedAssets = 10_000_000e18;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return managedAssets;
    }

    function totalSupply() public view returns (uint256) {
        return totalShareSupply;
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = shares / totalSupply() * totalAssets();
        _burn(msg.sender, shares);
        asset.transfer(receiver, assets);
    }

    function _burn(address owner, uint256 shares) internal {
        balanceOf[owner] -= shares;
        totalShareSupply -= shares;
    }
}

contract HardcodedScalePayout {
    IERC20Like public immutable payoutToken;
    uint256 public price = 2e18;

    constructor(IERC20Like payoutToken_) {
        payoutToken = payoutToken_;
    }

    function payout(uint256 amount, address receiver) external returns (uint256 amountOut) {
        amountOut = amount * price / 1e18;
        payoutToken.transfer(receiver, amountOut);
    }
}

contract ClaimableRateBeforeScale {
    IERC20Like public immutable rewardToken;
    uint256 public rewardRate = 3e18;
    uint256 public constant RATE_SCALE = 1e18;
    mapping(address => uint256) public claimable;

    constructor(IERC20Like rewardToken_) {
        rewardToken = rewardToken_;
    }

    function claimRewards() external returns (uint256 payout) {
        payout = claimable[msg.sender] / RATE_SCALE * rewardRate;
        claimable[msg.sender] -= payout;
        rewardToken.transfer(msg.sender, payout);
    }
}
