// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20MetadataLike is IERC20Like {
    function decimals() external view returns (uint8);
}

library Math {
    function mulDiv(uint256 x, uint256 y, uint256 z) internal pure returns (uint256) {
        return (x * y) / z;
    }
}

contract FullPrecisionDepositVault {
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
        shares = Math.mulDiv(assets, totalSupply(), totalAssets());
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function _mint(address receiver, uint256 shares) internal {
        balanceOf[receiver] += shares;
        totalShareSupply += shares;
    }
}

contract FullPrecisionRedeemVault {
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
        assets = Math.mulDiv(shares, totalAssets(), totalSupply());
        require(assets > 0, "zero assets");
        _burn(msg.sender, shares);
        asset.transfer(receiver, assets);
    }

    function _burn(address owner, uint256 shares) internal {
        balanceOf[owner] -= shares;
        totalShareSupply -= shares;
    }
}

contract DynamicDecimalPayout {
    IERC20MetadataLike public immutable payoutToken;
    uint256 public price = 2e18;

    constructor(IERC20MetadataLike payoutToken_) {
        payoutToken = payoutToken_;
    }

    function payout(uint256 amount, address receiver) external returns (uint256 amountOut) {
        uint256 scale = 10 ** uint256(payoutToken.decimals());
        amountOut = amount * price / scale;
        require(amountOut > 0, "zero amount");
        payoutToken.transfer(receiver, amountOut);
    }
}

contract FullPrecisionClaim {
    IERC20Like public immutable rewardToken;
    uint256 public rewardRate = 3e18;
    uint256 public constant RATE_SCALE = 1e18;
    mapping(address => uint256) public claimable;

    constructor(IERC20Like rewardToken_) {
        rewardToken = rewardToken_;
    }

    function claimRewards() external returns (uint256 payout) {
        payout = Math.mulDiv(claimable[msg.sender], rewardRate, RATE_SCALE);
        require(payout > 0, "zero amount");
        claimable[msg.sender] -= payout;
        rewardToken.transfer(msg.sender, payout);
    }
}
