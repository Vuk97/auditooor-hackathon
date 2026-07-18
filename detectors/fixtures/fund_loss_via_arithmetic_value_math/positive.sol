// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract DustShareDepositValueMath {
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
        balanceOf[receiver] += shares;
        totalShareSupply += shares;
    }
}

contract DecimalScaledWithdrawValueMath {
    IERC20Like public immutable asset;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function withdraw(uint256 shareAmount) external returns (uint256 tokensOut) {
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        tokensOut = shareAmount / 1e18;
        asset.transfer(msg.sender, tokensOut);
    }
}

contract StaleRateSpreadValueMath {
    uint256 public totalBorrows;
    uint256 public totalCash;
    uint256 public totalReserves;
    uint256 public reserveFactorMantissa = 0.1e18;

    function getBorrowRate() public view returns (uint256) {
        uint256 util = totalBorrows * 1e18 / (totalCash + totalBorrows - totalReserves);
        return util * 2e17 / 1e18;
    }

    function getSupplyRate() public view returns (uint256) {
        uint256 borrowRate = getBorrowRate();
        return borrowRate * (1e18 - reserveFactorMantissa) / 1e18;
    }

    function getSpread() external view returns (uint256 borrow, uint256 supply, uint256 spread) {
        borrow = getBorrowRate();
        supply = getSupplyRate();
        spread = borrow - supply;
    }
}

contract LiquidationDebtCollateralValueMath {
    IERC20Like public immutable collateralAsset;
    uint256 public collateralPrice = 2e18;
    uint256 public liquidationFee = 5e16;

    constructor(IERC20Like collateralAsset_) {
        collateralAsset = collateralAsset_;
    }

    function liquidate(address borrower, uint256 debt) external returns (uint256 collateral) {
        collateral = debt / collateralPrice * (1e18 + liquidationFee);
        collateralAsset.transferFrom(borrower, msg.sender, collateral);
    }
}

contract WithdrawalQueueValueMath {
    uint256 public totalShareSupply = 1000e18;
    uint256 public managedAssets = 900e18;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public queuedAssets;

    function totalAssets() public view returns (uint256) {
        return managedAssets;
    }

    function totalSupply() public view returns (uint256) {
        return totalShareSupply;
    }

    function requestWithdraw(uint256 shares) external returns (uint256 queued) {
        queuedAssets[msg.sender] = shares / totalSupply() * totalAssets();
        balanceOf[msg.sender] -= shares;
        totalShareSupply -= shares;
        return queuedAssets[msg.sender];
    }
}
