// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20MetadataLike is IERC20Like {
    function decimals() external view returns (uint8);
}

library MathLike {
    function mulDiv(uint256 x, uint256 y, uint256 z) internal pure returns (uint256) {
        return (x * y) / z;
    }
}

contract FullPrecisionDepositValueMath {
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
        shares = MathLike.mulDiv(assets, totalSupply(), totalAssets());
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalShareSupply += shares;
    }
}

contract DynamicDecimalWithdrawValueMath {
    IERC20MetadataLike public immutable asset;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    constructor(IERC20MetadataLike asset_) {
        asset = asset_;
    }

    function withdraw(uint256 shareAmount) external returns (uint256 tokensOut) {
        uint256 scale = 10 ** uint256(asset.decimals());
        tokensOut = MathLike.mulDiv(shareAmount, 1, scale);
        require(tokensOut > 0, "zero amount");
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        asset.transfer(msg.sender, tokensOut);
    }
}

contract AccruedRateSpreadValueMath {
    uint256 public totalBorrows;
    uint256 public totalCash;
    uint256 public totalReserves;
    uint256 public reserveFactorMantissa = 0.1e18;
    uint256 public accrualBlockNumber;

    function accrueInterest() public {
        if (accrualBlockNumber == block.number) {
            return;
        }
        uint256 borrowRate = getBorrowRate();
        uint256 interestAccumulated = totalBorrows * borrowRate / 1e18;
        totalBorrows += interestAccumulated;
        accrualBlockNumber = block.number;
    }

    function getBorrowRate() public view returns (uint256) {
        uint256 util = totalBorrows * 1e18 / (totalCash + totalBorrows - totalReserves + 1);
        return util * 2e17 / 1e18;
    }

    function getSpread() external returns (uint256 borrow, uint256 supply, uint256 spread) {
        accrueInterest();
        borrow = getBorrowRate();
        supply = borrow * (1e18 - reserveFactorMantissa) / 1e18;
        spread = borrow - supply;
    }
}

contract GuardedWithdrawalQueueValueMath {
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
        uint256 assets = MathLike.mulDiv(shares, totalAssets(), totalSupply());
        require(assets > 0, "zero assets");
        queuedAssets[msg.sender] = assets;
        balanceOf[msg.sender] -= shares;
        totalShareSupply -= shares;
        return assets;
    }
}
