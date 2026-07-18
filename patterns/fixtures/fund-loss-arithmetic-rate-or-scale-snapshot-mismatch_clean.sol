// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
}

library MathLike {
    function mulDiv(uint256 x, uint256 y, uint256 z) internal pure returns (uint256) {
        return (x * y) / z;
    }
}

contract RateSnapshotMismatchClean {
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

contract StateScaleValueMoveClean {
    IERC20Like public immutable asset;
    mapping(address => uint256) public queuedShares;
    uint256 public exchangeRate = 2e18;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function claim(uint256 shares) external returns (uint256 assets) {
        queuedShares[msg.sender] -= shares;
        assets = MathLike.mulDiv(shares, 1e18, exchangeRate);
        require(assets > 0, "zero assets");
        asset.transfer(msg.sender, assets);
    }
}

contract FeeStateSinkMismatchClean {
    IERC20Like public immutable token;
    address public owner;
    address public treasury;
    uint256 public accruedFee;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    constructor(IERC20Like token_, address treasury_) {
        token = token_;
        owner = msg.sender;
        treasury = treasury_;
    }

    function withdrawProtocolFee() external onlyOwner {
        uint256 feeAmount = accruedFee;
        require(feeAmount != 0, "no fee");
        accruedFee = 0;
        token.safeTransfer(treasury, feeAmount);
    }
}
