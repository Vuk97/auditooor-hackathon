// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
}

contract RateSnapshotMismatchPositive {
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

contract StateScaleValueMovePositive {
    IERC20Like public immutable asset;
    mapping(address => uint256) public queuedShares;
    uint256 public exchangeRate = 2e18;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function claim(uint256 shares) external returns (uint256 assets) {
        queuedShares[msg.sender] -= shares;
        assets = shares / exchangeRate * 1e18;
        asset.transfer(msg.sender, assets);
    }
}

contract FeeStateSinkMismatchPositive {
    IERC20Like public immutable token;
    address public treasury;
    uint256 public accruedFee;

    constructor(IERC20Like token_, address treasury_) {
        token = token_;
        treasury = treasury_;
    }

    function withdrawProtocolFee(address feeRecipient) external {
        uint256 feeAmount = accruedFee;
        require(feeAmount != 0, "no fee");
        accruedFee = 0;
        token.safeTransfer(feeRecipient, feeAmount);
    }
}
