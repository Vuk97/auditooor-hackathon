// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC3156FlashBorrowerLike {
    function onFlashLoan(address initiator, address token, uint256 amount, bytes calldata data) external returns (bytes32);
}

contract UsdtFeeFlashloanBrokenPositive {
    IERC20Like public immutable asset;
    uint256 public totalBorrows;
    uint256 public usdtFeeBps = 4;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function flashLoan(IERC3156FlashBorrowerLike receiver, uint256 amount, bytes calldata data) external {
        uint256 fee = amount * usdtFeeBps / 10_000;
        uint256 netAmount = amount - fee;

        asset.transfer(address(receiver), netAmount);
        totalBorrows += amount;

        receiver.onFlashLoan(msg.sender, address(asset), amount, data);

        asset.transferFrom(address(receiver), address(this), amount + fee);
    }
}
