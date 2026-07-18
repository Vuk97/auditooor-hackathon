// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: the raw live balance is only used as an upper bound against accounted
// assets. Direct donations do not inflate the share-price numerator.
contract DonationGuardedVault {
    address public immutable token;
    uint256 public accountedAssets;

    constructor(address token_) {
        token = token_;
    }

    function totalAssets() external view returns (uint256) {
        uint256 liveBalance = IERC20Balance(token).balanceOf(address(this));
        if (liveBalance < accountedAssets) {
            return liveBalance;
        }
        return accountedAssets;
    }
}

interface IERC20Balance {
    function balanceOf(address) external view returns (uint256);
}
