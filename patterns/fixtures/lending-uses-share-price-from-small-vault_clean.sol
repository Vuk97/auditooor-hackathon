// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC4626 {
    function convertToAssets(uint256 shares) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract LendingMarketClean {
    IERC4626 public collateralVault;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateralShares;
    uint256 public constant LTV_BPS = 9000;
    uint256 public constant MIN_SHARE_SUPPLY = 1e22;

    function borrow(uint256 shares, uint256 borrowAmount) external {
        // CLEAN: enforce supply floor before pricing
        require(collateralVault.totalSupply() >= MIN_SHARE_SUPPLY, "supply-floor");
        collateralShares[msg.sender] += shares;
        uint256 collatValue = collateralVault.convertToAssets(collateralShares[msg.sender]);
        uint256 maxDebt = (collatValue * LTV_BPS) / 10000;
        require(debt[msg.sender] + borrowAmount <= maxDebt, "LTV");
        debt[msg.sender] += borrowAmount;
    }
}
