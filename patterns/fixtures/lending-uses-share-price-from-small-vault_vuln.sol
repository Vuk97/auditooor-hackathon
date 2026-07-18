// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC4626 {
    function convertToAssets(uint256 shares) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface IERC20 { function transferFrom(address, address, uint256) external returns (bool); }

contract LendingMarketVuln {
    IERC4626 public collateralVault;
    IERC20 public debtToken;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateralShares;
    uint256 public constant LTV_BPS = 9000;

    // VULN: no supply-floor check on the ERC4626 pricing source
    function borrow(uint256 shares, uint256 borrowAmount) external {
        collateralShares[msg.sender] += shares;
        uint256 collatValue = collateralVault.convertToAssets(collateralShares[msg.sender]);
        uint256 maxDebt = (collatValue * LTV_BPS) / 10000;
        require(debt[msg.sender] + borrowAmount <= maxDebt, "LTV");
        debt[msg.sender] += borrowAmount;
    }
}
