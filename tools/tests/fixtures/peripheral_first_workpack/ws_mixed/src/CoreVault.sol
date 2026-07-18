// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title CoreVault - main deposit/withdraw logic (saturated core module)
contract CoreVault {
    mapping(address => uint256) public shares;
    uint256 public totalAssets;

    function deposit(uint256 amount) external returns (uint256 sharesOut) {
        sharesOut = (totalAssets == 0) ? amount : (amount * totalShares()) / totalAssets;
        shares[msg.sender] += sharesOut;
        totalAssets += amount;
    }

    function withdraw(uint256 sharesIn) external returns (uint256 assets) {
        assets = (sharesIn * totalAssets) / totalShares();
        shares[msg.sender] -= sharesIn;
        totalAssets -= assets;
    }

    function totalShares() public view returns (uint256 total) {
        total = totalAssets; // simplified
    }
}
