// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: redeem rounds the asset-out amount UP (favors the caller).
contract RedeemRoundingVulnerable {
    uint256 internal totalSupply;
    uint256 internal totalAssets;

    function mulDivUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        return (a * b + d - 1) / d;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = mulDivUp(shares, totalAssets, totalSupply);
        totalSupply -= shares;
        totalAssets -= assets;
    }
}
