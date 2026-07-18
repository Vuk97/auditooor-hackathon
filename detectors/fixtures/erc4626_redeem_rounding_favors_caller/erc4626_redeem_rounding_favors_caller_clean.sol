// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: redeem rounds the asset-out amount DOWN to the user (spec-correct).
contract RedeemRoundingClean {
    uint256 internal totalSupply;
    uint256 internal totalAssets;

    function mulDivDown(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        return (a * b) / d;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = mulDivDown(shares, totalAssets, totalSupply);
        totalSupply -= shares;
        totalAssets -= assets;
    }
}
