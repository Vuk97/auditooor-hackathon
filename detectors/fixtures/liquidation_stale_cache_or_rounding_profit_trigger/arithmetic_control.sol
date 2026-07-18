// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AdjacentArithmeticRoundingControl {
    function previewRedeemRoundTrip(uint256 seizedAssets, uint256 totalAssets, uint256 totalShares)
        external
        pure
        returns (uint256 repaidAssets, uint256 repaidShares)
    {
        repaidAssets = toAssetsUp(seizedAssets, totalAssets, totalShares);
        repaidShares = toSharesDown(repaidAssets, totalAssets, totalShares);
    }

    function toAssetsUp(uint256 shares, uint256 assets, uint256 totalShares) internal pure returns (uint256) {
        return (shares * assets + totalShares - 1) / totalShares;
    }

    function toSharesDown(uint256 assets, uint256 totalAssets, uint256 totalShares) internal pure returns (uint256) {
        return assets * totalShares / totalAssets;
    }
}
