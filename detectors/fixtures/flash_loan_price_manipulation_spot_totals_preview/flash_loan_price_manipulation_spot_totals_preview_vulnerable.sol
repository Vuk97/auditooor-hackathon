// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FlashLoanPriceManipulationSpotTotalsPreviewVulnerable {
    uint256 internal reserveBase = 500 ether;
    uint256 internal reserveQuote = 1_000 ether;
    uint256 internal totalAssets = 2_500 ether;

    function previewSpotTotals(uint256 amountIn) external view returns (uint256) {
        uint256 spotPrice = (reserveQuote * 1e18) / reserveBase;
        return (amountIn * spotPrice) / totalAssets;
    }
}
