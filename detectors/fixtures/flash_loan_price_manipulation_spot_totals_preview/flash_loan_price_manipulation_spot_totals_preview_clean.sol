// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FlashLoanPriceManipulationSpotTotalsPreviewClean {
    uint256 internal reserveBase = 500 ether;
    uint256 internal reserveQuote = 1_000 ether;

    function previewSpotTotals(uint256 amountIn) external view returns (uint256) {
        return _oracleTwapQuote(amountIn);
    }

    function _oracleTwapQuote(uint256 amountIn) internal view returns (uint256) {
        uint256 oraclePrice = getOraclePrice();
        return (amountIn * oraclePrice) / 1e18;
    }

    function getOraclePrice() internal view returns (uint256) {
        return (reserveQuote * 1e18) / reserveBase;
    }
}
