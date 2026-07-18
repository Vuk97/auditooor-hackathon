pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract PerpMarketRouter {}

contract PredyPoolBadDebtClean {
    IERC20Like public quoteToken;

    constructor(IERC20Like token) {
        quoteToken = token;
    }

    function executeLiquidation(address liquidator, int256 remainingMargin) external {
        if (remainingMargin < 0) {
            quoteToken.safeTransferFrom(liquidator, address(this), uint256(-remainingMargin));
        }
    }
}
