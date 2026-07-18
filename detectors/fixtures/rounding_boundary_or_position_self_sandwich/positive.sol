// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoundingBoundaryOrPositionSelfSandwichPositive {
    struct Position {
        uint256 collateral;
        uint256 debt;
    }

    struct SwapParams {
        uint256 amountIn;
        uint256 minAmountOut;
        uint16 maxSlippageBps;
    }

    mapping(address => Position) public positions;

    function executeSwap(SwapParams memory params) internal pure returns (uint256) {
        uint256 slippage = (params.amountIn * params.maxSlippageBps) / 10000;
        return params.amountIn - slippage;
    }

    function openPosition(uint256 collateral, uint256 debt, uint256 amountIn) external {
        SwapParams memory params = SwapParams({
            amountIn: amountIn,
            minAmountOut: 0,
            maxSlippageBps: 10000
        });

        uint256 received = executeSwap(params);
        positions[msg.sender] = Position({
            collateral: collateral + received,
            debt: debt
        });
    }

    function closePosition(uint256 amountIn) external {
        Position storage position = positions[msg.sender];
        SwapParams memory params = SwapParams({
            amountIn: amountIn,
            minAmountOut: 0,
            maxSlippageBps: 10000
        });

        uint256 received = executeSwap(params);
        position.collateral += received;
        position.debt = 0;
    }
}

contract RoundingBoundaryBitmapPositive {
    mapping(address => uint256) public userConfig;

    function setBorrowing(uint8 reserveId, bool enabled) external {
        uint256 shift = reserveId * 2;
        uint256 mask = 1 << shift;
        if (enabled) {
            userConfig[msg.sender] |= mask;
        } else {
            userConfig[msg.sender] &= ~mask;
        }
    }
}
