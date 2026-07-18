// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoundingBoundaryOrPositionSelfSandwichClean {
    uint16 public constant MAX_SLIPPAGE_BPS = 100;
    uint256 public constant MIN_HEALTH_FACTOR = 150;

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
    uint256 public totalAssets = 1_000_000 ether;
    uint256 public totalSupply = 1_000 ether;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public userConfig;

    function executeSwap(SwapParams memory params) internal pure returns (uint256) {
        uint256 slippage = (params.amountIn * params.maxSlippageBps) / 10000;
        uint256 amountOut = params.amountIn - slippage;
        require(amountOut >= params.minAmountOut, "slippage");
        return amountOut;
    }

    function openPosition(
        uint256 collateral,
        uint256 debt,
        uint256 amountIn,
        uint256 minAmountOut,
        uint16 maxSlippageBps
    ) external {
        require(minAmountOut > 0, "zero output");
        require(maxSlippageBps <= MAX_SLIPPAGE_BPS, "slippage cap");

        SwapParams memory params = SwapParams({
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            maxSlippageBps: maxSlippageBps
        });

        uint256 received = executeSwap(params);
        uint256 healthFactor = debt == 0 ? type(uint256).max : ((collateral + received) * 100) / debt;
        require(healthFactor >= MIN_HEALTH_FACTOR, "unhealthy");

        positions[msg.sender] = Position({
            collateral: collateral + received,
            debt: debt
        });
    }

    function closePosition(uint256 amountIn, uint256 minAmountOut, uint16 maxSlippageBps) external {
        require(minAmountOut > 0, "zero output");
        require(maxSlippageBps <= MAX_SLIPPAGE_BPS, "slippage cap");

        Position storage position = positions[msg.sender];
        SwapParams memory params = SwapParams({
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            maxSlippageBps: maxSlippageBps
        });

        uint256 received = executeSwap(params);
        uint256 healthFactor = position.debt == 0 ? type(uint256).max : (received * 100) / position.debt;
        require(healthFactor >= MIN_HEALTH_FACTOR, "unhealthy close");

        position.collateral += received;
        position.debt = 0;
    }

    function setBorrowing(uint8 reserveId, bool enabled) external {
        require(reserveId < 64, "reserve bound");
        uint256 shift = reserveId * 2;
        uint256 mask = 1 << shift;
        if (enabled) {
            userConfig[msg.sender] |= mask;
        } else {
            userConfig[msg.sender] &= ~mask;
        }
    }

    function mintShares(uint256 assets) external returns (uint256 minted) {
        minted = (assets * totalSupply) / totalAssets;
        require(minted > 0, "zero shares");
        shares[msg.sender] += minted;
    }
}
