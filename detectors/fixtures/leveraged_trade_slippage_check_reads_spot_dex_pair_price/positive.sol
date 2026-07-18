pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

contract LeveragedTradeEnginePositive {
    function openLong(
        address pair,
        uint256 collateralAmount,
        uint256 leverage,
        uint256 minAmountOut
    ) external view returns (uint256 amountOut) {
        IUniswapV2Pair spotPair = IUniswapV2Pair(pair);
        (uint112 reserve0, uint112 reserve1,) = spotPair.getReserves();
        address baseToken = spotPair.token0();
        address quoteToken = spotPair.token1();

        uint256 quotedReserve = baseToken < quoteToken ? uint256(reserve1) : uint256(reserve0);
        uint256 baseReserve = baseToken < quoteToken ? uint256(reserve0) : uint256(reserve1);
        uint256 spotPrice = quotedReserve * 1e18 / baseReserve;

        amountOut = collateralAmount * leverage * 1e18 / spotPrice;
        require(amountOut >= minAmountOut, "slippage");
    }
}
