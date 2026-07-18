pragma solidity ^0.8.20;

interface IUniswapV3PoolLike {
    function burn(int24 tickLower, int24 tickUpper, uint128 amount)
        external
        returns (uint256 amount0, uint256 amount1);

    function mint(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount,
        bytes calldata data
    ) external returns (uint256 amount0, uint256 amount1);
}

contract ReallocateStealsLiquidityFromSiblingPairPositive {
    IUniswapV3PoolLike internal immutable uniswapPool;

    struct PairStatus {
        int24 lowerTick;
        int24 upperTick;
        uint128 liquidity;
    }

    constructor(IUniswapV3PoolLike pool) {
        uniswapPool = pool;
    }

    function triggerReallocate(PairStatus memory pairStatus) external {
        reallocateLiquidity(pairStatus);
    }

    function reallocateLiquidity(PairStatus memory pairStatus) internal {
        (uint256 amount0, uint256 amount1) = uniswapPool.burn(
            pairStatus.lowerTick,
            pairStatus.upperTick,
            pairStatus.liquidity
        );

        uint128 nextLiquidity = uint128(amount0 + amount1);
        uniswapPool.mint(
            address(this),
            pairStatus.lowerTick,
            pairStatus.upperTick,
            nextLiquidity,
            ""
        );
    }
}
