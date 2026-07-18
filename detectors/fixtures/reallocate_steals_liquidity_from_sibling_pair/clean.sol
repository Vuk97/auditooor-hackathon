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

contract ReallocateStealsLiquidityFromSiblingPairClean {
    IUniswapV3PoolLike internal immutable uniswapPool;

    struct PairStatus {
        int24 lowerTick;
        int24 upperTick;
        uint128 liquidity;
    }

    mapping(bytes32 => uint128) internal liquidityByPair;

    constructor(IUniswapV3PoolLike pool) {
        uniswapPool = pool;
    }

    function triggerReallocate(uint256 pairId, PairStatus memory pairStatus) external {
        reallocateLiquidity(pairId, pairStatus);
    }

    function reallocateLiquidity(uint256 pairId, PairStatus memory pairStatus) internal {
        bytes32 positionKey = keccak256(
            abi.encode(address(uniswapPool), pairId, pairStatus.lowerTick, pairStatus.upperTick)
        );

        uint128 lpShare = liquidityByPair[positionKey];
        (uint256 amount0, uint256 amount1) = uniswapPool.burn(
            pairStatus.lowerTick,
            pairStatus.upperTick,
            lpShare
        );

        uint128 nextLiquidity = uint128(amount0 + amount1);
        liquidityByPair[positionKey] = nextLiquidity;
        uniswapPool.mint(
            address(this),
            pairStatus.lowerTick,
            pairStatus.upperTick,
            nextLiquidity,
            abi.encode(pairId)
        );
    }
}
