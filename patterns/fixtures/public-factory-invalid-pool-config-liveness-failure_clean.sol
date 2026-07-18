// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OfficialRevertShapePool {
    uint256 public immutable amp;
    uint256 public immutable swapFeeBps;
    uint256 public immutable protocolFeeBps;

    constructor(
        address token0,
        address token1,
        uint256 amplification,
        uint256 swapFee,
        uint256 protocolFee
    ) {
        token0;
        token1;
        amp = amplification;
        swapFeeBps = swapFee;
        protocolFeeBps = protocolFee;
    }

    function quoteSwap(uint256 amountIn) external view returns (uint256) {
        uint256 invariantShare = amountIn / amp;
        return amountIn - ((invariantShare * swapFeeBps) / 10_000);
    }
}

contract PublicPoolFactoryInvalidConfigClean {
    uint256 public constant MAX_SWAP_FEE_BPS = 1_000;
    uint256 public constant MAX_PROTOCOL_FEE_BPS = 10_000;
    uint256 public defaultSwapFeeBps = 30;
    address[] public officialPools;

    event PoolCreated(address indexed pool);

    error ZeroAmplification();
    error FeeOutOfRange();

    function createPool(
        address token0,
        address token1,
        uint256 amp,
        uint256 swapFeeBps,
        uint256 protocolFeeBps
    ) external returns (address pool) {
        if (amp == 0) revert ZeroAmplification();

        uint256 effectiveSwapFeeBps = swapFeeBps;
        if (swapFeeBps == type(uint256).max) {
            effectiveSwapFeeBps = defaultSwapFeeBps;
        }

        if (effectiveSwapFeeBps > MAX_SWAP_FEE_BPS) revert FeeOutOfRange();
        if (protocolFeeBps > MAX_PROTOCOL_FEE_BPS) revert FeeOutOfRange();

        pool = address(new OfficialRevertShapePool(
            token0,
            token1,
            amp,
            effectiveSwapFeeBps,
            protocolFeeBps
        ));
        officialPools.push(pool);
        emit PoolCreated(pool);
    }
}
