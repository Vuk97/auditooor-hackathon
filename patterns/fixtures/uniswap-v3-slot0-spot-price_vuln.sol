// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// uniswap-v3-slot0-spot-price detector. DO NOT DEPLOY.
///
/// getPrice() derives the collateral price from the live sqrtPriceX96
/// returned by pool.slot0(). A flashloan that dislocates the pool within
/// one transaction will cause any downstream collateral / mint math that
/// consumes this price to be evaluated against a manipulated spot value.

interface IUniswapV3Pool {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
}

contract SlotZeroOracleVuln {
    IUniswapV3Pool public pool;

    constructor(IUniswapV3Pool _pool) {
        pool = _pool;
    }

    /// VULNERABLE: reads sqrtPriceX96 directly from slot0. No observe / consult
    /// / getQuoteAtTick / TWAP / _consult appears in the body, so a flashloan
    /// can skew this value in one tx.
    function getPrice() external view returns (uint256 priceX96) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        // Naive conversion: (sqrtPriceX96)^2 / 2^96 ~ price
        priceX96 = uint256(sqrtPriceX96) * uint256(sqrtPriceX96) >> 96;
    }

    /// Downstream surface that would consume the manipulable price —
    /// included so the fixture shows the realistic shape of the bug.
    function collateralValue(uint256 amount) external view returns (uint256) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        uint256 priceX96 = uint256(sqrtPriceX96) * uint256(sqrtPriceX96) >> 96;
        return amount * priceX96;
    }
}
