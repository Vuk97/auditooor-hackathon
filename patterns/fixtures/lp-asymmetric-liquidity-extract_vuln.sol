// SPDX-License-Identifier: MIT
// Fixture: lp-asymmetric-liquidity-extract — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

// VULN: vault holds reserve/pool/liquidity state and exposes single-sided
// deposit paths (provideSingleSided, zap, addLiquidity with a single flag)
// without any oracle/TWAP/sqrtPriceX96/imbalance/priceDeviation check.
// An attacker tilts the internal ratio with a preparatory swap, calls one
// of these functions, and extracts the reserve as IL-arbitrage in the same
// tx.
contract AsymmetricLPVuln {
    // Preconditions: state var names match /reserve|pool|liquidity|totalReserves|poolBalance/
    uint256 public reserve;
    uint256 public pool;
    uint256 public liquidity;
    uint256 public totalReserves;
    uint256 public poolBalance;

    // VULN: provideSingleSided adds inventory on one side of the book with
    // no price-imbalance defense. This is the canonical C0176 shape.
    function provideSingleSided(uint256 amountA) external {
        reserve += amountA;
        liquidity += amountA;
    }

    // VULN: an addLiquidity entrypoint with a `single`-sided flag branch
    // and no oracle/TWAP read.
    function addLiquiditySingle(uint256 amount, bool singleFlag) external {
        // "addLiquidity ... single" on one logical line — matches body regex.
        if (singleFlag) {
            pool += amount;
            totalReserves += amount;
        }
    }

    // VULN: zap router, aka "zapIn", deposits one asset and internally
    // swaps half — classic single-sided shape with no deviation guard.
    function zap(uint256 amount) external {
        poolBalance += amount;
        reserve += amount;
    }

    // VULN: swap entrypoint on the same reserve with oneSided semantics
    // and no sqrtPriceX96 / oracle check.
    function swap(uint256 amountIn, bool oneSided) external returns (uint256) {
        if (oneSided) {
            reserve -= amountIn / 2;
            poolBalance += amountIn;
        }
        return amountIn;
    }
}
