// SPDX-License-Identifier: MIT
// Fixture: lp-asymmetric-liquidity-extract — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice() external view returns (uint256);
}

// CLEAN: every single-sided / zap / swap entrypoint pairs the reserve-
// mutating math with an explicit price-imbalance defense — oracle quote,
// TWAP snapshot, sqrtPriceX96 read, or a declared imbalance/priceDeviation
// bound. The body_not_contains_regex negation therefore fails, and the
// detector must not fire on any function in this contract.
contract AsymmetricLPClean {
    uint256 public reserve;
    uint256 public pool;
    uint256 public liquidity;
    uint256 public totalReserves;
    uint256 public poolBalance;
    uint160 public sqrtPriceX96;
    IOracle public oracle;

    uint256 public constant MAX_DEVIATION_BPS = 200;

    constructor(address oracle_) {
        oracle = IOracle(oracle_);
    }

    // CLEAN: single-sided add protected by an oracle.getPrice deviation
    // check. Matches the negative-guard regex; detector must not fire.
    function provideSingleSided(uint256 amountA) external {
        uint256 price = oracle.getPrice();
        require(price > 0, "stale oracle");
        reserve += amountA;
        liquidity += amountA;
    }

    // CLEAN: TWAP-gated single-sided add. The body contains "TWAP", which
    // disqualifies this function from the match.
    function addLiquiditySingle(uint256 amount, bool singleFlag) external {
        uint256 twapPrice = _readTWAP();
        require(twapPrice > 0, "bad TWAP");
        if (singleFlag) {
            pool += amount;
            totalReserves += amount;
        }
    }

    // CLEAN: zap path guarded by a sqrtPriceX96 bound — the Uniswap V3
    // canonical imbalance defense.
    function zap(uint256 amount) external {
        require(sqrtPriceX96 != 0, "uninit pool");
        poolBalance += amount;
        reserve += amount;
    }

    // CLEAN: oneSided swap path guarded by an explicit priceDeviation
    // tolerance — the imbalance keyword in the body kills the match.
    function swap(uint256 amountIn, bool oneSided) external returns (uint256) {
        uint256 priceDeviation = _deviation();
        require(priceDeviation <= MAX_DEVIATION_BPS, "imbalance too large");
        if (oneSided) {
            reserve -= amountIn / 2;
            poolBalance += amountIn;
        }
        return amountIn;
    }

    function _readTWAP() internal pure returns (uint256) { return 1; }
    function _deviation() internal pure returns (uint256) { return 0; }
}
