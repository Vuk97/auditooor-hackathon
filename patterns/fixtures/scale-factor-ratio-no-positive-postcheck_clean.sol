// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RatioOracleFactoryClean {
    uint256 public immutable SCALE_FACTOR;
    uint256 public immutable CONVERSION_RATE;
    uint256 public immutable FACTOR;

    constructor(
        uint256 baseVaultConversionSample,
        uint256 quoteVaultConversionSample,
        uint256 baseDecimals,
        uint256 quoteDecimals
    ) {
        require(baseVaultConversionSample != 0, "base sample 0");
        require(quoteVaultConversionSample != 0, "quote sample 0");

        SCALE_FACTOR = quoteVaultConversionSample / baseVaultConversionSample;
        CONVERSION_RATE = (10 ** (18 + quoteDecimals - baseDecimals))
            * quoteVaultConversionSample / baseVaultConversionSample;
        FACTOR = 10 ** (18 + quoteDecimals - baseDecimals)
            * quoteVaultConversionSample / baseVaultConversionSample;

        require(SCALE_FACTOR > 0, "scale zero");
        require(CONVERSION_RATE > 0, "conversion rate zero");
        require(FACTOR > 0, "factor zero");
    }

    function price(uint256 baseAmount) external view returns (uint256) {
        return baseAmount * SCALE_FACTOR / 1e18;
    }
}

contract RatioScaleMulDivClean {
    uint256 public immutable RATE;

    constructor(uint256 assetSample, uint256 shareSample) {
        require(shareSample != 0, "share sample 0");
        RATE = Math.mulDiv(assetSample, 1e18, shareSample);
        require(RATE > 0, "rate zero");
    }
}

contract RatioOracleFactoryBoundedClean {
    uint256 public immutable SCALE_FACTOR;

    constructor(uint256 baseVaultConversionSample, uint256 quoteVaultConversionSample) {
        require(baseVaultConversionSample != 0, "base sample 0");
        require(quoteVaultConversionSample >= baseVaultConversionSample, "scale would truncate");
        SCALE_FACTOR = quoteVaultConversionSample / baseVaultConversionSample;
    }
}

contract TimeoutConfigRatioClean {
    uint256 public immutable RATE;

    constructor(uint256 elapsedBlocks, uint256 windowBlocks) {
        require(windowBlocks != 0, "window 0");
        RATE = elapsedBlocks / windowBlocks;
    }
}

contract LiteralScaleRatioClean {
    uint256 public immutable SCALE_FACTOR;

    constructor() {
        SCALE_FACTOR = 10 ** 18 / 10 ** 6;
    }
}

library Math {
    function mulDiv(uint256 x, uint256 y, uint256 z) internal pure returns (uint256) {
        return (x * y) / z;
    }
}
