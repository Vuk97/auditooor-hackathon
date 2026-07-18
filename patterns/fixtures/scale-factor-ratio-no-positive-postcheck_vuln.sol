// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RatioOracleFactoryVuln {
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
    }

    function price(uint256 baseAmount) external view returns (uint256) {
        return baseAmount * SCALE_FACTOR / 1e18;
    }
}

contract RatioScaleInitVuln {
    uint256 public RATE;

    function initialize(uint256 assetSample, uint256 shareSample) external {
        require(shareSample != 0, "share sample 0");
        RATE = assetSample / shareSample;
    }
}
