pragma solidity ^0.8.20;

interface IWooOracle {
    function price(address base) external view returns (uint256);
}

contract WooStylePmmQuoteClean {
    IWooOracle public immutable oracle;
    IWooOracle public immutable secondaryOracle;
    uint256 public immutable deviationBps;
    uint256 public baseReserve = 500 ether;
    uint256 public quoteReserve = 750_000 ether;

    constructor(IWooOracle oracle_, IWooOracle secondaryOracle_, uint256 deviationBps_) {
        oracle = oracle_;
        secondaryOracle = secondaryOracle_;
        deviationBps = deviationBps_;
    }

    function querySwap(address baseToken, uint256 baseAmount) external view returns (uint256 quoteAmount) {
        uint256 oraclePrice = oracle.price(baseToken);
        uint256 fallbackPrice = secondaryOracle.price(baseToken);
        require(oraclePrice > 0 && fallbackPrice > 0, "oracle price missing");

        uint256 reserveRatio = quoteReserve * 1e18 / baseReserve;
        uint256 diffPrimaryFallback = oraclePrice > fallbackPrice
            ? oraclePrice - fallbackPrice
            : fallbackPrice - oraclePrice;
        uint256 diffPrimaryReserve = oraclePrice > reserveRatio
            ? oraclePrice - reserveRatio
            : reserveRatio - oraclePrice;

        require(diffPrimaryFallback * 10_000 / fallbackPrice <= deviationBps, "secondaryOracle deviation");
        require(diffPrimaryReserve * 10_000 / reserveRatio <= deviationBps, "reserve deviation");

        quoteAmount = baseAmount * oraclePrice / 1e18;
    }
}
