pragma solidity ^0.8.20;

interface IWooOracle {
    function price(address base) external view returns (uint256);
}

contract WooStylePmmQuotePositive {
    IWooOracle public immutable oracle;
    uint256 public baseReserve = 500 ether;
    uint256 public quoteReserve = 750_000 ether;

    constructor(IWooOracle oracle_) {
        oracle = oracle_;
    }

    function querySwap(address baseToken, uint256 baseAmount) external view returns (uint256 quoteAmount) {
        uint256 oraclePrice = oracle.price(baseToken);
        require(oraclePrice > 0, "oracle price missing");

        uint256 reserveRatio = quoteReserve * 1e18 / baseReserve;
        uint256 cappedDepth = quoteReserve * reserveRatio / 1e18;
        quoteAmount = baseAmount * oraclePrice / 1e18;
        if (quoteAmount > cappedDepth) {
            quoteAmount = cappedDepth;
        }
    }
}
