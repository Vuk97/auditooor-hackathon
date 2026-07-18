// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IoracleQueryExchangeRateReturnsIncorrectBlockTimeMsVulnerable {
    struct ExchangeRate {
        uint256 rate;
        uint256 blockTimeMs;
        uint64 blockHeight;
    }

    mapping(bytes32 => ExchangeRate) internal exchangeRates;

    function seed(bytes32 pair, uint256 rate, uint256 historicBlockTimeMs, uint64 historicBlockHeight) external {
        exchangeRates[pair] = ExchangeRate({
            rate: rate,
            blockTimeMs: historicBlockTimeMs,
            blockHeight: historicBlockHeight
        });
    }

    function queryExchangeRate(bytes32 pair) external view returns (uint256 rate, uint256 blockTimeMs, uint64 blockHeight) {
        ExchangeRate storage exchangeRate = exchangeRates[pair];
        rate = exchangeRate.rate;
        blockHeight = exchangeRate.blockHeight;
        blockTimeMs = block.timestamp * 1000;
    }
}
