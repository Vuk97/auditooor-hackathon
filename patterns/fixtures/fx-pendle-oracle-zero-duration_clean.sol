// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — zero-duration returns spot rate from storage.
// Source: pendle-finance/pendle-core-v2-public@2709ae3

interface IPMarket {
    function observe(uint32[] memory durations) external view returns (uint216[] memory lnImpliedRateCumulative);
    function _storage() external view returns (uint96 lnImpliedRate, uint96 lastLnImpliedRate, uint96 unused0, uint256 unused1, uint256 unused2, uint256 unused3);
}

library PendlePYOracleLib {
    // FIXED: duration==0 returns spot rate from storage, bypassing TWAP path
    function getMarketLnImpliedRate(address market, uint32 duration)
        internal
        view
        returns (uint256)
    {
        if (duration == 0) {
            (uint96 lnImpliedRate,,,,,) = IPMarket(market)._storage();
            return uint256(lnImpliedRate);
        }

        uint32[] memory durations = new uint32[](2);
        durations[0] = duration;
        durations[1] = 0;

        uint216[] memory result = IPMarket(market).observe(durations);
        return uint256(result[0] - result[1]) / duration;
    }
}
