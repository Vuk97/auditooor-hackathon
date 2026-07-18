// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — no zero-duration guard before calling observe().
// Source: pendle-finance/pendle-core-v2-public@2709ae3

interface IPMarket {
    function observe(uint32[] memory durations) external view returns (uint216[] memory lnImpliedRateCumulative);
}

library PendlePYOracleLib {
    // VULNERABLE: duration=0 passed to observe() which may revert or return stale data
    function getMarketLnImpliedRate(address market, uint32 duration)
        internal
        view
        returns (uint256)
    {
        // No zero-duration guard
        uint32[] memory durations = new uint32[](2);
        durations[0] = duration; // if duration==0, observe may fail
        durations[1] = 0;

        uint216[] memory result = IPMarket(market).observe(durations);
        return uint256(result[0] - result[1]) / duration; // division by zero if duration==0
    }
}
