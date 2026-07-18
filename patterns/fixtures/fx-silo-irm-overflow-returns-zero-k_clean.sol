// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — overflow guard returns (0, kmin) preserving invariant.
// Source: silo-finance/silo-contracts-v2@f12498e

library SafeCast {
    function wouldOverflowOnCastToInt256(uint256 v) internal pure returns (bool) {
        return v > uint256(type(int256).max);
    }
}

contract DynamicKinkModel {
    using SafeCast for uint256;

    struct Config { int256 kmin; int256 kmax; }

    // FIXED: returns (0, kmin) so k-invariant k ∈ [kmin,kmax] is preserved
    function getCurrentInterestRate(
        uint256 interestRateTimestamp,
        uint256 blockTimestamp,
        uint256 collateralAssets,
        uint256 debtAssets,
        Config memory cfg
    ) external pure returns (int256 rcomp, int256 k) {
        if (interestRateTimestamp.wouldOverflowOnCastToInt256()) return (0, cfg.kmin);
        if (blockTimestamp.wouldOverflowOnCastToInt256())        return (0, cfg.kmin);
        if (collateralAssets.wouldOverflowOnCastToInt256())      return (0, cfg.kmin);
        if (debtAssets.wouldOverflowOnCastToInt256())            return (0, cfg.kmin);
        k = cfg.kmin;
        rcomp = 0;
    }
}
