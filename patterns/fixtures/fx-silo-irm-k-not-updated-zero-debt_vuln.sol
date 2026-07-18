// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: vulnerable — zero-debt path returns stale k without updating it.
// Source: silo-finance/silo-contracts-v2@e3dd4b0 (M-02 fix)

contract DynamicKinkModel {
    struct State { int256 k; }

    int256 public kmin;

    // VULNERABLE: returns (0, state.k) early — k is frozen at last value
    function compoundInterestRate(
        uint256 _tba,
        uint256 _t0,
        uint256 _t1,
        State memory _state
    ) public view returns (int256 rcomp, int256 k) {
        // BUG: early return skips k-adjustment entirely
        if (_tba == 0) return (0, _state.k);

        // ... full k-adjustment logic runs here for non-zero debt
        k = _state.k;
        rcomp = _computeRcomp(_tba, _t0, _t1, k);
    }

    function _computeRcomp(uint256 tba, uint256 t0, uint256 t1, int256 k)
        internal pure returns (int256) {
        return int256(tba) * int256(t1 - t0) * k / 1e18;
    }
}
