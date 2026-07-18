// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture: fixed — k-adjustment runs even at zero debt; rcomp zeroed at end.
// Source: silo-finance/silo-contracts-v2@e3dd4b0 (M-02 fix)

contract DynamicKinkModel {
    struct State { int256 k; }

    int256 public kmin;

    // FIXED: full k-adjustment runs regardless of debt; rcomp is zeroed after if no debt
    function compoundInterestRate(
        uint256 _tba,
        uint256 _t0,
        uint256 _t1,
        State memory _state
    ) public view returns (int256 rcomp, int256 k) {
        // ... full k-adjustment logic always runs
        k = _state.k;
        rcomp = _computeRcomp(_tba, _t0, _t1, k);

        // zero rcomp at end — but k was updated correctly during the calculation
        if (_tba == 0) rcomp = 0;
    }

    function _computeRcomp(uint256 tba, uint256 t0, uint256 t1, int256 k)
        internal pure returns (int256) {
        return int256(tba) * int256(t1 - t0) * k / 1e18;
    }
}
