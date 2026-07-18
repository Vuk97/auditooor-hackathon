// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal rate-at-target IRM. C0364 root cause: _updateInterestRate
// adjusts rateAtTarget from instantaneous utilization on every call,
// without an epoch-boundary guard, so sub-epoch invocations compound a
// rate-at-target error. Detector MUST fire on _updateInterestRate.
contract IntraEpochRateCompoundingVuln {
    uint256 public rateAtTarget = 1e16; // 1% per epoch toy number
    uint256 public utilization;
    uint256 public lastUpdate;
    uint256 public epochDuration = 12 hours;

    // VULN: rateAtTarget is adjusted every call regardless of whether a
    // full epoch has elapsed. No `block.timestamp - lastUpdate >= epoch`
    // gate, no newEpoch / epochBoundary / isNewEpoch check. The `rate *
    // utilization` / `adjustRate(...)` body matches the positive anchor.
    function _updateInterestRate(uint256 u) external {
        utilization = u;
        uint256 adjustment = (u > 5e17) ? rateAtTarget / 100 : rateAtTarget / 200;
        rateAtTarget = adjustRate(rateAtTarget, adjustment);
        lastUpdate = block.timestamp;
    }

    // VULN variant: updateRate reuses the same rateAtTarget math without
    // the epoch guard. Also matches the pattern.
    function updateRate() external {
        uint256 rate = rateAtTarget * (utilization + 1) / 1e18;
        rateAtTarget = rate;
        lastUpdate = block.timestamp;
    }

    function adjustRate(uint256 base, uint256 delta) internal pure returns (uint256) {
        return base + delta;
    }
}
