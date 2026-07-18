// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: rateAtTarget adjustments are gated on an epoch boundary.
// The `block.timestamp - lastUpdate >= epochDuration` gate matches the
// body_not_contains_regex negative anchor, so detector is suppressed.
contract IntraEpochRateCompoundingClean {
    uint256 public rateAtTarget = 1e16;
    uint256 public utilization;
    uint256 public lastUpdate;
    uint256 public epochDuration = 12 hours;

    // CLEAN: only adjust rateAtTarget when at least one full epoch has
    // elapsed. Body contains the canonical epoch-boundary check, so the
    // negative regex matches and the detector does NOT fire.
    function _updateInterestRate(uint256 u) external {
        utilization = u;
        if (block.timestamp - lastUpdate >= epochDuration) {
            uint256 adjustment = (u > 5e17) ? rateAtTarget / 100 : rateAtTarget / 200;
            rateAtTarget = adjustRate(rateAtTarget, adjustment);
            lastUpdate = block.timestamp;
        }
    }

    // CLEAN variant: uses a newEpoch() check — also present in the
    // negative regex saturate list.
    function updateRate() external {
        if (isNewEpoch()) {
            uint256 rate = rateAtTarget * (utilization + 1) / 1e18;
            rateAtTarget = rate;
            lastUpdate = block.timestamp;
        }
    }

    function isNewEpoch() public view returns (bool) {
        return block.timestamp - lastUpdate >= epochDuration;
    }

    function adjustRate(uint256 base, uint256 delta) internal pure returns (uint256) {
        return base + delta;
    }
}
