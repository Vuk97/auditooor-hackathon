// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — guard returns staticFeePercentage when max < static.
// Source: balancer/balancer-v3-monorepo@767a6a1

contract StableSurgeHook {
    struct SurgeFeeData {
        uint256 maxSurgeFeePercentage;
        uint256 surgeThresholdPercentage;
    }

    mapping(address => SurgeFeeData) internal _surgeFeePoolData;

    // FIXED: early return when max surge fee < static fee prevents underflow
    function _computeSurgeFee(
        address pool,
        uint256 staticFeePercentage,
        uint256 imbalancePct
    ) internal view returns (uint256 surgeFeePercentage) {
        SurgeFeeData memory surgeFeeData = _surgeFeePoolData[pool];

        // Guard: if max surge fee is less than static, fee cannot be below static
        if (surgeFeeData.maxSurgeFeePercentage < staticFeePercentage) {
            return staticFeePercentage;
        }

        uint256 feeRange = surgeFeeData.maxSurgeFeePercentage - staticFeePercentage;
        surgeFeePercentage = staticFeePercentage + (imbalancePct * feeRange / 1e18);
    }
}
