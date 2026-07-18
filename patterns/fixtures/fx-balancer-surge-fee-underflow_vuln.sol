// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — surge fee underflows when max < static fee.
// Source: balancer/balancer-v3-monorepo@767a6a1

contract StableSurgeHook {
    struct SurgeFeeData {
        uint256 maxSurgeFeePercentage;
        uint256 surgeThresholdPercentage;
    }

    mapping(address => SurgeFeeData) internal _surgeFeePoolData;

    // VULNERABLE: no guard for maxSurgeFee < staticFee → underflow on (max - static)
    function _computeSurgeFee(
        address pool,
        uint256 staticFeePercentage,
        uint256 imbalancePct
    ) internal view returns (uint256 surgeFeePercentage) {
        SurgeFeeData memory surgeFeeData = _surgeFeePoolData[pool];

        // BUG: if maxSurgeFeePercentage < staticFeePercentage, next line underflows
        uint256 feeRange = surgeFeeData.maxSurgeFeePercentage - staticFeePercentage;
        surgeFeePercentage = staticFeePercentage + (imbalancePct * feeRange / 1e18);
    }
}
