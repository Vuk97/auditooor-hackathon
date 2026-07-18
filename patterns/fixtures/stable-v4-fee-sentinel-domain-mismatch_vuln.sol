// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

type PoolId is bytes32;

library SafeCast {
    function toUint24(uint256 value) internal pure returns (uint24) {
        return uint24(value);
    }
}

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

contract StableV4FeeSentinelDomainMismatchVuln {
    uint256 internal constant FEE_PRECISION = 1_000_000;
    uint256 public immutable lpFeePercentage;

    constructor(address token0, address token1, uint256 _lpFeePercentage) {
        lpFeePercentage = _lpFeePercentage;

        PoolKey memory poolKey = PoolKey({
            currency0: token0,
            currency1: token1,
            fee: SafeCast.toUint24(_lpFeePercentage),
            tickSpacing: 1,
            hooks: address(this)
        });
        poolKey;
    }

    function getFees(uint256 amount) external view returns (uint256) {
        return amount * lpFeePercentage / FEE_PRECISION;
    }
}
