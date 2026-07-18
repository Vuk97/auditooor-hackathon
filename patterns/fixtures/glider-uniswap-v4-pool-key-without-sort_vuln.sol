// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

contract V4PoolKeySortVuln {
    function build(address a, address b) external pure returns (PoolKey memory) {
        return PoolKey({ currency0: a, currency1: b, fee: 3000, tickSpacing: 60, hooks: address(0) });
    }
}
