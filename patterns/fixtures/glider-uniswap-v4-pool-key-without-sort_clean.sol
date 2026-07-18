// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

contract V4PoolKeySortClean {
    function build(address a, address b) external pure returns (PoolKey memory) {
        (address c0, address c1) = a < b ? (a, b) : (b, a);
        return PoolKey({ currency0: c0, currency1: c1, fee: 3000, tickSpacing: 60, hooks: address(0) });
    }
}
