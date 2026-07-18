// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — create() calls _registerPoolWithFactory twice.
// Source: balancer/balancer-v3-monorepo@509caa6

contract BasePoolFactory {
    mapping(address => bool) internal _isPoolFromFactory;

    // _registerPoolWithVault already calls _registerPoolWithFactory internally
    function _registerPoolWithVault(address pool) internal {
        _registerPoolWithFactory(pool);
        // ... vault.registerPool(pool) ...
    }

    function _registerPoolWithFactory(address pool) internal {
        require(!_isPoolFromFactory[pool], "Already registered");
        _isPoolFromFactory[pool] = true;
    }
}

contract Gyro2CLPPoolFactory is BasePoolFactory {
    // VULNERABLE: calls _registerPoolWithVault (which internally calls _registerPoolWithFactory)
    // AND then calls _registerPoolWithFactory again → double registration → revert
    function create(
        address tokenA,
        address tokenB
    ) external returns (address pool) {
        pool = address(new MockPool(tokenA, tokenB));
        _registerPoolWithVault(pool);
        _registerPoolWithFactory(pool); // BUG: already registered above
    }
}

contract MockPool {
    constructor(address, address) {}
}
