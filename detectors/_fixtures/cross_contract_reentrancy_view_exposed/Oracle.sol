// SPDX-License-Identifier: MIT
// External observer half of the multi-contract fixture for burn-down
// item #5. The Oracle reads Pool.getReserves() / Pool.totalSupply()
// during a callback window — exactly the cross-contract edge a
// per-contract detector would miss.
//
// This file is the SAME in the vulnerable and clean variants. The bug
// is in Pool, not Oracle: Oracle merely demonstrates that a
// cross-contract callgraph edge exists. A correct detector must
// follow the edge from `quote()` -> `Pool.getReserves()` to know that
// the unguarded view is reachable mid-callback.
pragma solidity ^0.8.20;

interface IPool {
    function getReserves() external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

contract Oracle {
    IPool public pool;

    constructor(address _pool) {
        pool = IPool(_pool);
    }

    // Reads Pool's exposed view — the cross-contract edge the
    // detector must walk. A single-contract scan that only inspects
    // Oracle has no way to know whether the read is safe.
    function quote() external view returns (uint256) {
        return pool.getReserves();
    }

    function quoteSupply() external view returns (uint256) {
        return pool.totalSupply();
    }
}
