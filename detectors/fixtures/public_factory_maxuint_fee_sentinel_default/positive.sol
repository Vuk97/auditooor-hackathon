// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pool {
    uint256 public immutable amp;
    uint256 public immutable feeBps;

    constructor(uint256 _amp, uint256 _feeBps) {
        amp = _amp;
        feeBps = _feeBps;
    }
}

contract PoolFactory {
    uint256 public constant DEFAULT_FEE_BPS = 30;
    address public lastPool;

    function createPool(uint256 amp, uint256 feeBps) external returns (address pool) {
        if (feeBps == type(uint256).max) {
            feeBps = DEFAULT_FEE_BPS;
        }

        pool = address(new Pool(amp, feeBps));
        lastPool = pool;
    }
}
