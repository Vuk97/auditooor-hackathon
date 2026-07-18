// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPoolManager { struct PoolKey { address c0; address c1; uint24 fee; int24 tickSpacing; address hooks; } }

contract HookVuln {
    address public poolManager;
    uint256 public lastSwapAmount;

    // VULN: hook function has no access control -- caller not restricted to pool manager
    function beforeSwap(address, IPoolManager.PoolKey calldata, bytes calldata data) external returns (bytes4) {
        lastSwapAmount = abi.decode(data, (uint256));
        return bytes4(0);
    }
}
