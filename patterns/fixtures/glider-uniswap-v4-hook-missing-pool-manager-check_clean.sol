// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPoolManager { struct PoolKey { address c0; address c1; uint24 fee; int24 tickSpacing; address hooks; } }

contract HookClean {
    address public poolManager;
    uint256 public lastSwapAmount;

    modifier onlyPoolManager() { require(msg.sender == poolManager, "not PM"); _; }

    // CLEAN: onlyPoolManager gate
    function beforeSwap(address, IPoolManager.PoolKey calldata, bytes calldata data) external onlyPoolManager returns (bytes4) {
        lastSwapAmount = abi.decode(data, (uint256));
        return bytes4(0);
    }
}
