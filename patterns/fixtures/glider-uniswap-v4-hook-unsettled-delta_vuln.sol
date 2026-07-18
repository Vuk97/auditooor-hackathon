// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPoolManager {
    function swap(bytes calldata) external returns (int256 delta);
}

contract V4HookUnsettledDeltaVuln {
    IPoolManager public manager;

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        int256 delta = manager.swap(data);
        // BalanceDelta owed but no settle/take before return
        return abi.encode(delta);
    }
}
