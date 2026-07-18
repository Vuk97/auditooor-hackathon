// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPoolManager {
    function swap(bytes calldata) external returns (int256 delta);
    function settle(address c) external payable;
    function take(address c, address to, uint256 amount) external;
}

contract V4HookUnsettledDeltaClean {
    IPoolManager public manager;

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        int256 delta = manager.swap(data);
        if (delta < 0) manager.settle(address(0));
        else if (delta > 0) manager.take(address(0), msg.sender, uint256(delta));
        return abi.encode(delta);
    }
}
