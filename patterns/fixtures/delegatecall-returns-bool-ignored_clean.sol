// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: reverts immediately on a failed delegatecall and bubbles up the
// callee's revert reason so the caller sees the true failure cause.
contract DelegatecallBoolChecked {
    address public implementation;
    uint256 public lastBlock;

    constructor(address impl) {
        implementation = impl;
    }

    function execute(bytes calldata data) external returns (bytes memory) {
        lastBlock = block.number;
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
