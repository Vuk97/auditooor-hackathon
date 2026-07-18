// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: captures the delegatecall success bool but never reverts on
// failure. If the callee reverts mid-way, any state mutation that
// happened before the delegatecall persists, and the post-call path
// runs as if everything succeeded — leaving the contract in a
// partially-applied, silently-inconsistent state.
contract DelegatecallBoolIgnored {
    address public implementation;
    uint256 public lastBlock;

    constructor(address impl) {
        implementation = impl;
    }

    function execute(bytes calldata data) external returns (bytes memory) {
        lastBlock = block.number; // pre-call state mutation (persists even on revert below)
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        // BUG: ok is captured but never checked — silent partial failure.
        return ret;
    }
}
