// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: delegatecalls into `target` without verifying `target` is a
// contract. If `target` happens to be an EOA, the EVM returns
// success=true with no code run — the caller's state transition that
// was supposed to happen inside the delegatecall silently does not
// occur, yet the caller proceeds as if it did.
contract DelegatecallNoContractCheck {
    address public implementation;

    function setImplementation(address impl) external {
        implementation = impl;
    }

    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "delegatecall failed"); // true even when impl is an EOA
        return ret;
    }
}
