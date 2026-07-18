// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: explicitly asserts the delegatecall target is a contract.
// `target.code.length > 0` rules out EOAs and freshly-self-destructed
// addresses, so the caller no longer silently executes a no-op that
// the caller's post-call logic would otherwise treat as success.
contract DelegatecallContractChecked {
    address public implementation;

    function setImplementation(address impl) external {
        implementation = impl;
    }

    function execute(bytes calldata data) external returns (bytes memory) {
        require(implementation.code.length > 0, "target not a contract");
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
