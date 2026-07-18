// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Mutation base: a SOLIDITY-level delegatecall (caught by has_low_level_delegatecall,
// MISSED by asm_delegatecalls). The mutation test rewrites this `.delegatecall(...)`
// into a Yul `delegatecall(...)` and asserts asm_delegatecalls flips [] -> [hit]
// (closing the blind spot the solidity-only predicate had).
contract AsmSolidityDelegatecallBase {
    address implementation;

    function forward(bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = implementation.delegatecall(data);
    }
}
