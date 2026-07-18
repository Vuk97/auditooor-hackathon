// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Negative-detection fixture: a plain counter contract that exposes
// no ERC4626 surface. The capv3 iter-001 T4 campaign emitter must
// refuse to emit harnesses against this workspace.
contract Counter {
    uint256 public count;
    function increment() external { count += 1; }
    function set(uint256 v) external { count = v; }
}
