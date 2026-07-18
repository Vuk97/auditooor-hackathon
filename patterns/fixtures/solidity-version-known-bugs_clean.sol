// SPDX-License-Identifier: MIT
// CLEAN: pragma targets 0.8.24, which is not on the known-bugs list.
pragma solidity 0.8.24;

contract CleanPragma {
    uint256 public value;

    constructor() {
        value = 1;
    }

    function set(uint256 v) external {
        value = v;
    }
}
