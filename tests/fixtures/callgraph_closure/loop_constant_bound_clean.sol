// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (e): a constant-bounded loop (and a param-bounded one). Neither reads a
// state variable in its bound, so unbounded_loop_suspect=FALSE (never-FP).
contract LoopConstantBoundClean {
    uint256 public total;

    function constLoop() external {
        for (uint256 i = 0; i < 10; i++) {
            total += i;
        }
    }

    function paramLoop(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            total += i;
        }
    }
}
