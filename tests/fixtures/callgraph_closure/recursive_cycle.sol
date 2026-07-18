// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (d): recursive / mutually-recursive call cycle.
// `a()` -> `b()` -> `a()` (mutual recursion) and `loop()` -> `loop()`
// (self recursion). The closure traversal MUST terminate via the visited-set
// cycle-guard rather than recursing forever / overflowing the stack.
contract RecursiveCycle {
    uint256 public x;

    function a(uint256 n) internal {
        if (n > 0) {
            b(n - 1);
        }
    }

    function b(uint256 n) internal {
        if (n > 0) {
            a(n - 1);
        }
    }

    function loop(uint256 n) internal {
        if (n > 0) {
            loop(n - 1); // self-recursion
        }
        x += 1;
    }

    function entryRec(uint256 n) external {
        a(n);
        loop(n);
    }
}
