// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Trivially clean counter library. No state external to itself, no
///         privileged actions, no value movement. If a detector fires on
///         this file under FP calibration it is by definition an FP.
library Counter {
    struct Slot {
        uint256 value;
    }

    function increment(Slot storage s) internal {
        unchecked {
            s.value += 1;
        }
    }

    function decrement(Slot storage s) internal {
        require(s.value > 0, "Counter: underflow");
        unchecked {
            s.value -= 1;
        }
    }

    function reset(Slot storage s) internal {
        s.value = 0;
    }
}
