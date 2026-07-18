// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// gas-bounded loop: termination rests on a per-iteration gas magic number.
contract Batcher {
    bytes32[] queue;
    uint256 head;
    function drain() external {
        while (gasleft() > 50000) {          // <-- gas-bounded-loop
            if (head >= queue.length) break;
            head++;
        }
    }
}
