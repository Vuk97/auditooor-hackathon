// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FLAGGED: the bool `success` of `.call` is discarded. On a failed callee the tx
// silently continues (the canonical "unchecked low-level call return" bug).
contract UncheckedLowLevelCallSuspect {
    function forward(address to, bytes calldata data) external {
        to.call(data);
    }

    function send_eth(address payable to, uint256 amount) external {
        to.send(amount);
    }
}
