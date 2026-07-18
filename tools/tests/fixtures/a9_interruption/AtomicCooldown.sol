// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// COUNTER-CASE (must NOT fire): the phase-1 creator ALSO settles the record atomically in its
// own body (push + pop), so a single fn writes all of S. This is the FP-guard / flush-group
// boundary - the `atomic` predicate excludes it even though a separate settle fn also exists.
// Drop the `atomic or ...` guard and this fixture WRONGLY fires (predicate is load-bearing).
contract AtomicCooldown {
    struct TRequest { uint64 unlockAt; uint192 shares; }
    mapping(address account => TRequest[] requests) public activeRequests;

    // phase-1 that ALSO settles atomically (create + settle in ONE body)
    function requestRedeem(
        address to,
        uint256 shares,
        bool settleNow
    ) external {
        TRequest[] storage requests = activeRequests[to];
        requests.push(TRequest(uint64(block.timestamp), uint192(shares)));
        if (settleNow) {
            requests.pop();
        }
    }

    // a separate settle-only body ALSO exists (so creators+settlers are non-empty)
    function finalize(address user, uint256 i) external {
        TRequest[] storage requests = activeRequests[user];
        requests[i] = requests[requests.length - 1];
        requests.pop();
    }
}
