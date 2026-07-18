// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal two-phase cooldown mirroring the strata SharesCooldown shape: phase-1 CREATES a
// pending request record (push into the request array); the SETTLE (pop) lives ONLY in a
// separate finalize/cancel body. No single fn both creates AND settles -> interruption split.
contract SplitCooldown {
    struct TRequest { uint64 unlockAt; uint192 shares; }
    mapping(address account => TRequest[] requests) public activeRequests;

    // phase-1: CREATE only (multiline signature on purpose, like the real target)
    function requestRedeem(
        address to,
        uint256 shares,
        uint32 cooldownSeconds
    ) external {
        TRequest[] storage requests = activeRequests[to];
        requests.push(TRequest(uint64(block.timestamp + cooldownSeconds), uint192(shares)));
    }

    // phase-2: SETTLE only, in a SEPARATE body
    function finalize(address user, uint256 i) external {
        TRequest[] storage requests = activeRequests[user];
        // ... redeem underlying ...
        requests[i] = requests[requests.length - 1];
        requests.pop();
    }

    // recovery is ALSO a separate body (still no single-fn create+settle)
    function cancel(address user, uint256 i) external {
        TRequest[] storage requests = activeRequests[user];
        requests[i] = requests[requests.length - 1];
        requests.pop();
    }
}
