// SPDX-License-Identifier: MIT
// Fixture: resolve-gated-on-flag-that-callback-path-never-sets — VULNERABLE
// Detector MUST fire on this contract.
//
// Mirrors the Polymarket Draft 2 read-side shape: resolveManually gates
// the creator refund on `questionData.refund`, but the function itself
// never sets that flag. If any upstream callback path failed to flip
// `refund = true` (see sibling pattern), the gate is silently skipped.
pragma solidity ^0.8.20;

interface IConditionalTokens {
    function reportPayouts(bytes32 questionID, uint256[] calldata payouts) external;
}

struct QuestionData {
    address creator;
    address rewardToken;
    uint256 reward;
    bool resolved;
    bool reset;
    bool refund;
}

contract UmaCtfAdapterVuln {
    mapping(bytes32 => QuestionData) public questions;
    IConditionalTokens public ctf;
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "NotAdmin");
        _;
    }

    // VULN: external resolveManually gates refund on `questionData.refund`
    // but never writes to that flag itself. If the upstream priceDisputed
    // callback used `_reset(..., false, ...)` and forgot to set the flag,
    // this branch is silently skipped and the creator is never refunded.
    function resolveManually(bytes32 questionID, uint256[] calldata payouts) external onlyAdmin {
        QuestionData storage questionData = questions[questionID];
        questionData.resolved = true;

        // Read-only flag-gate — never sets refund=true here.
        if (questionData.refund) {
            _refund(questionData);
        }

        ctf.reportPayouts(questionID, payouts);
        emit QuestionManuallyResolved(questionID, payouts);
    }

    // Second resolution surface — `resolve` naming, same read-only-gate bug.
    function resolve(bytes32 questionID) external {
        QuestionData storage questionData = questions[questionID];
        if (questionData.refund) {
            _refund(questionData);
        }
        questionData.resolved = true;
    }

    // Third surface — `finalize` naming with shorthand `q.refund`.
    function finalize(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        if (q.refund) {
            _refund(q);
        }
        q.resolved = true;
    }

    function _refund(QuestionData storage q) internal {
        // would transfer reward back to q.creator
        q;
    }

    event QuestionManuallyResolved(bytes32 indexed questionID, uint256[] payouts);
}
