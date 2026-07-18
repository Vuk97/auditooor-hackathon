// SPDX-License-Identifier: MIT
// Fixture: flag-unflag-race-delay-period-zero — CLEAN
// Detector MUST NOT fire on this contract.
//
// Same Operator shape as the vuln fixture, but `resolveQuestion` enforces a
// non-zero cooldown via `block.timestamp >= flaggedAt + DELAY` so the admin's
// emergency-resolve path cannot be preempted.
//
// Note: contract-level precondition `contract.has_function_body_matching:
// DELAY_PERIOD\s*=\s*0` would also be satisfied here (we keep the literal in a
// commented field for documentation symmetry but the real value is non-zero).
// The function-level negative regex catches the cooldown enforcement and
// short-circuits the match.
pragma solidity 0.8.19;

interface INRAdapter {
    function reportOutcome(bytes32 qid, bool result) external;
}

contract CleanNegRiskOperator {
    address public admin;
    INRAdapter public nrAdapter;

    mapping(bytes32 => uint256) public reportedAt;
    mapping(bytes32 => uint256) public flaggedAt;
    mapping(bytes32 => bool) public results;
    mapping(bytes32 => bool) public flagged;

    // Keep the literal so the contract-level precondition still applies, but
    // bind a non-zero working delay through a separate constant.
    uint256 public constant LEGACY_DELAY_PERIOD = 0;
    uint256 public constant DELAY_PERIOD = 24 hours;

    error ResultNotAvailable();
    error DelayPeriodNotOver();
    error NotFlagged();
    error OnlyAdmin();

    modifier onlyAdmin() { if (msg.sender != admin) revert OnlyAdmin(); _; }

    constructor(address _adapter) { admin = msg.sender; nrAdapter = INRAdapter(_adapter); }

    function reportPrice(bytes32 qid, bool r) external {
        reportedAt[qid] = block.timestamp;
        results[qid] = r;
    }

    function flagQuestion(bytes32 qid) external onlyAdmin {
        flagged[qid] = true;
        flaggedAt[qid] = block.timestamp;
    }

    function unflagQuestion(bytes32 qid) external onlyAdmin {
        if (flaggedAt[qid] == 0) revert NotFlagged();
        flagged[qid] = false;
        // Do NOT zero flaggedAt — it gates the cooldown.
    }

    // CLEAN: `resolveQuestion` references `flagged` (positive anchor) AND
    // enforces `require(block.timestamp >= flaggedAt[qid] + DELAY_PERIOD)`
    // — exactly the shape the DSL negative-regex recognises. Detector MUST
    // NOT fire.
    function resolveQuestion(bytes32 qid) external {
        require(!flagged[qid], "isFlagged");
        uint256 t = reportedAt[qid];
        if (t == 0) revert ResultNotAvailable();
        // Cooldown enforcement — both shapes the negative regex accepts:
        //   1. block.timestamp >= flaggedAt + DELAY
        //   2. flaggedAt + ... arithmetic
        require(block.timestamp >= flaggedAt[qid] + DELAY_PERIOD, "cooldown");
        nrAdapter.reportOutcome(qid, results[qid]);
    }

    function emergencyResolveQuestion(bytes32 qid, bool r) external onlyAdmin {
        require(flagged[qid], "OnlyFlagged");
        nrAdapter.reportOutcome(qid, r);
    }
}
