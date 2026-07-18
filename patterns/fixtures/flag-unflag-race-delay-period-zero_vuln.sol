// SPDX-License-Identifier: MIT
// Fixture: flag-unflag-race-delay-period-zero — VULNERABLE
// Detector MUST fire on this contract.
//
// Polymarket Draft 5 shape: an Operator-style contract has a permissionless
// resolveQuestion gated by `onlyNotFlagged`, an admin flag/unflag pair, and
// the safety cooldown constant DELAY_PERIOD = 0 → zero-width window. Admin's
// emergencyResolveQuestion can be preempted by a mempool bundle.
pragma solidity 0.8.19;

interface INRAdapter {
    function reportOutcome(bytes32 qid, bool result) external;
}

contract VulnNegRiskOperator {
    address public admin;
    INRAdapter public nrAdapter;

    mapping(bytes32 => uint256) public reportedAt;
    mapping(bytes32 => uint256) public flaggedAt;
    mapping(bytes32 => bool) public results;
    mapping(bytes32 => bool) public flagged;

    // ROOT CAUSE: zero-width safety window.
    uint256 public constant DELAY_PERIOD = 0;

    error ResultNotAvailable();
    error DelayPeriodNotOver();
    error NotFlagged();
    error OnlyAdmin();

    modifier onlyAdmin() { if (msg.sender != admin) revert OnlyAdmin(); _; }
    modifier onlyNotFlagged(bytes32 qid) { require(!flagged[qid], "flagged"); _; }

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
        flaggedAt[qid] = 0;
    }

    // VULN: permissionless resolve, gated only by `onlyNotFlagged` and a
    // tautological `block.timestamp >= reportedAt + DELAY_PERIOD` check
    // (DELAY_PERIOD = 0). Body references `flagged` for the negative regex's
    // positive anchor, but provides NO `DELAY_PERIOD > 0` /
    // `block.timestamp >= flaggedAt + DELAY` / `flaggedAt + ...` guard.
    // Detector MUST fire — contract name matches `Operator`, function name
    // matches `resolveQuestion`.
    function resolveQuestion(bytes32 qid) external onlyNotFlagged(qid) {
        require(!flagged[qid], "isFlagged");
        uint256 t = reportedAt[qid];
        if (t == 0) revert ResultNotAvailable();
        // Tautology when DELAY_PERIOD = 0 — the comparison passes immediately.
        if (block.timestamp < t + DELAY_PERIOD) revert DelayPeriodNotOver();
        nrAdapter.reportOutcome(qid, results[qid]);
    }

    function emergencyResolveQuestion(bytes32 qid, bool r) external onlyAdmin {
        require(flagged[qid], "OnlyFlagged");
        nrAdapter.reportOutcome(qid, r);
    }
}
