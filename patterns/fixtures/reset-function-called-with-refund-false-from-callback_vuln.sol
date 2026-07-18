// SPDX-License-Identifier: MIT
// Fixture: reset-function-called-with-refund-false-from-callback — VULNERABLE
// Detector MUST fire on this contract.
//
// Mirrors the Polymarket Drafts 1+2 root cause shape: priceDisputed (a
// permissionless oracle callback) calls _reset(..., false, ...) — the
// resetRefund=false branch — without ever flipping `questionData.refund = true`.
// The downstream resolveManually path gates the refund on that flag, so
// the creator's reward is silently stranded at the OO.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

struct QuestionData {
    address creator;
    address rewardToken;
    uint256 reward;
    uint256 requestTimestamp;
    bytes ancillaryData;
    uint256 proposalBond;
    uint256 liveness;
    bool resolved;
    bool reset;
    bool refund;
}

contract UmaCtfAdapterVuln {
    mapping(bytes32 => QuestionData) public questions;
    address public optimisticOracle;

    modifier onlyOptimisticOracle() {
        require(msg.sender == optimisticOracle, "NotOO");
        _;
    }

    // Permissionless oracle callback — name matches /^priceDisputed$/.
    // VULN: ends with `_reset(..., false, ...)` and never sets refund=true.
    function priceDisputed(
        bytes32,
        uint256,
        bytes memory ancillaryData,
        uint256
    ) external onlyOptimisticOracle {
        bytes32 questionID = keccak256(ancillaryData);
        QuestionData storage questionData = questions[questionID];
        if (questionData.resolved) {
            IERC20(questionData.rewardToken).transfer(questionData.creator, questionData.reward);
            return;
        }
        if (questionData.reset) {
            questionData.refund = true;
            return;
        }
        // VULN: third arg is the resetRefund flag; passing `false` puts
        // the refund flag into the un-set state, and we never compensate.
        _reset(address(this), questionID, false, questionData);
    }

    // Second callback surface — same vulnerable shape via onPriceSettled.
    function onPriceSettled(bytes32 questionID) external onlyOptimisticOracle {
        QuestionData storage questionData = questions[questionID];
        _reset(address(this), questionID, false, questionData);
    }

    // Third surface — onCallback variant. Same vulnerable shape.
    function onCallback(bytes32 questionID) external onlyOptimisticOracle {
        QuestionData storage questionData = questions[questionID];
        _reset(address(this), questionID, false, questionData);
    }

    // Internal helper — only sets refund=false in one branch, never sets it true.
    function _reset(address requestor, bytes32 questionID, bool resetRefund, QuestionData storage questionData)
        internal
    {
        questionData.requestTimestamp = block.timestamp;
        questionData.reset = true;
        if (resetRefund) questionData.refund = false; // never sets true
        // _requestPrice consumes the refunded reward into a fresh OO request.
        _requestPrice(requestor, questionData);
        emit QuestionReset(questionID);
    }

    function _requestPrice(address, QuestionData storage) internal {}

    event QuestionReset(bytes32 indexed questionID);
}
