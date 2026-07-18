// SPDX-License-Identifier: MIT
// Fixture: reset-function-called-with-refund-false-from-callback — CLEAN
// Detector MUST NOT fire on this contract.
//
// Mitigation matches the Polymarket Drafts 1+2 recommendation: every
// permissionless callback that calls `_reset(..., false, ...)` also
// explicitly flips `questionData.refund = true;` so that the downstream
// resolveManually path's `if (questionData.refund) _refund(...)` gate
// always fires and the creator is refunded.
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

contract UmaCtfAdapterClean {
    mapping(bytes32 => QuestionData) public questions;
    address public optimisticOracle;

    modifier onlyOptimisticOracle() {
        require(msg.sender == optimisticOracle, "NotOO");
        _;
    }

    // CLEAN: callback still calls `_reset(..., false, ...)` but explicitly
    // sets `questionData.refund = true;` immediately afterwards so the
    // downstream resolveManually gate is reached.
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
        _reset(address(this), questionID, false, questionData);
        // CLEAN: explicit flag-set after the reset.
        questionData.refund = true;
    }

    // CLEAN: alternative mitigation — pass `true` so _reset's resetRefund
    // branch can also fold in the flag-set internally.
    function onPriceSettled(bytes32 questionID) external onlyOptimisticOracle {
        QuestionData storage questionData = questions[questionID];
        _reset(address(this), questionID, true, questionData);
        questionData.refund = true;
    }

    // Internal helper — also folds the flag-set into the !resetRefund branch
    // so even if a future caller forgets to set refund=true, the bookkeeping
    // stays consistent.
    function _reset(address requestor, bytes32 questionID, bool resetRefund, QuestionData storage questionData)
        internal
    {
        questionData.requestTimestamp = block.timestamp;
        questionData.reset = true;
        if (resetRefund) {
            questionData.refund = false;
        } else {
            questionData.refund = true;
        }
        _requestPrice(requestor, questionData);
        emit QuestionReset(questionID);
    }

    function _requestPrice(address, QuestionData storage) internal {}

    event QuestionReset(bytes32 indexed questionID);
}
