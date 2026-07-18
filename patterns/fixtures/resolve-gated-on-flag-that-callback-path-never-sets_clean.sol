// SPDX-License-Identifier: MIT
// Fixture: resolve-gated-on-flag-that-callback-path-never-sets — CLEAN
// Detector MUST NOT fire on this contract.
//
// Mitigation: replace the read-only flag-gate with either (a) a direct
// balance check that does not depend on cross-function bookkeeping, or
// (b) set the refund flag inside the same function before reading it.
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

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

contract UmaCtfAdapterClean {
    mapping(bytes32 => QuestionData) public questions;
    IConditionalTokens public ctf;
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "NotAdmin");
        _;
    }

    // CLEAN (a): set the flag inside the resolve path before reading it,
    // based on the actual on-chain state (the contract has the reward
    // balance iff a refund is owed). This removes the cross-function
    // dependency entirely.
    function resolveManually(bytes32 questionID, uint256[] calldata payouts) external onlyAdmin {
        QuestionData storage questionData = questions[questionID];
        questionData.resolved = true;

        // Set the flag locally based on the actual balance, then read it.
        if (IERC20(questionData.rewardToken).balanceOf(address(this)) >= questionData.reward) {
            questionData.refund = true;
        }
        if (questionData.refund) {
            _refund(questionData);
        }

        ctf.reportPayouts(questionID, payouts);
        emit QuestionManuallyResolved(questionID, payouts);
    }

    // CLEAN (b): replace the flag-gate with a direct balance check.
    function resolve(bytes32 questionID) external {
        QuestionData storage questionData = questions[questionID];
        uint256 bal = IERC20(questionData.rewardToken).balanceOf(address(this));
        if (bal >= questionData.reward) {
            _refund(questionData);
        }
        questionData.resolved = true;
    }

    // CLEAN: finalize path also writes refund=true based on on-chain state
    // before any read.
    function finalize(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        if (IERC20(q.rewardToken).balanceOf(address(this)) >= q.reward) {
            q.refund = true;
        }
        if (q.refund) {
            _refund(q);
        }
        q.resolved = true;
    }

    function _refund(QuestionData storage q) internal {
        IERC20(q.rewardToken).transfer(q.creator, q.reward);
    }

    event QuestionManuallyResolved(bytes32 indexed questionID, uint256[] payouts);
}
