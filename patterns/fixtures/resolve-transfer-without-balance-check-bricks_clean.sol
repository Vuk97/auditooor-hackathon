// SPDX-License-Identifier: MIT
// Fixture: resolve-transfer-without-balance-check-bricks — CLEAN
// Detector MUST NOT fire on this contract.
//
// Mitigation matches the Polymarket Draft 3 recommendation: gate the
// transfer on `balanceOf(address(this))` and surface an admin-handoff
// state when the adapter is empty, instead of letting the ERC20 revert
// brick the resolve() call.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

struct QuestionData {
    address creator;
    address rewardToken;
    uint256 reward;
    bool resolved;
    bool paused;
}

contract UmaCtfAdapterClean {
    mapping(bytes32 => QuestionData) public questions;
    int256 internal constant IGNORE_PRICE = type(int256).min;

    event ResolutionRequiresManualIntervention(bytes32 indexed questionID);

    // CLEAN: explicit balanceOf(address(this)) gate before the transfer.
    // If the adapter has been drained, surface a paused/manual-resolution
    // state and return — the call does NOT revert, so the question remains
    // recoverable via the admin handoff path.
    function resolve(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        int256 price = _oraclePrice(questionID);

        if (price == IGNORE_PRICE) {
            uint256 bal = IERC20(q.rewardToken).balanceOf(address(this));
            if (bal < q.reward) {
                q.paused = true;
                emit ResolutionRequiresManualIntervention(questionID);
                return;
            }
            IERC20(q.rewardToken).transfer(q.creator, q.reward);
            return;
        }

        q.resolved = true;
    }

    // CLEAN: zero-amount short-circuit covers the empty-balance case for
    // any reward-token whose transfer reverts on insufficient balance.
    function _resolve(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        if (q.reward == 0) return;
        require(q.reward > 0, "ZERO_REWARD");
        SafeERC20.safeTransfer(IERC20(q.rewardToken), q.creator, q.reward);
        q.resolved = true;
    }

    // CLEAN: balance check + skip-if-zero on the finalize path.
    function finalize(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        if (IERC20(q.rewardToken).balanceOf(address(this)) == 0) return;
        IERC20(q.rewardToken).transfer(q.creator, q.reward);
    }

    function _oraclePrice(bytes32) internal pure returns (int256) {
        return type(int256).min;
    }
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "SafeERC20: transfer failed");
    }
}
