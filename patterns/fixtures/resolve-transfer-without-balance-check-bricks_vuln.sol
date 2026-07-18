// SPDX-License-Identifier: MIT
// Fixture: resolve-transfer-without-balance-check-bricks — VULNERABLE
// Detector MUST fire on this contract.
//
// Mirrors the Polymarket Draft 3 shape: UmaCtfAdapter._resolve / resolve
// performs an ERC20 transfer to the question creator (or the OO requestor)
// on the ignore-price branch with no prior balance check. If a previous
// dispute callback consumed the adapter's balance, the transfer reverts
// and the entire resolve() call rolls back, bricking the market.
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
}

contract UmaCtfAdapterVuln {
    mapping(bytes32 => QuestionData) public questions;
    int256 internal constant IGNORE_PRICE = type(int256).min;

    // External resolution entrypoint — name matches /^(resolve|_resolve|finalize|close|settle|distribute)/.
    // VULN: ignore-branch performs a transfer to the creator with no
    // balanceOf(address(this)) check and no zero-amount short-circuit.
    // If `reward == 0` or the adapter has been drained by a prior
    // priceDisputed callback, IERC20.transfer reverts and resolve()
    // rolls back, bricking on-chain resolution.
    function resolve(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        int256 price = _oraclePrice(questionID);

        if (price == IGNORE_PRICE) {
            // unconditional transfer of the reward back to the creator
            IERC20(q.rewardToken).transfer(q.creator, q.reward);
            return;
        }

        q.resolved = true;
    }

    // Second resolution surface — same shape, SafeERC20-style call.
    function _resolve(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
        // VULN: no balance check, no zero-amount guard.
        SafeERC20.safeTransfer(IERC20(q.rewardToken), q.creator, q.reward);
        q.resolved = true;
    }

    // Third surface — finalize naming. Same bug.
    function finalize(bytes32 questionID) external {
        QuestionData storage q = questions[questionID];
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
