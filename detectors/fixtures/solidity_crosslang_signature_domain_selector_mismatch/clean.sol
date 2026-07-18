// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelectorDomainReplayClean {
    bytes32 private constant ACTION_TYPEHASH =
        keccak256("SignedAction(address user,bytes4 selector,uint256 amount,uint256 nonce)");

    struct SignedAction {
        address user;
        bytes4 selector;
        uint256 amount;
        uint256 nonce;
    }

    mapping(address => uint256) public rewardDebt;

    function claimRewards(
        SignedAction calldata action,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _verifyAction(action, v, r, s);
        rewardDebt[action.user] += action.amount;
    }

    function cancelWithdrawal(
        SignedAction calldata action,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _verifyAction(action, v, r, s);
        rewardDebt[action.user] -= action.amount;
    }

    function _verifyAction(
        SignedAction calldata action,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view {
        require(action.selector == msg.sig, "selector mismatch");

        bytes32 digest = keccak256(
            abi.encode(
                ACTION_TYPEHASH,
                action.user,
                action.selector,
                action.amount,
                action.nonce
            )
        );
        address signer = ecrecover(digest, v, r, s);
        require(signer == action.user, "bad sig");
    }
}
