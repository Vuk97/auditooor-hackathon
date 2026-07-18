// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// cross-chain-message-replayable detector. DO NOT DEPLOY.
///
/// `finalizeWithdrawal` is the receive-side entry point for an L2->L1
/// bridge withdrawal. It neither (a) binds `msg.sender` to the canonical
/// `messenger` nor (b) records the message identifier as processed. The
/// same calldata can be replayed by anyone to mint `amount` to `to` on
/// every call, draining the bridge escrow against a single locked deposit.
contract CrossChainReplayVuln {
    address public messenger;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(address _messenger) {
        messenger = _messenger;
    }

    function finalizeWithdrawal(
        bytes32 msgId,
        address to,
        uint256 amount
    ) external {
        // Replay guard and canonical-sender bind are both missing.
        // The identifier parameter is accepted as data but never recorded.
        balances[to] += amount;
        totalSupply += amount;
    }
}
