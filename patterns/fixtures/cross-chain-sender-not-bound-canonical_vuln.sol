// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// cross-chain-sender-not-bound-canonical detector. DO NOT DEPLOY.
///
/// `finalizeDeposit` is the receive-side entry point but never enforces
/// that msg.sender is the canonical messenger. Any EOA can invoke it
/// directly and mint tokens on this chain with no corresponding lock on
/// the remote chain. A per-message replay guard is intentionally
/// present so this fixture isolates the sender-bind break and does not
/// overlap with the cross-chain-message-replayable detector.
contract FinalizeDepositVuln {
    address public messenger;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processed;

    constructor(address _messenger) {
        messenger = _messenger;
    }

    function finalizeDeposit(
        bytes32 msgId,
        address to,
        uint256 amount
    ) external {
        require(!processed[msgId], "replay");
        processed[msgId] = true;
        // Sender bind is missing — any EOA reaches this path.
        balances[to] += amount;
    }
}
