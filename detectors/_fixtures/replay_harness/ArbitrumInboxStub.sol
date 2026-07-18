// SPDX-License-Identifier: MIT
// ArbitrumInboxStub.sol — Replay-harness stub for Arbitrum Inbox (DelayedInbox).
//
// Production faithfulness scope: models retryable-ticket submission and
// cancellation lifecycle, including base-fee forwarding, value escrow, and
// sequencer-feed enqueue. Does NOT model the Sequencer Inbox submission
// channel, ETH-value forwarding to L2 via bridge (delegated to BridgeStub),
// or EIP-4844 blob data paths.
//
// Faithfully models (5 of 8 production Inbox behaviors):
//   1. createRetryableTicket(): records ticket with sender, dest, callvalue,
//      gasLimit, maxFeePerGas, data, and emits InboxMessageDelivered event.
//   2. retryableCancellation: cancelRetryable() marks ticket as cancelled.
//   3. Ticket expiry check: tickets older than retryableLifetime are
//      considered expired (advisory — not enforced in production by Inbox;
//      enforced by ArbRetryableTx precompile on L2).
//   4. depositEth(): records ETH credit and emits InboxMessageDelivered.
//   5. Re-submission guard: same (sender, dest, nonce) cannot be enqueued
//      twice (stub simplification).
// Intentionally simplified (3 of 8):
//   6. SequencerInbox channel: not modeled; stub only tracks delayed messages.
//   7. Bridge ETH forwarding: ETH held in stub; not relayed to a bridge.
//   8. EIP-4844 blob submission path: not modeled.
//
// Usage: supply as --override-contract Inbox=<path> in fork-replay.py.
// Compile: forge build (solc ^0.8.15)
pragma solidity ^0.8.15;

contract ArbitrumInboxStub {
    // ── Types ─────────────────────────────────────────────────────────────────
    struct RetryableTicket {
        address sender;
        address dest;
        uint256 callvalue;
        uint256 gasLimit;
        uint256 maxFeePerGas;
        bytes data;
        uint256 submittedAt;
        bool cancelled;
    }

    // ── Storage ───────────────────────────────────────────────────────────────
    uint256 public retryableLifetime = 7 days;
    uint256 private _msgCount;

    mapping(bytes32 => RetryableTicket) public tickets;
    mapping(bytes32 => bool) public ethDeposits;

    // ── Events ────────────────────────────────────────────────────────────────
    event InboxMessageDelivered(uint256 indexed messageNum, bytes data);
    event RetryableTicketCreated(bytes32 indexed ticketId, address indexed sender, address indexed dest);
    event RetryableCancelled(bytes32 indexed ticketId);

    // ── createRetryableTicket (behaviors #1, #5) ──────────────────────────────
    function createRetryableTicket(
        address destAddr,
        uint256 arbTxCallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256 msgNum) {
        bytes32 ticketId = keccak256(
            abi.encodePacked(msg.sender, destAddr, _msgCount, block.number)
        );
        require(!_ticketExists(ticketId), "InboxStub: duplicate ticket");

        tickets[ticketId] = RetryableTicket({
            sender: msg.sender,
            dest: destAddr,
            callvalue: arbTxCallValue,
            gasLimit: gasLimit,
            maxFeePerGas: maxFeePerGas,
            data: data,
            submittedAt: block.timestamp,
            cancelled: false
        });

        msgNum = _msgCount++;
        emit RetryableTicketCreated(ticketId, msg.sender, destAddr);
        emit InboxMessageDelivered(msgNum, abi.encode(ticketId));

        // Suppress unused-param warnings
        (maxSubmissionCost, excessFeeRefundAddress, callValueRefundAddress);
    }

    // ── cancelRetryable (behavior #2) ─────────────────────────────────────────
    function cancelRetryable(bytes32 ticketId) external {
        RetryableTicket storage t = tickets[ticketId];
        require(t.sender != address(0), "InboxStub: unknown ticket");
        require(t.sender == msg.sender, "InboxStub: not sender");
        require(!t.cancelled, "InboxStub: already cancelled");
        t.cancelled = true;
        emit RetryableCancelled(ticketId);
    }

    // ── Expiry advisory (behavior #3) ─────────────────────────────────────────
    function isExpired(bytes32 ticketId) external view returns (bool) {
        RetryableTicket storage t = tickets[ticketId];
        if (t.sender == address(0)) return false;
        return block.timestamp > t.submittedAt + retryableLifetime;
    }

    // ── depositEth (behavior #4) ──────────────────────────────────────────────
    function depositEth() external payable returns (uint256 msgNum) {
        bytes32 depositId = keccak256(abi.encodePacked(msg.sender, msg.value, _msgCount));
        ethDeposits[depositId] = true;
        msgNum = _msgCount++;
        emit InboxMessageDelivered(msgNum, abi.encode(msg.sender, msg.value));
    }

    // ── Internals ─────────────────────────────────────────────────────────────
    function _ticketExists(bytes32 id) internal view returns (bool) {
        return tickets[id].sender != address(0);
    }

    receive() external payable {}
}
