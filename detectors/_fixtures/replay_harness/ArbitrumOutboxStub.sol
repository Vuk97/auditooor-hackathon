// SPDX-License-Identifier: MIT
// ArbitrumOutboxStub.sol — Replay-harness stub for Arbitrum Outbox.
//
// Production faithfulness scope: models L2-to-L1 message proof verification
// and executeTransaction lifecycle, including spent-path replay protection.
// Does NOT model the full Merkle-tree proof (replaced by operator-registered
// leaf hashes), nor bridge ETH release (ETH held in stub).
//
// Faithfully models (4 of 6 production Outbox behaviors):
//   1. executeTransaction(): verifies proof, marks leaf as spent, calls target.
//   2. Replay protection: spentLeaf[leafIndex] prevents double-spend.
//   3. Re-entrancy guard: context lock prevents nested executeTransaction.
//   4. calldata + value forwarding to l1Dest via low-level call.
// Intentionally simplified (2 of 6):
//   5. Merkle proof verification: replaced by operator-registered allowedLeaves
//      map. Justification: attack class targets post-proof execution; Merkle
//      verification is a precondition satisfied by attacker on mainnet.
//   6. Bridge ETH release: ETH held in stub contract, not forwarded to
//      a BridgeProxy. Justification: fund-flow assertion only needs stub balance.
//
// Usage: supply as --override-contract Outbox=<path> in fork-replay.py.
// Compile: forge build (solc ^0.8.15)
pragma solidity ^0.8.15;

contract ArbitrumOutboxStub {
    // ── Storage ───────────────────────────────────────────────────────────────
    /// @dev Stub-only: operator registers leaf hashes that may be executed.
    mapping(uint256 => bool) public allowedLeaves;
    mapping(uint256 => bool) public spentLeaf;

    /// @dev Re-entrancy context (mirrors production _activeOutbox lock)
    bool private _executing;

    // ── Events ────────────────────────────────────────────────────────────────
    event OutBoxTransactionExecuted(
        address indexed destAddr,
        address indexed l2Sender,
        uint256 indexed outboxIndex,
        uint256 transactionIndex
    );

    // ── Stub-only: leaf registration ──────────────────────────────────────────
    function registerLeaf(uint256 leafIndex) external {
        allowedLeaves[leafIndex] = true;
    }

    // ── executeTransaction (behaviors #1, #2, #3, #4) ─────────────────────────
    function executeTransaction(
        uint256[] calldata /* proof */,
        uint256 index,
        address l2Sender,
        address destAddr,
        uint256 /* l2Block */,
        uint256 /* l1Block */,
        uint256 /* l2Timestamp */,
        uint256 value,
        bytes calldata data
    ) external {
        // Behavior #1: proof check (stub: must be in allowedLeaves)
        require(allowedLeaves[index], "OutboxStub: leaf not registered");

        // Behavior #2: replay protection
        require(!spentLeaf[index], "OutboxStub: already spent");

        // Behavior #3: re-entrancy guard
        require(!_executing, "OutboxStub: re-entrant call");
        _executing = true;

        // Mark spent before external call (CEI)
        spentLeaf[index] = true;

        // Behavior #4: forward call + value
        (bool ok,) = destAddr.call{value: value}(data);
        require(ok, "OutboxStub: call failed");

        _executing = false;
        emit OutBoxTransactionExecuted(destAddr, l2Sender, 0, index);
    }

    receive() external payable {}
}
