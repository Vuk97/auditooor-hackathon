// SPDX-License-Identifier: MIT
// OptimismPortalStub.sol — Replay-harness stub for OptimismPortal2.
//
// Production faithfulness scope: models withdrawalProven + finalizeWithdrawal
// lifecycle including guardian pause, finalization window, and re-entrancy
// lock. Does NOT model SecureMerkleTrie inclusion proof (replaced by
// registeredWithdrawals map) or L2OutputOracle slot verification.
//
// Faithfully models (6 of 7 production checks):
//   1. _checkPause(): guardian-controlled paused flag.
//   2. withdrawalProven[withdrawalHash] existence check before finalizeWithdrawal.
//   3. finalizedWithdrawals[withdrawalHash] replay-protection check.
//   4. finalizationPeriodSeconds elapsed since proven timestamp.
//   5. ETH/ERC20 fund transfer on finalizeWithdrawal (via low-level call).
//   6. Re-entrancy guard (l2Sender lock pattern).
// Intentionally simplified (1 of 7):
//   7. SecureMerkleTrie inclusion proof: replaced by operator-registered
//      withdrawals map. Justification: the attack class (FN2) targets
//      withdrawal hijacking after the proof window opens; Merkle verification
//      is a precondition that the attacker already satisfies on mainnet.
//
// Usage: supply as --override-contract OptimismPortal=<path> in fork-replay.py
//        or as a forge test dependency for hermetic harness builds.
//
// Compile: forge build (solc ^0.8.15)
pragma solidity ^0.8.15;

contract OptimismPortalStub {
    // ── Storage ──────────────────────────────────────────────────────────────

    address public immutable GUARDIAN;
    bool public paused;

    uint256 public finalizationPeriodSeconds = 7 days;

    /// @dev Replaces SecureMerkleTrie: operator registers withdrawal hashes.
    mapping(bytes32 => bool) public registeredWithdrawals;

    struct ProvenWithdrawal {
        address l2Sender;
        address target;
        uint256 value;
        uint256 gasLimit;
        bytes data;
        uint128 timestamp;
        bool proven;
    }

    mapping(bytes32 => ProvenWithdrawal) public withdrawalProven;
    mapping(bytes32 => bool) public finalizedWithdrawals;

    /// @dev Re-entrancy guard — mirrors OptimismPortal2 l2Sender lock.
    address private constant _DEFAULT_L2_SENDER = address(1);
    address public l2Sender = _DEFAULT_L2_SENDER;

    // ── Events ────────────────────────────────────────────────────────────────
    event WithdrawalProven(bytes32 indexed withdrawalHash, address indexed from, address indexed to);
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success);

    // ── Constructor ───────────────────────────────────────────────────────────
    constructor(address guardian) {
        GUARDIAN = guardian;
    }

    // ── Guardian pause (check #1) ─────────────────────────────────────────────
    modifier whenNotPaused() {
        require(!paused, "OptimismPortalStub: paused");
        _;
    }

    function pause() external {
        require(msg.sender == GUARDIAN, "not guardian");
        paused = true;
    }

    function unpause() external {
        require(msg.sender == GUARDIAN, "not guardian");
        paused = false;
    }

    // ── Registration (stub-only; replaces Merkle proof) ───────────────────────
    /// @notice Operator-only helper that bypasses Merkle verification.
    ///         This is a stub-only function — no equivalent in production.
    function registerWithdrawal(bytes32 withdrawalHash) external {
        registeredWithdrawals[withdrawalHash] = true;
    }

    // ── proveWithdrawal (checks #1, #7-stub) ─────────────────────────────────
    function proveWithdrawal(
        bytes32 withdrawalHash,
        address l2SenderAddr,
        address target,
        uint256 value,
        uint256 gasLimit,
        bytes calldata data
    ) external whenNotPaused {
        // Stub: accept if operator registered this hash (replaces Merkle proof)
        require(registeredWithdrawals[withdrawalHash], "proof not registered (stub)");
        require(!withdrawalProven[withdrawalHash].proven, "already proven");

        withdrawalProven[withdrawalHash] = ProvenWithdrawal({
            l2Sender: l2SenderAddr,
            target: target,
            value: value,
            gasLimit: gasLimit,
            data: data,
            timestamp: uint128(block.timestamp),
            proven: true
        });
        emit WithdrawalProven(withdrawalHash, l2SenderAddr, target);
    }

    // ── finalizeWithdrawal (checks #2, #3, #4, #5, #6) ───────────────────────
    function finalizeWithdrawal(bytes32 withdrawalHash) external whenNotPaused {
        // Check #2: must be proven
        ProvenWithdrawal storage pw = withdrawalProven[withdrawalHash];
        require(pw.proven, "not proven");

        // Check #3: replay protection
        require(!finalizedWithdrawals[withdrawalHash], "already finalized");

        // Check #4: finalization window
        require(
            block.timestamp >= pw.timestamp + finalizationPeriodSeconds,
            "finalization period not elapsed"
        );

        // Check #6: re-entrancy guard (l2Sender lock)
        require(l2Sender == _DEFAULT_L2_SENDER, "re-entrant call");
        l2Sender = pw.l2Sender;

        // Mark finalized before external call (CEI pattern)
        finalizedWithdrawals[withdrawalHash] = true;

        // Check #5: fund transfer
        (bool ok,) = pw.target.call{value: pw.value, gas: pw.gasLimit}(pw.data);

        l2Sender = _DEFAULT_L2_SENDER;
        emit WithdrawalFinalized(withdrawalHash, ok);
    }

    // ── Receive ETH (for testing) ─────────────────────────────────────────────
    receive() external payable {}
}
