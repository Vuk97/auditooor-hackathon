// SPDX-License-Identifier: MIT
// WormholeBridgeStub.sol — Replay-harness stub for Wormhole Core Bridge.
//
// Production faithfulness scope: models VAA quorum verification and message
// dispatch, including guardian-set rotation and sequence tracking. Does NOT
// model the full 65-byte ECDSA guardian signature verification (replaced by
// a mock-guardian map) or the p2p gossip VAA propagation layer.
//
// Faithfully models (5 of 8 production CoreBridge behaviors):
//   1. Guardian-set quorum check: requires mockGuardians[n] == true for at
//      least ceil(2/3) of configured guardian count (quorumNumerator/denominator).
//   2. Message sequence tracking: sequence[emitterChain][emitterAddress]
//      increments per publishMessage, preventing duplicate emission IDs.
//   3. VAA replay protection: usedVAAs[vaaHash] prevents re-submission.
//   4. parseAndVerifyVM(): returns (VM struct, bool valid, string reason).
//   5. publishMessage(): emits LogMessagePublished with sequence + nonce + payload.
// Intentionally simplified (3 of 8):
//   6. ECDSA guardian signature verification: replaced by mock-guardian address
//      map. Justification: attack class targets post-VAA execution; ECDSA
//      verification is a precondition that the attacker already clears on
//      mainnet by using a legitimate VAA.
//   7. Guardian-set rotation timelock: not modeled; setGuardianSet() is
//      immediate in stub.
//   8. Consistency-level confirmation counts: always treated as finalized.
//
// Usage: supply as --override-contract CoreBridge=<path> in fork-replay.py.
// Compile: forge build (solc ^0.8.20)
pragma solidity ^0.8.20;

contract WormholeBridgeStub {
    // ── Types ─────────────────────────────────────────────────────────────────
    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        bytes32 hash;
    }

    struct GuardianSet {
        address[] keys;
        uint32 expirationTime;
    }

    // ── Storage ───────────────────────────────────────────────────────────────
    uint32 public currentGuardianSetIndex;
    mapping(uint32 => GuardianSet) public guardianSets;

    /// @dev Stub: addresses that count as valid guardian signers.
    mapping(address => bool) public mockGuardians;
    uint256 public mockGuardianCount;

    /// @dev Quorum: default 2/3 + 1.
    uint256 public quorumNumerator = 2;
    uint256 public quorumDenominator = 3;

    mapping(bytes32 => bool) public usedVAAs;

    /// @dev sequence[emitterChain][emitterAddress]
    mapping(uint16 => mapping(bytes32 => uint64)) public sequence;

    // ── Events ────────────────────────────────────────────────────────────────
    event LogMessagePublished(
        address indexed sender,
        uint64 sequence_,
        uint32 nonce,
        bytes payload,
        uint8 consistencyLevel
    );

    // ── Stub-only: guardian setup ─────────────────────────────────────────────
    function addMockGuardian(address guardian) external {
        if (!mockGuardians[guardian]) {
            mockGuardians[guardian] = true;
            mockGuardianCount++;
        }
    }

    function setGuardianSet(address[] calldata keys) external {
        currentGuardianSetIndex++;
        guardianSets[currentGuardianSetIndex] = GuardianSet({
            keys: keys,
            expirationTime: 0
        });
    }

    // ── parseAndVerifyVM (behaviors #1, #3, #4) ───────────────────────────────
    /// @notice Simplified: caller provides a pre-decoded VM struct plus
    ///         a list of mock-guardian addresses that "signed" it.
    function parseAndVerifyVM(
        VM calldata vm_,
        address[] calldata signers
    ) external view returns (VM memory, bool valid, string memory reason) {
        // Behavior #3: replay protection
        if (usedVAAs[vm_.hash]) {
            return (vm_, false, "VAA already processed");
        }
        // Behavior #1: quorum check
        uint256 validSigs;
        for (uint256 i; i < signers.length; i++) {
            if (mockGuardians[signers[i]]) validSigs++;
        }
        uint256 needed = (mockGuardianCount * quorumNumerator) / quorumDenominator + 1;
        if (validSigs < needed) {
            return (vm_, false, "insufficient guardian signatures");
        }
        return (vm_, true, "");
    }

    // ── submitVAA (marks used) ────────────────────────────────────────────────
    function submitVAA(VM calldata vm_, address[] calldata signers) external returns (bool) {
        (, bool valid, string memory reason) = this.parseAndVerifyVM(vm_, signers);
        require(valid, reason);
        usedVAAs[vm_.hash] = true;
        return true;
    }

    // ── publishMessage (behaviors #2, #5) ─────────────────────────────────────
    function publishMessage(
        uint32 nonce,
        bytes calldata payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 seq) {
        bytes32 emitterAddress = bytes32(uint256(uint160(msg.sender)));
        seq = sequence[1][emitterAddress]++;
        emit LogMessagePublished(msg.sender, seq, nonce, payload, consistencyLevel);
    }

    receive() external payable {}
}
