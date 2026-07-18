// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire on createIndexingDispute.
///
/// Mirrors OZ-2025-L-02 ("Double Jeopardy") on The Graph DisputeManager:
/// createIndexingDispute hashes (allocationId) WITHOUT msg.sender, while
/// createQueryDispute correctly mixes in (queryHash, attestation, msg.sender).
/// Asymmetry → two fishermen submitting the same allocationId collide on
/// disputeId; the second loses its bond.
contract DisputeManagerVulnerable {
    struct Dispute {
        address fisherman;
        uint256 deposit;
    }

    mapping(bytes32 => Dispute) public disputes;

    /// VULN: id pre-image OMITS msg.sender → caller collisions are possible.
    /// This is the asymmetric path the detector must flag.
    function createIndexingDispute(bytes32 allocationId, uint256 deposit) external {
        bytes32 id = keccak256(abi.encode(allocationId));
        require(disputes[id].fisherman == address(0), "duplicate");
        disputes[id] = Dispute({fisherman: msg.sender, deposit: deposit});
    }

    /// CLEAN sibling: id pre-image MIXES IN msg.sender → caller-scoped, safe.
    /// Detector must NOT flag this one. Its presence in the same contract is
    /// the asymmetry-anchor that makes the createIndexingDispute omission
    /// load-bearing.
    function createQueryDispute(
        bytes32 queryHash,
        bytes calldata attestation,
        uint256 deposit
    ) external {
        bytes32 id = keccak256(abi.encode(queryHash, attestation, msg.sender));
        require(disputes[id].fisherman == address(0), "duplicate");
        disputes[id] = Dispute({fisherman: msg.sender, deposit: deposit});
    }
}
