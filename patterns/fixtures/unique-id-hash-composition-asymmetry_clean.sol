// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// Both paired create-style entry points route through a SHARED `_buildId(...)`
/// helper that takes a uniform (caller, businessFields) tuple. Structural
/// symmetry is enforced by code locality — exactly the negative case Codex
/// described as the symmetry-restoring shape.
contract DisputeManagerClean {
    struct Dispute {
        address fisherman;
        uint256 deposit;
    }

    mapping(bytes32 => Dispute) public disputes;

    function _buildId(address caller, bytes32 businessKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(caller, businessKey));
    }

    /// CLEAN: routes through shared `_buildId` helper.
    function createIndexingDispute(bytes32 allocationId, uint256 deposit) external {
        bytes32 id = _buildId(msg.sender, allocationId);
        require(disputes[id].fisherman == address(0), "duplicate");
        disputes[id] = Dispute({fisherman: msg.sender, deposit: deposit});
    }

    /// CLEAN: routes through the same `_buildId` helper, structurally symmetric.
    function createQueryDispute(
        bytes32 queryHash,
        bytes calldata attestation,
        uint256 deposit
    ) external {
        bytes32 businessKey = keccak256(abi.encode(queryHash, attestation));
        bytes32 id = _buildId(msg.sender, businessKey);
        require(disputes[id].fisherman == address(0), "duplicate");
        disputes[id] = Dispute({fisherman: msg.sender, deposit: deposit});
    }
}
