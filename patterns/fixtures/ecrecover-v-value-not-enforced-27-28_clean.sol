// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// Enforces v ∈ {27, 28} before calling ecrecover, and rejects address(0)
/// downstream as defense-in-depth.
contract EcrecoverVNotEnforcedClean {
    mapping(uint256 => address) public orderOwner;

    function authorize(
        uint256 id,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (bool) {
        // CLEAN: explicit canonical-v range guard.
        require(v == 27 || v == 28, "bad v");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "zero signer");
        return recovered == orderOwner[id];
    }
}
