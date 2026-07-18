// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire.
/// Calls ecrecover without constraining v to {27, 28}. A malformed v yields
/// address(0), which collides with the default (zero) owner slot and lets an
/// attacker forge authorization for any uninitialized id.
contract EcrecoverVNotEnforcedVuln {
    mapping(uint256 => address) public orderOwner;

    function authorize(
        uint256 id,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external view returns (bool) {
        // VULN: no `require(v == 27 || v == 28)` guard, and no ECDSA wrapper.
        // For v outside {27, 28} ecrecover returns address(0), which equals
        // the unset orderOwner[id] slot for any id that was never registered.
        address recovered = ecrecover(digest, v, r, s);
        return recovered == orderOwner[id];
    }
}
