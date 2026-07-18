// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire.
/// Two dynamic arguments (string name, address[] recipients) are concatenated
/// without length prefixes; distinct inputs can collide on the order hash.
contract EncodePackedCollisionVuln {
    mapping(bytes32 => bool) public used;

    function orderHash(string calldata name, address[] calldata recipients, uint256 nonce)
        external
        pure
        returns (bytes32)
    {
        // VULN: keccak256(abi.encodePacked(dynamic, dynamic, ...)) — SWC-133
        return keccak256(abi.encodePacked(name, recipients, nonce));
    }

    function authorize(
        string calldata name,
        address[] calldata recipients,
        uint256 nonce,
        bytes calldata /*sig*/
    ) external {
        // VULN: same collision-prone hash feeds an authorization decision
        bytes32 h = keccak256(abi.encodePacked(name, recipients, nonce));
        require(!used[h], "replay");
        used[h] = true;
    }
}
