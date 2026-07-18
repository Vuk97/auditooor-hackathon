// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// Uses abi.encode (length-prefixed) instead of abi.encodePacked for the hash.
contract EncodePackedCollisionClean {
    mapping(bytes32 => bool) public used;

    function orderHash(string calldata name, address[] calldata recipients, uint256 nonce)
        external
        pure
        returns (bytes32)
    {
        // CLEAN: abi.encode length-prefixes dynamic args — no collision.
        return keccak256(abi.encode(name, recipients, nonce));
    }

    function authorize(
        string calldata name,
        address[] calldata recipients,
        uint256 nonce,
        bytes calldata /*sig*/
    ) external {
        bytes32 h = keccak256(abi.encode(name, recipients, nonce));
        require(!used[h], "replay");
        used[h] = true;
    }
}
