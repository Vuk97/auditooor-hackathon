// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP GUARD: a generic EIP-712 permit struct hash. No leaf/proof context, no
// message-type discriminator. E10 must not fire on ordinary commitment hashing.
contract Permit {
    function hashPermit(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, spender, value, nonce));
    }
}
