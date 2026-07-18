// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DEDUP BOUNDARY (vs E3): the ONLY unbound field is a DOMAIN identity
// (originNetwork), and there is NO message-type discriminator at all. That is E3's
// cross-chain-domain-not-bound cell, NOT E10's proof-leaf-type cell. E10 excludes
// domain/chain/nonce/sender identity fields and MUST stay silent here.
contract DomainOnlyLeaf {
    function getLeafValue(
        uint32 originNetwork,
        uint256 amount,
        bytes32 metadataHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(amount, metadataHash));
    }
}
