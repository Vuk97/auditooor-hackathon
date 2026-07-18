// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: hand-rolled EIP-712 domain separator omits chainId.
contract DomainMissingChainIdVulnerable {
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 private constant TYPEHASH =
        keccak256("EIP712Domain(string name,string version,address verifyingContract)");

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            TYPEHASH,
            keccak256("MyApp"),
            keccak256("1"),
            address(this)
        ));
    }

    function verify(bytes32 structHash, uint8 v, bytes32 r, bytes32 s)
        external
        view
        returns (address)
    {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        return ecrecover(digest, v, r, s);
    }
}
