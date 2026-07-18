// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Eip712DomainSeparatorUsedWithoutChainidThusIntroducingCrossChClean {
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal DOMAIN_SEPARATOR;
    bytes32 internal constant NAME_HASH = keccak256("BridgeVerifier");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    function verify(bytes32 structHash, uint8 v, bytes32 r, bytes32 s, address signer)
        external
        view
        returns (bool)
    {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        return ecrecover(digest, v, r, s) == signer;
    }
}
