// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: DOMAIN_SEPARATOR is built from block.chainid so signatures
// bind to the live network. A redeployment on a second chain produces
// a different separator and the signature no longer validates.
contract PermitClean {
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = buildDomainSeparator();
    }

    function buildDomainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PermitClean")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }
}
