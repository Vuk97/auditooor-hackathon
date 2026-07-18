// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: DOMAIN_SEPARATOR is built with a hardcoded chain id of `1`.
// Once this bytecode is redeployed on an L2 at the same CREATE2
// address, a signature valid on mainnet replays on the L2 because
// the separator still binds to chain id 1.
contract PermitVuln {
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = buildDomainSeparator();
    }

    function buildDomainSeparator() public view returns (bytes32) {
        // Hardcoded chainId = 1 — no block.chainid reference anywhere.
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PermitVuln")),
                keccak256(bytes("1")),
                1,
                address(this)
            )
        );
    }
}
