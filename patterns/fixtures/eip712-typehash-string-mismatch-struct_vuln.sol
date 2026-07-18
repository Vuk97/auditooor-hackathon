// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: PERMIT_TYPEHASH declares the fields in order
//   (owner, spender, value, nonce, deadline)
// but hashStruct(...) packs them into abi.encode as
//   (owner, spender, value, deadline, nonce)
// — `deadline` and `nonce` are swapped. Every wallet-side signature
// hashes to the canonical field order the string literal declares;
// the contract hashes the swapped order; ecrecover returns garbage
// and every permit() call reverts "invalid signature".
//
// A v1 pattern cannot prove this field-for-field mismatch — it flags
// the structural shape (typehash constant + abi.encode over TYPEHASH)
// and leaves the semantic check to the auditor.
contract PermitTypehashMismatchVuln {
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PermitVuln")),
                block.chainid,
                address(this)
            )
        );
    }

    function hashStruct(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) public pure returns (bytes32) {
        // MISMATCH: deadline and nonce are swapped relative to PERMIT_TYPEHASH.
        return keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                deadline,
                nonce
            )
        );
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 structHash = hashStruct(owner, spender, value, nonces[owner], deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "invalid signature");
        nonces[owner]++;
    }
}
