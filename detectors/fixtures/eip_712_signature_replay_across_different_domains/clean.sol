// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Eip712SignatureReplayAcrossDifferentDomainsClean {
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 private immutable DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("ReplaySafePermit")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
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
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonces[owner],
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");

        nonces[owner] += 1;
    }
}
