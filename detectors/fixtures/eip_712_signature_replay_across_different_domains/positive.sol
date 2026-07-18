// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Eip712SignatureReplayAcrossDifferentDomainsPositive {
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

    mapping(address => uint256) public nonces;

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                nonces[owner],
                deadline
            )
        );

        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");

        nonces[owner] += 1;
    }
}
