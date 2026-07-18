// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: setAuthorizationWithSig without idempotency check — nonce burned even if no state change.
// Source: morpho-org/morpho-blue@94c9f57 (cantina fix)
// Vulnerability: An attacker who intercepts a signed authorization can replay it with the
// same isAuthorized value that is already stored, burning the signer's nonce and invalidating
// all future signatures with higher nonces that the signer may have pre-distributed.

struct Authorization {
    address authorizer;
    address authorized;
    bool isAuthorized;
    uint256 nonce;
    uint256 deadline;
}

struct Signature {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

contract Fix {
    string internal constant SIGNATURE_EXPIRED = "signature expired";
    string internal constant INVALID_NONCE = "invalid nonce";
    string internal constant INVALID_SIGNATURE = "invalid signature";

    bytes32 public constant AUTHORIZATION_TYPEHASH = keccak256(
        "Authorization(address authorizer,address authorized,bool isAuthorized,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    mapping(address => mapping(address => bool)) public isAuthorized;
    mapping(address => uint256) public nonce;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(keccak256("EIP712Domain(string name)"), keccak256("Morpho")));
    }

    // VULNERABLE: no check that isAuthorized != current value; nonce is consumed even when no change happens
    function setAuthorizationWithSig(Authorization memory authorization, Signature calldata signature) external {
        require(block.timestamp <= authorization.deadline, SIGNATURE_EXPIRED);
        require(authorization.nonce == nonce[authorization.authorizer]++, INVALID_NONCE);

        bytes32 hashStruct = keccak256(abi.encode(AUTHORIZATION_TYPEHASH, authorization));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signatory = ecrecover(digest, signature.v, signature.r, signature.s);

        require(signatory != address(0) && authorization.authorizer == signatory, INVALID_SIGNATURE);

        isAuthorized[authorization.authorizer][authorization.authorized] = authorization.isAuthorized;
    }
}
