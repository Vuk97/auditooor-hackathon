// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EcdsaLowSMissingPositive {
    address public immutable owner;
    mapping(bytes32 => bool) public usedSignatures;

    constructor(address signer_) {
        owner = signer_;
    }

    function consumeSignature(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        bytes32 signatureKey = keccak256(abi.encodePacked(r, s, v));
        require(!usedSignatures[signatureKey], "replayed");
        usedSignatures[signatureKey] = true;

        address signer = ecrecover(digest, v, r, s);
        return signer == owner;
    }
}
