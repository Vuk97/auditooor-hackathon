// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EcdsaLowSMissingClean {
    address public immutable owner;
    mapping(bytes32 => bool) public usedSignatures;

    uint256 internal constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    constructor(address signer_) {
        owner = signer_;
    }

    function consumeSignature(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        require(uint256(s) <= HALF_N, "malleable sig");

        bytes32 signatureKey = keccak256(abi.encodePacked(r, s, v));
        require(!usedSignatures[signatureKey], "replayed");
        usedSignatures[signatureKey] = true;

        address signer = ecrecover(digest, v, r, s);
        return signer == owner;
    }
}
