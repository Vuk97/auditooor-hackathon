// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: same shape as the vuln, but every consume path deletes /
// zeroizes the map entry IMMEDIATELY after the verify.

contract CommitmentNonceMapNoDeleteAfterConsumeClean {
    mapping(bytes32 => bool)    public used;
    mapping(bytes32 => bytes32) public commitment;
    mapping(bytes32 => uint256) public nonce;
    address public owner;

    constructor() { owner = msg.sender; }

    // CLEAN — explicit delete after consume.
    function verify(
        bytes32 c,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (address signer) {
        require(used[c] == false, "consumed");
        bytes32 digest = commitment[c];
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        used[c] = true;
        delete commitment[c];      // defense-in-depth zeroize
        delete nonce[c];
    }

    function consume(bytes32 c, uint8 v, bytes32 r, bytes32 s) external {
        require(used[c] == false, "consumed");
        bytes32 digest = keccak256(abi.encode(c, nonce[c]));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signer");
        used[c] = true;
        delete commitment[c];
        delete nonce[c];
    }
}
