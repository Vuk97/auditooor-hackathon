// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: single-use commitment/nonce map consumed in a verify flow but
// not deleted afterwards — leaves the value live in storage so any
// future regression (refactor, upgrade, reentrancy) re-enables replay.

contract CommitmentNonceMapNoDeleteAfterConsumeVuln {
    mapping(bytes32 => bool)    public used;        // gating bit
    mapping(bytes32 => bytes32) public commitment;  // commitment payload
    mapping(bytes32 => uint256) public nonce;       // per-key nonce
    address public owner;

    constructor() { owner = msg.sender; }

    // VULN — verifies a signature against ecrecover and marks `used`,
    // but never deletes `commitment[c]` or `nonce[c]`. Defense-in-depth gap.
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
        // missing: delete commitment[c]; delete nonce[c];
    }

    // VULN — `consume` reads the nonce + signature, runs verify, but
    // again leaves both maps live in storage.
    function consume(bytes32 c, uint8 v, bytes32 r, bytes32 s) external {
        require(used[c] == false, "consumed");
        bytes32 digest = keccak256(abi.encode(c, nonce[c]));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signer");
        used[c] = true;
        // missing zeroizer.
    }
}
