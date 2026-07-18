// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// MUTATION-NON-VACUITY base: FLAGGED (missing-nonce). The mutation adds
// `nonces[signer]++` which must flip missing-nonce FLAGGED -> clean.
// This proves the oracle keys on the ABSENCE of a nonce write, not on any
// other property of the function.
contract SigReplayMutationBase {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function verifyAndExecute(
        address target,
        uint256 value,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad sig");
        // No nonce write here - FLAGGED.
        (bool ok, ) = target.call{value: value}("");
        require(ok, "call failed");
    }
}
