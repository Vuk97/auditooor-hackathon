// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FLAGGED (missing-nonce): verifyAndExecute calls ecrecover, consumes the
// recovered signer for an effect, but NEVER writes to a used-nonce / used-hash
// mapping (no `nonces[signer]++`, no `usedHashes[hash] = true`). A valid
// signature can therefore be submitted more than once.
contract SigReplayMissingNonce {
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
        // No nonce written - signature is replayable.
        (bool ok, ) = target.call{value: value}("");
        require(ok, "call failed");
    }
}
