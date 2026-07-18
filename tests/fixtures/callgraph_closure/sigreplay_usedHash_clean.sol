// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// CLEAN (used-hash mapping write present): the function marks the hash in a
// `usedHashes` mapping before proceeding - this is a per-message nonce
// equivalent. missing-nonce NOT triggered.
// Note: block.chainid is absent so missing-chainid WOULD trigger, but this
// fixture is used only to verify the missing-nonce suppression. A full
// compliant contract would also include chainid.
contract SigReplayUsedHashClean {
    address public owner;
    mapping(bytes32 => bool) public usedHashes;

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
        require(!usedHashes[hash], "replayed");
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad sig");
        usedHashes[hash] = true;   // per-message nonce via mapping write
        (bool ok, ) = target.call{value: value}("");
        require(ok, "call failed");
    }
}
