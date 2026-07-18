// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// CLEAN (nonce consumed + chainid included): the function writes a nonce
// mapping (missing-nonce NOT triggered) AND the digest includes block.chainid
// (missing-chainid NOT triggered). Neither sub-rule fires.
contract SigReplayNonceAndChainIdClean {
    address public owner;
    mapping(address => uint256) public nonces;

    constructor(address _owner) {
        owner = _owner;
    }

    function verifyAndExecute(
        address target,
        uint256 value,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 hash = keccak256(abi.encode(block.chainid, target, value, nonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad sig");
        nonces[signer]++;
        (bool ok, ) = target.call{value: value}("");
        require(ok, "call failed");
    }
}
