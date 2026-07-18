// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FLAGGED (missing-chainid): verifyAndExecute calls ecrecover, burns the nonce
// (so missing-nonce is NOT triggered), but the digest fed to ecrecover is built
// from abi.encode WITHOUT including block.chainid. The same signed digest is
// valid on every chain this contract is deployed to - cross-chain replay.
contract SigReplayMissingChainId {
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
        // Digest does NOT include block.chainid - cross-chain replayable.
        bytes32 hash = keccak256(abi.encode(target, value, nonce));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "bad sig");
        nonces[signer]++;   // nonce consumed - missing-nonce NOT triggered
        (bool ok, ) = target.call{value: value}("");
        require(ok, "call failed");
    }
}
