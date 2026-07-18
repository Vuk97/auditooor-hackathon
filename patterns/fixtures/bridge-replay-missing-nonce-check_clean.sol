// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but the inbound message id is consumed via a `processed[]`
/// mapping before any value-bearing state change. Replay reverts.
contract BridgeReplayClean {
    address public attester;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    mapping(bytes32 => bool) public processed;

    constructor(address _attester) {
        attester = _attester;
    }

    function receiveMessage(
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(recipient, amount, nonce));
        require(!processed[digest], "replay");
        processed[digest] = true;

        address signer = ecrecover(digest, v, r, s);
        require(signer == attester, "bad attester");

        balances[recipient] += amount;
        totalSupply += amount;
    }
}
