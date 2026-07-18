// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// bridge-replay-missing-nonce-check detector. DO NOT DEPLOY.
///
/// Inbound receive-side entrypoint mints tokens to a recipient based on a
/// signed attestation, but never records the message id or advances a
/// per-source nonce. The same calldata can be resubmitted indefinitely to
/// mint unlimited tokens on the destination chain.
contract BridgeReplayVuln {
    address public attester;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

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
        // Signature is verified, but the digest includes the nonce as data
        // only — the nonce is never *consumed* in storage. Replay trivially.
        bytes32 digest = keccak256(abi.encodePacked(recipient, amount, nonce));
        address signer = ecrecover(digest, v, r, s);
        require(signer == attester, "bad attester");

        balances[recipient] += amount;
        totalSupply += amount;
    }
}
