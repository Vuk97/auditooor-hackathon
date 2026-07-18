// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - vuln fixture for detector family
// deserialized-payout-without-source-commitment
// (pattern: bridge-deserialized-payout-without-source-export-commitment)
//
// Sub-gap: payout derives (recipient, amount, token) from abi.decode
// without binding a unique source-export/txid into the verified commitment.
// Attacker crafts arbitrary bytes that decode to attacker-chosen payout
// params and satisfy the proof check.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgeDeserializedPayoutVuln {
    bytes32 public stateRoot;

    constructor(bytes32 root) {
        stateRoot = root;
    }

    function _verifyStateRoot(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            h = keccak256(abi.encodePacked(h, proof[i]));
        }
        return h == stateRoot;
    }

    // VULNERABLE: payload bytes are abi.decoded into (recipient, amount, token).
    // The leaf is keccak256(payload) - the proof binds the raw bytes but NOT
    // a unique source-export/txid. An attacker can craft any (recipient, amount,
    // token) payload whose keccak256 is a leaf in the state root and trigger
    // a payout to themselves.
    function processBridgeMessage(
        bytes calldata payload,
        bytes32[] calldata proof
    ) external {
        bytes32 leaf = keccak256(payload);
        require(_verifyStateRoot(proof, leaf), "bad proof");

        // Decode after proof - no source-export/txid in the decoded fields.
        (address recipient, uint256 amount, address token) =
            abi.decode(payload, (address, uint256, address));

        // No nonce / no transferId / no sourceTxid - pure deserialized payout.
        IERC20(token).transfer(recipient, amount);
    }
}
