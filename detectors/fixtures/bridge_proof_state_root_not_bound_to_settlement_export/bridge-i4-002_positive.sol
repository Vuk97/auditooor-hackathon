// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - vuln fixture for detector family
// proof-state-root-not-bound-to-settlement (pattern: bridge-proof-state-root-not-bound-to-settlement-export)
//
// Sub-gap A of VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified):
// The payout verifies a proof against a state root but the payout leaf/hash
// does NOT include a unique source-export/txid identifier. Attacker-authored
// (recipient, amount, token) components satisfy the binding without naming a
// genuine authorized export.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgeUnboundPayoutHashVuln {
    bytes32 public stateRoot;
    address public custodyToken;

    // Consume-once ledger exists BUT is keyed by leaf hash, not by a unique
    // source export identifier. An attacker can pick arbitrary (recipient,
    // amount) values that hash to a fresh leaf they haven't used yet.
    mapping(bytes32 => bool) private _usedLeaves;

    constructor(bytes32 root, address token) {
        stateRoot = root;
        custodyToken = token;
    }

    function _verifyStateRoot(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            h = keccak256(abi.encodePacked(h, proof[i]));
        }
        return h == stateRoot;
    }

    // VULNERABLE: payout leaf is keccak256(recipient, amount) only.
    // No unique source identifier is included in the binding, so
    // any (recipient, amount) pair that hashes to a leaf the state root
    // covers is accepted. The attacker can pick any such pair.
    function settle(
        address recipient,
        uint256 amount,
        bytes32[] calldata proof
    ) external returns (bool) {
        // Leaf binding omits the unique source identifier - only recipient+amount.
        bytes32 leaf = keccak256(abi.encodePacked(recipient, amount));

        require(!_usedLeaves[leaf], "leaf already used");
        require(_verifyStateRoot(proof, leaf), "bad proof");

        _usedLeaves[leaf] = true;

        // Custody released. Because the leaf is not bound to a unique
        // source export, different (recipient, amount) pairs that hash to
        // valid leaves in the state root each authorize independent payouts
        // with no connection to a real authorized source export.
        IERC20(custodyToken).transfer(recipient, amount);
        return true;
    }
}
