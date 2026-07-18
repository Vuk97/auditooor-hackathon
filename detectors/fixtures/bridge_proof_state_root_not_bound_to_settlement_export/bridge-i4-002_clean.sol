// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - clean fixture for detector family
// proof-state-root-not-bound-to-settlement (pattern: bridge-proof-state-root-not-bound-to-settlement-export)
//
// The payout leaf now includes the unique source-export/txid identifier,
// so an attacker cannot freely assemble (recipient, amount) components
// that satisfy the binding without pointing at a genuine authorized export.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgeUnboundPayoutHashClean {
    bytes32 public stateRoot;
    address public custodyToken;
    mapping(bytes32 => bool) private _processedTxids;

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

    // SAFE: payout leaf binds (recipient, amount, sourceTxid).
    // The unique source export/txid identifier is required to be part of
    // the verified commitment; attacker-authored components must name a
    // real authorized export present in the state root.
    function settle(
        address recipient,
        uint256 amount,
        bytes32 sourceTxid,
        bytes32[] calldata proof
    ) external returns (bool) {
        require(!_processedTxids[sourceTxid], "export already consumed");

        // Leaf binds the unique source export identifier.
        bytes32 leaf = keccak256(abi.encodePacked(recipient, amount, sourceTxid));
        require(_verifyStateRoot(proof, leaf), "bad proof");

        // Consume the unique source export before releasing custody.
        _processedTxids[sourceTxid] = true;
        IERC20(custodyToken).transfer(recipient, amount);
        return true;
    }
}
