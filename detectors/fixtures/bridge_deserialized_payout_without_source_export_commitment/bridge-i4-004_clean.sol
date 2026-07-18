// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - clean fixture for detector family
// deserialized-payout-without-source-commitment
// (pattern: bridge-deserialized-payout-without-source-export-commitment)
//
// The decoded payload includes a unique sourceTxid / transferId that is
// bound into the verified leaf and consumed into a processed-txid ledger
// before the transfer fires.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgeDeserializedPayoutClean {
    bytes32 public stateRoot;
    mapping(bytes32 => bool) private _processedTxids;

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

    // SAFE: payload includes a sourceTxid field; the leaf binds it into the
    // verified commitment; it is consumed before the transfer.
    function processBridgeMessage(
        bytes calldata payload,
        bytes32[] calldata proof
    ) external {
        bytes32 leaf = keccak256(payload);
        require(_verifyStateRoot(proof, leaf), "bad proof");

        // Decode includes transferId (unique source-export identifier).
        (address recipient, uint256 amount, address token, bytes32 transferId) =
            abi.decode(payload, (address, uint256, address, bytes32));

        require(!_processedTxids[transferId], "transfer already processed");
        _processedTxids[transferId] = true;

        IERC20(token).transfer(recipient, amount);
    }
}
