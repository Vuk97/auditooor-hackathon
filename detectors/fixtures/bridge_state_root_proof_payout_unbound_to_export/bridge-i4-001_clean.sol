// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - clean fixture for detector family
// bridge-payout-lacks-export-txid-consumption.
//
// Same bridge dispatcher shape as the vuln fixture, but the payout path
// consults and updates a processed-txid ledger (_processedTxids) BEFORE
// releasing custody, so each authorized source export drains custody at
// most once and replay is impossible.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VerusLikeBridgeDispatcherClean {
    bytes32 public stateRoot;
    address public custodyToken;

    // Consume-once ledger: a source export/txid maps to true once drained.
    mapping(bytes32 => bool) private _processedTxids;

    constructor(bytes32 root, address token) {
        stateRoot = root;
        custodyToken = token;
    }

    function _verifyAgainstStateRoot(
        bytes32[] calldata proof,
        bytes32 leaf
    ) internal view returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            h = keccak256(abi.encodePacked(h, proof[i]));
        }
        return h == stateRoot;
    }

    // SAFE payout path. The unique source export/txid is bound into the
    // verified leaf AND consumed into _processedTxids strictly before the
    // value transfer. A replayed or synthetic-but-already-drained export
    // is rejected by the consume-once gate.
    function payout(
        bytes calldata payload,
        bytes32[] calldata proof
    ) external returns (bool) {
        (address recipient, uint256 amount, bytes32 sourceTxid) =
            abi.decode(payload, (address, uint256, bytes32));

        require(!_processedTxids[sourceTxid], "export already consumed");

        bytes32 leaf = keccak256(abi.encodePacked(recipient, amount, sourceTxid));
        require(_verifyAgainstStateRoot(proof, leaf), "bad proof");

        // Consume the unique source export before releasing custody.
        _processedTxids[sourceTxid] = true;

        IERC20(custodyToken).transfer(recipient, amount);
        return true;
    }
}
