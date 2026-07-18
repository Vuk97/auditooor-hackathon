// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - clean fixture for detector family
// dispatcher-delegatecall-skips-processed-txid-gate
// (pattern: bridge-dispatcher-delegatecall-skips-processed-txid-gate)
//
// The dispatcher now consults and writes a processed-txid ledger at the
// entry point BEFORE the delegatecall, so replay is blocked.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgePayoutTargetClean {
    function executePayout(address token, address recipient, uint256 amount) external {
        IERC20(token).transfer(recipient, amount);
    }
}

contract BridgeDispatcherClean {
    address public payoutTarget;
    address public custodyToken;
    bytes32 public stateRoot;
    uint256 public dispatchCount;

    // Consume-once ledger lives in the dispatcher's storage, checked
    // before the delegatecall, so it is authoritative regardless of what
    // the target does.
    mapping(bytes32 => bool) private _processedTxids;

    constructor(address target, address token, bytes32 root) {
        payoutTarget = target;
        custodyToken = token;
        stateRoot = root;
    }

    function _verifyStateRoot(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            h = keccak256(abi.encodePacked(h, proof[i]));
        }
        return h == stateRoot;
    }

    // SAFE: the dispatcher consults _processedTxids before the proof check
    // and writes it before the delegatecall. Replay is blocked at entry
    // even though custody is still released by the dispatcher itself.
    function dispatch(
        bytes calldata payload,
        bytes32[] calldata proof
    ) external {
        dispatchCount += 1;

        (address recipient, uint256 amount, bytes32 sourceTxid) =
            abi.decode(payload, (address, uint256, bytes32));

        require(!_processedTxids[sourceTxid], "export already consumed");

        bytes32 leaf = keccak256(abi.encodePacked(recipient, amount, sourceTxid));
        require(_verifyStateRoot(proof, leaf), "bad proof");

        // Mark consumed before the delegatecall.
        _processedTxids[sourceTxid] = true;

        bytes memory data = abi.encodeWithSelector(
            BridgePayoutTargetClean.executePayout.selector,
            custodyToken,
            recipient,
            amount
        );
        (bool ok,) = payoutTarget.delegatecall(data);
        require(ok, "payout failed");

        IERC20(custodyToken).transfer(recipient, amount);
    }
}
