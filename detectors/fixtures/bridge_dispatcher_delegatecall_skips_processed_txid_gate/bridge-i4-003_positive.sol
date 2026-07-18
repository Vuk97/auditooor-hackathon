// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - vuln fixture for detector family
// dispatcher-delegatecall-skips-processed-txid-gate
// (pattern: bridge-dispatcher-delegatecall-skips-processed-txid-gate)
//
// Sub-gap B of VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified):
// The dispatcher routes payout via delegatecall without consulting a
// processed-txid ledger at the dispatcher entry point. Replay is possible.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BridgePayoutTarget {
    // Target contract performs the actual transfer.
    // Does NOT read or write any processed-txid ledger.
    function executePayout(address token, address recipient, uint256 amount) external {
        IERC20(token).transfer(recipient, amount);
    }
}

contract BridgeDispatcherVuln {
    address public payoutTarget;
    address public custodyToken;
    bytes32 public stateRoot;
    uint256 public dispatchCount;

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

    // VULNERABLE: dispatcher verifies the proof, then delegatecalls a
    // target contract and releases custody itself without consulting a
    // processed-txid ledger. Replay of the same proof inputs succeeds
    // each time.
    function dispatch(
        bytes calldata payload,
        bytes32[] calldata proof
    ) external {
        dispatchCount += 1;

        (address recipient, uint256 amount, bytes32 sourceTxid) =
            abi.decode(payload, (address, uint256, bytes32));

        bytes32 leaf = keccak256(abi.encodePacked(recipient, amount, sourceTxid));
        require(_verifyStateRoot(proof, leaf), "bad proof");

        // delegatecall to the payout target - no processed-txid gate at
        // the dispatcher level, and no consume-once write happens before
        // custody is released.
        bytes memory data = abi.encodeWithSelector(
            BridgePayoutTarget.executePayout.selector,
            custodyToken,
            recipient,
            amount
        );
        (bool ok,) = payoutTarget.delegatecall(data);
        require(ok, "payout failed");

        IERC20(custodyToken).transfer(recipient, amount);
    }
}
