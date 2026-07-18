// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HACKERMAN_V3 Lane I4 - vuln fixture for detector family
// bridge-payout-lacks-export-txid-consumption.
//
// Anchor: VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified).
// The payout path verifies payload components against a state root but
// releases custody WITHOUT consuming a unique source export/txid and
// WITHOUT consulting any processed-txid ledger at settlement.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VerusLikeBridgeDispatcherVuln {
    bytes32 public stateRoot;
    address public custodyToken;

    constructor(bytes32 root, address token) {
        stateRoot = root;
        custodyToken = token;
    }

    // Proof path: checks that the supplied components are well-formed /
    // included under the committed state root. This proves component
    // validity only - NOT that the components name a unique unspent
    // authorized source export.
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

    // VULNERABLE payout path. The disbursement is computed from
    // attacker-authored payload bytes, validated against the state-root
    // proof, then custody is released. There is NO read or write of a
    // processed-txid / consumed-export ledger anywhere on this path, so
    // the same inputs can be replayed and synthetic components drain
    // custody.
    function payout(
        bytes calldata payload,
        bytes32[] calldata proof
    ) external returns (bool) {
        (address recipient, uint256 amount, bytes32 sourceTxid) =
            abi.decode(payload, (address, uint256, bytes32));

        bytes32 leaf = keccak256(abi.encodePacked(recipient, amount, sourceTxid));
        require(_verifyAgainstStateRoot(proof, leaf), "bad proof");

        // Custody released with no consume-once gate.
        IERC20(custodyToken).transfer(recipient, amount);
        return true;
    }
}
