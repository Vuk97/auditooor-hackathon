// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Heuristic-only fixture for an RPC-layer finding. This contract does not model
// DNS rebinding; it only exercises the current Solidity proxy detector.
contract DnsRebindingInTheRpcApiProxyPositive {
    uint256 internal balance;

    function _checkAdminPolicy() internal pure {
        // Clean variant calls this helper; positive variant intentionally skips it.
    }

    function getNodeSigner() internal view returns (bool) {
        return balance > 0;
    }
}
