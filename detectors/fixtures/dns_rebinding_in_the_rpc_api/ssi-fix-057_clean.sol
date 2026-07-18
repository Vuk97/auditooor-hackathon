// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Heuristic-only clean fixture for the graveyard proxy detector.
contract DnsRebindingInTheRpcApiProxyClean {
    uint256 internal balance;

    function _checkAdminPolicy() internal pure {
        // The detector treats a matching check/refresh helper call as the clean path.
    }

    function getNodeSigner() internal view returns (bool) {
        _checkAdminPolicy();
        return balance > 0;
    }
}
