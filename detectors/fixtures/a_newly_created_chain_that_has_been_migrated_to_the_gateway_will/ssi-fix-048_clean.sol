// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NewlyCreatedChainMigratedGatewayClean {
    uint256 internal forwardedBridgeBurn;
    bytes32[] internal historicalRoots;
    bool internal gatewayReturnQueued;

    function prime(uint256 burnValue, bytes32 root) external {
        forwardedBridgeBurn = burnValue;
        historicalRoots.push(root);
    }

    function priorityTree() external returns (bool) {
        return _updateTreeSnapshot();
    }

    function _updateTreeSnapshot() internal returns (bool) {
        gatewayReturnQueued = forwardedBridgeBurn > 0 && historicalRoots.length > 0;
        return gatewayReturnQueued;
    }
}
