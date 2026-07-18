// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title BridgeRouter - cross-chain message dispatch (bridge-router peripheral)
contract BridgeRouter {
    address public relayer;

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function relay(bytes calldata payload, uint256 dstChainId) external {
        // dispatch to cross-chain bridge
        (bool ok,) = relayer.call(abi.encode(payload, dstChainId));
        require(ok, "relay failed");
    }

    function processMessage(bytes calldata data) external {
        require(msg.sender == relayer, "only relayer");
        // handle inbound message
    }
}
