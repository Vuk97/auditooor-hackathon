// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// global-pool-fallback-auth detector. DO NOT DEPLOY.
///
/// A hub-and-spoke cross-chain receiver authenticates every inbound
/// payload by reading `_adapterDetails[chainId][poolId][msg.sender]`.
/// The payload's `poolId` is extracted via `messagePoolId(payload)` and
/// falls back to `PoolId(0)` for admin-class messages (upgrade / recover
/// / reconfigure). All admin traffic therefore shares the single
/// GLOBAL_POOL adapter slot regardless of per-pool configuration.

type PoolId is uint64;

interface IMessageProperties {
    function messagePoolId(bytes calldata payload) external pure returns (PoolId);
}

interface IGateway {
    function handle(uint16 chainId, bytes calldata payload) external;
}

contract GlobalPoolFallbackAuthVuln {
    struct Adapter {
        uint8 id;
        uint8 quorum;
        uint8 threshold;
    }

    IMessageProperties public messageProperties;
    IGateway public gateway;

    mapping(uint16 => mapping(PoolId => address[])) public adapters;
    mapping(uint16 => mapping(PoolId => mapping(address => Adapter))) internal _adapterDetails;

    constructor(IMessageProperties _props, IGateway _gw) {
        messageProperties = _props;
        gateway = _gw;
    }

    /// @notice Receive-side entry point. Authenticates via the adapter
    /// set keyed on (chainId, poolId) where poolId is decoded from the
    /// payload — and silently falls back to PoolId(0) for admin-class
    /// messages that carry no per-pool field. See wiki for details.
    function handle(uint16 chainId, bytes calldata payload) external {
        PoolId poolId = messageProperties.messagePoolId(payload);
        Adapter memory a = _adapterDetails[chainId][poolId][msg.sender];
        require(a.id != 0, "not an adapter");
        gateway.handle(chainId, payload);
    }
}
