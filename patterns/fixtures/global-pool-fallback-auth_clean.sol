// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the
/// vuln fixture, but admin-class messages (ScheduleUpgrade, RecoverTokens,
/// SetPoolAdapters) are authenticated through a dedicated
/// `adminAdapters` set rather than falling back into the shared
/// GLOBAL_POOL slot of the per-pool `_adapterDetails` map.

type PoolId is uint64;

interface IMessageProperties {
    function messagePoolId(bytes calldata payload) external pure returns (PoolId);
    function isAdminMessage(bytes calldata payload) external pure returns (bool);
}

interface IGateway {
    function handle(uint16 chainId, bytes calldata payload) external;
}

contract GlobalPoolFallbackAuthClean {
    struct Adapter {
        uint8 id;
        uint8 quorum;
        uint8 threshold;
    }

    IMessageProperties public messageProperties;
    IGateway public gateway;

    mapping(uint16 => mapping(PoolId => address[])) public adapters;
    mapping(uint16 => mapping(PoolId => mapping(address => Adapter))) internal _adapterDetails;

    /// Separate, independently-configured adapter set for admin-class
    /// messages. Keyed only by chainId — not collapsed into PoolId(0).
    mapping(uint16 => mapping(address => Adapter)) internal _adminAdapters;

    constructor(IMessageProperties _props, IGateway _gw) {
        messageProperties = _props;
        gateway = _gw;
    }

    function handle(uint16 chainId, bytes calldata payload) external {
        if (messageProperties.isAdminMessage(payload)) {
            // ScheduleUpgrade / RecoverTokens / SetPoolAdapters: route
            // through the dedicated admin adapter set.
            Adapter memory a = _adminAdapters[chainId][msg.sender];
            require(a.id != 0 && a.threshold >= 3, "admin quorum");
            gateway.handle(chainId, payload);
            return;
        }

        PoolId poolId = messageProperties.messagePoolId(payload);
        Adapter memory pa = _adapterDetails[chainId][poolId][msg.sender];
        require(pa.id != 0, "not an adapter");
        gateway.handle(chainId, payload);
    }
}
