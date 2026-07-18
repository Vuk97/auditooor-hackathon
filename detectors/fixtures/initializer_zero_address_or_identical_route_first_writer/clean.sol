// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InitializerRouteFirstWriterClean {
    error NotFactory();
    error SameChain();
    error ZeroGateway();

    address public immutable factory;
    uint32 public sourceChainId;
    uint32 public destinationChainId;
    address public remoteGateway;
    bool public routeInitialized;

    mapping(uint32 => mapping(uint32 => address)) public gatewayFor;

    event RouteInitialized(uint32 sourceChainId, uint32 destinationChainId, address remoteGateway);

    constructor() {
        factory = msg.sender;
    }

    function initializeBridgeRoute(
        uint32 _sourceChainId,
        uint32 _destinationChainId,
        address _remoteGateway
    ) external {
        if (msg.sender != factory) revert NotFactory();
        if (_sourceChainId == _destinationChainId) revert SameChain();
        if (_remoteGateway == address(0)) revert ZeroGateway();
        require(!routeInitialized, "already initialized");

        sourceChainId = _sourceChainId;
        destinationChainId = _destinationChainId;
        remoteGateway = _remoteGateway;
        gatewayFor[_sourceChainId][_destinationChainId] = _remoteGateway;
        routeInitialized = true;

        emit RouteInitialized(_sourceChainId, _destinationChainId, _remoteGateway);
    }
}
