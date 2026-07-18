// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InitializerRouteFirstWriterPositive {
    uint32 public sourceChainId;
    uint32 public destinationChainId;
    address public remoteGateway;
    bool public routeInitialized;

    mapping(uint32 => mapping(uint32 => address)) public gatewayFor;

    event RouteInitialized(uint32 sourceChainId, uint32 destinationChainId, address remoteGateway);

    function initializeBridgeRoute(
        uint32 _sourceChainId,
        uint32 _destinationChainId,
        address _remoteGateway
    ) external {
        require(!routeInitialized, "already initialized");

        sourceChainId = _sourceChainId;
        destinationChainId = _destinationChainId;
        remoteGateway = _remoteGateway;
        gatewayFor[_sourceChainId][_destinationChainId] = _remoteGateway;
        routeInitialized = true;

        emit RouteInitialized(_sourceChainId, _destinationChainId, _remoteGateway);
    }
}
