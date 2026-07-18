// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PublicDomainRouteSetup {
    uint32 public sourceChainId;
    uint32 public destinationChainId;
    address public remoteGateway;

    mapping(uint32 => mapping(uint32 => address)) public gatewayFor;

    event RouteConfigured(uint32 sourceChainId, uint32 destinationChainId, address remoteGateway);

    function configureRoute(
        uint32 _sourceChainId,
        uint32 _destinationChainId,
        address _remoteGateway
    ) external {
        sourceChainId = _sourceChainId;
        destinationChainId = _destinationChainId;
        remoteGateway = _remoteGateway;
        gatewayFor[_sourceChainId][_destinationChainId] = _remoteGateway;

        emit RouteConfigured(_sourceChainId, _destinationChainId, _remoteGateway);
    }
}

contract PublicDomainRouteFirstWriter {
    mapping(uint32 => mapping(uint32 => address)) public routes;

    function migrateChainToGateway(
        uint32 sourceChainId,
        uint32 destinationChainId,
        address gateway
    ) external {
        require(routes[sourceChainId][destinationChainId] == address(0), "route exists");
        routes[sourceChainId][destinationChainId] = gateway;
    }
}
