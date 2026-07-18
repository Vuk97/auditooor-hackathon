// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RouteOwnerBootstrapVulnerable {
    address public owner;
    address public admin;
    address public remoteGateway;
    mapping(uint256 => mapping(uint256 => address)) public routes;
    mapping(uint256 => address) public routeOwner;

    function setupRoute(
        uint256 sourceChainId,
        uint256 destinationChainId,
        address configuredOwner,
        address configuredAdmin,
        address configuredGateway
    ) external {
        owner = configuredOwner;
        admin = configuredAdmin;
        remoteGateway = configuredGateway;
        routes[sourceChainId][destinationChainId] = configuredGateway;
        routeOwner[sourceChainId] = configuredOwner;
    }
}

contract GatewayInitializerVulnerable {
    address public owner;
    address public remoteBridge;
    mapping(uint256 => address) public gatewayFor;

    function initializeGateway(
        uint256 chainId,
        address initialOwner,
        address gateway
    ) external {
        owner = initialOwner;
        remoteBridge = gateway;
        gatewayFor[chainId] = gateway;
    }
}
