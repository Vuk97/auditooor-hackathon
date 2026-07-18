// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract MinimalInitializable {
    bool private initialized;

    modifier initializer() {
        require(!initialized, "already initialized");
        initialized = true;
        _;
    }
}

contract OwnerBoundRouteSetupClean {
    address public owner;
    address public admin;
    address public remoteGateway;
    mapping(uint256 => mapping(uint256 => address)) public routes;
    mapping(uint256 => address) public routeOwner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    function setupRoute(
        uint256 sourceChainId,
        uint256 destinationChainId,
        address configuredOwner,
        address configuredAdmin,
        address configuredGateway
    ) external onlyOwner {
        owner = configuredOwner;
        admin = configuredAdmin;
        remoteGateway = configuredGateway;
        routes[sourceChainId][destinationChainId] = configuredGateway;
        routeOwner[sourceChainId] = configuredOwner;
    }
}

contract InitializerGuardedGatewayClean is MinimalInitializable {
    address public owner;
    address public remoteBridge;
    mapping(uint256 => address) public gatewayFor;

    function initializeGateway(
        uint256 chainId,
        address initialOwner,
        address gateway
    ) external initializer {
        owner = initialOwner;
        remoteBridge = gateway;
        gatewayFor[chainId] = gateway;
    }
}
