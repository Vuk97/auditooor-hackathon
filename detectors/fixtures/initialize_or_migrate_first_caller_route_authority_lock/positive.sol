// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PublicGatewayMigrator {
    address public owner;
    address public remoteGateway;
    mapping(uint256 => mapping(uint256 => address)) public routes;

    function migrateToGateway(
        uint256 sourceChainId,
        uint256 destinationChainId,
        address newRemoteGateway,
        address newOwner
    ) external {
        require(owner == address(0), "owner already set");
        require(remoteGateway == address(0), "gateway already set");
        require(routes[sourceChainId][destinationChainId] == address(0), "route already set");

        owner = newOwner;
        remoteGateway = newRemoteGateway;
        routes[sourceChainId][destinationChainId] = newRemoteGateway;
    }
}

contract PublicChainGatewayRegistry {
    mapping(uint256 => address) public gatewayFor;
    mapping(uint256 => bool) public registeredChains;

    function registerChain(uint256 chainId, address gateway) external {
        require(gatewayFor[chainId] == address(0), "gateway already set");
        require(!registeredChains[chainId], "chain already registered");

        gatewayFor[chainId] = gateway;
        registeredChains[chainId] = true;
    }
}

contract PublicTrustedRemoteBootstrap {
    mapping(uint16 => bytes) public trustedRemoteLookup;

    function setTrustedRemote(uint16 remoteChainId, bytes calldata remotePath) external {
        require(trustedRemoteLookup[remoteChainId].length == 0, "remote already set");

        trustedRemoteLookup[remoteChainId] = remotePath;
    }
}
