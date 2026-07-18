// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BoundGatewayMigrator {
    address public immutable deployer;
    address public owner;
    address public remoteGateway;
    mapping(uint256 => mapping(uint256 => address)) public routes;

    constructor() {
        deployer = msg.sender;
    }

    function migrateToGateway(
        uint256 sourceChainId,
        uint256 destinationChainId,
        address newRemoteGateway,
        address newOwner
    ) external {
        require(msg.sender == deployer, "not deployer");
        require(owner == address(0), "owner already set");
        require(remoteGateway == address(0), "gateway already set");
        require(routes[sourceChainId][destinationChainId] == address(0), "route already set");

        owner = newOwner;
        remoteGateway = newRemoteGateway;
        routes[sourceChainId][destinationChainId] = newRemoteGateway;
    }
}

contract GovernedChainGatewayRegistry {
    address public immutable governance;
    mapping(uint256 => address) public gatewayFor;
    mapping(uint256 => bool) public registeredChains;

    constructor(address initialGovernance) {
        governance = initialGovernance;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "not governance");
        _;
    }

    function registerChain(uint256 chainId, address gateway) external onlyGovernance {
        require(gatewayFor[chainId] == address(0), "gateway already set");
        require(!registeredChains[chainId], "chain already registered");

        gatewayFor[chainId] = gateway;
        registeredChains[chainId] = true;
    }
}

contract FactoryBoundTrustedRemoteBootstrap {
    address public immutable factory;
    mapping(uint16 => bytes) public trustedRemoteLookup;

    constructor() {
        factory = msg.sender;
    }

    function setTrustedRemote(uint16 remoteChainId, bytes calldata remotePath) external {
        require(msg.sender == factory, "not factory");
        require(trustedRemoteLookup[remoteChainId].length == 0, "remote already set");

        trustedRemoteLookup[remoteChainId] = remotePath;
    }
}
