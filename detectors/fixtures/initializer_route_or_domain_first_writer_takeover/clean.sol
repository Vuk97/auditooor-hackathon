// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovernedDomainRouteSetup {
    error NotGovernance();
    error SameChain();
    error ZeroGateway();

    address public immutable governance;
    uint32 public sourceChainId;
    uint32 public destinationChainId;
    address public remoteGateway;

    mapping(uint32 => mapping(uint32 => address)) public gatewayFor;

    constructor(address initialGovernance) {
        governance = initialGovernance;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    function configureRoute(
        uint32 _sourceChainId,
        uint32 _destinationChainId,
        address _remoteGateway
    ) external onlyGovernance {
        if (_sourceChainId == _destinationChainId) revert SameChain();
        if (_remoteGateway == address(0)) revert ZeroGateway();

        sourceChainId = _sourceChainId;
        destinationChainId = _destinationChainId;
        remoteGateway = _remoteGateway;
        gatewayFor[_sourceChainId][_destinationChainId] = _remoteGateway;
    }
}

contract FactoryBoundDomainFirstWriter {
    error NotFactory();
    error SameChain();
    error ZeroGateway();

    address public immutable factory;
    mapping(uint32 => mapping(uint32 => address)) public routes;

    constructor() {
        factory = msg.sender;
    }

    function migrateChainToGateway(
        uint32 sourceChainId,
        uint32 destinationChainId,
        address gateway
    ) external {
        if (msg.sender != factory) revert NotFactory();
        if (sourceChainId == destinationChainId) revert SameChain();
        if (gateway == address(0)) revert ZeroGateway();
        require(routes[sourceChainId][destinationChainId] == address(0), "route exists");

        routes[sourceChainId][destinationChainId] = gateway;
    }
}
