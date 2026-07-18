// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovernedRouteMigration {
    address public immutable governance;
    mapping(uint256 => mapping(uint256 => address)) public gatewayFor;
    mapping(bytes32 => bool) public routeCreated;
    mapping(uint256 => address) public migratedChains;

    error NotGovernance();
    error InvalidChain();
    error SameChain();
    error ZeroGateway();

    event RouteMigrated(uint256 sourceChainId, uint256 destinationChainId, address gateway);

    constructor(address initialGovernance) {
        governance = initialGovernance;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    function migrateChainToGateway(
        uint256 sourceChainId,
        uint256 destinationChainId,
        address gateway
    ) external onlyGovernance {
        if (sourceChainId == 0 || destinationChainId == 0) revert InvalidChain();
        if (sourceChainId == destinationChainId) revert SameChain();
        if (gateway == address(0)) revert ZeroGateway();

        bytes32 routeKey = keccak256(abi.encode(sourceChainId, destinationChainId));

        require(gatewayFor[sourceChainId][destinationChainId] == address(0), "route exists");
        require(!routeCreated[routeKey], "route created");

        gatewayFor[sourceChainId][destinationChainId] = gateway;
        routeCreated[routeKey] = true;
        migratedChains[sourceChainId] = gateway;

        emit RouteMigrated(sourceChainId, destinationChainId, gateway);
    }
}
