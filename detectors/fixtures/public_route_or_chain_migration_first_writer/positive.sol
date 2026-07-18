// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PublicRouteMigrationFirstWriter {
    mapping(uint256 => mapping(uint256 => address)) public gatewayFor;
    mapping(bytes32 => bool) public routeCreated;
    mapping(uint256 => address) public migratedChains;

    event RouteMigrated(uint256 sourceChainId, uint256 destinationChainId, address gateway);

    function migrateChainToGateway(
        uint256 sourceChainId,
        uint256 destinationChainId,
        address gateway
    ) external {
        bytes32 routeKey = keccak256(abi.encode(sourceChainId, destinationChainId));

        require(gatewayFor[sourceChainId][destinationChainId] == address(0), "route exists");
        require(!routeCreated[routeKey], "route created");

        gatewayFor[sourceChainId][destinationChainId] = gateway;
        routeCreated[routeKey] = true;
        migratedChains[sourceChainId] = gateway;

        emit RouteMigrated(sourceChainId, destinationChainId, gateway);
    }
}
