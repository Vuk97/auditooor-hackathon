pragma solidity ^0.8.20;

contract BridgeRouteClean {
    error SameChainId();

    uint32 public sourceChainId;
    uint32 public destinationChainId;
    address public remoteGateway;

    event RouteConfigured(uint32 sourceChainId, uint32 destinationChainId, address remoteGateway);

    function configureRoute(
        uint32 _sourceChainId,
        uint32 _destinationChainId,
        address _remoteGateway
    ) external {
        require(_sourceChainId != _destinationChainId, "same chain");

        sourceChainId = _sourceChainId;
        destinationChainId = _destinationChainId;
        remoteGateway = _remoteGateway;

        emit RouteConfigured(_sourceChainId, _destinationChainId, _remoteGateway);
    }
}
