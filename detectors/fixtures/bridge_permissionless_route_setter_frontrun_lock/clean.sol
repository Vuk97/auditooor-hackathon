pragma solidity ^0.8.20;

contract BridgePermissionlessRouteSetterClean {
    address public owner;
    uint32 public sourceChainId;
    uint32 public destinationChainId;
    address public remoteBridge;

    event RouteConfigured(uint32 indexed sourceChainId, uint32 indexed destinationChainId, address remoteGateway);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    function setRemoteBridge(
        uint32 _sourceChainId,
        uint32 _destinationChainId,
        address _remoteBridge
    ) external onlyOwner {
        require(remoteBridge == address(0), "route exists");
        sourceChainId = _sourceChainId;
        destinationChainId = _destinationChainId;
        remoteBridge = _remoteBridge;
        emit RouteConfigured(_sourceChainId, _destinationChainId, _remoteBridge);
    }
}
