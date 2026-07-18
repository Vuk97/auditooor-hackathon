pragma solidity ^0.8.20;

contract BridgeReplayKeyDomainClean {
    mapping(bytes32 => bool) public processedMessages;

    event MessageProcessed(uint32 sourceDomain, uint32 destinationDomain, bytes32 key);

    function receiveMessage(
        uint32 sourceDomain,
        uint32 destinationDomain,
        address sender,
        uint256 nonce,
        bytes calldata payload
    ) external {
        require(destinationDomain == uint32(block.chainid), "wrong destination");

        bytes32 key = keccak256(
            abi.encode(sourceDomain, destinationDomain, address(this), sender, nonce, payload)
        );
        require(!processedMessages[key], "already processed");

        processedMessages[key] = true;
        emit MessageProcessed(sourceDomain, destinationDomain, key);
    }
}
