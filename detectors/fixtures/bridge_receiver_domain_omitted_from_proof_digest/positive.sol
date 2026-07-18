pragma solidity ^0.8.20;

interface IBridgeApplicationReceiver {
    function handleBridgeMessage(uint32 applicationDomain, bytes calldata payload) external;
}

contract BridgeReceiverDomainPositive {
    mapping(bytes32 => bool) public acceptedExportRoots;
    mapping(bytes32 => bool) public consumedDigests;

    event ReceiverMessageApplied(uint32 applicationDomain, address receiver, bytes32 replayDigest);

    function applyReceiverMessage(
        uint32 applicationDomain,
        bytes32 exportRoot,
        bytes32 receipt,
        address receiver,
        bytes calldata payload,
        bytes32[] calldata proof
    ) external {
        require(acceptedExportRoots[exportRoot], "unknown export root");

        bytes32 payloadHash = keccak256(payload);
        bytes32 replayDigest = keccak256(abi.encode(exportRoot, receipt, receiver, payloadHash));
        require(!consumedDigests[replayDigest], "already consumed");
        require(_verify(proof, exportRoot, replayDigest), "bad proof");

        consumedDigests[replayDigest] = true;
        IBridgeApplicationReceiver(receiver).handleBridgeMessage(applicationDomain, payload);

        emit ReceiverMessageApplied(applicationDomain, receiver, replayDigest);
    }

    function _verify(bytes32[] calldata, bytes32, bytes32) internal pure returns (bool) {
        return true;
    }
}
