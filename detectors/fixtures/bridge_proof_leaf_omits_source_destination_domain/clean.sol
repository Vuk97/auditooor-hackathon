pragma solidity ^0.8.20;

contract BridgeProofDomainClean {
    mapping(bytes32 => bool) public acceptedRoots;
    mapping(bytes32 => bool) public consumedProofs;

    event BridgeProofAccepted(uint32 sourceDomain, uint32 destinationDomain, bytes32 proofLeaf);

    function verifyBridgeProof(
        uint32 sourceDomain,
        uint32 destinationDomain,
        bytes32 root,
        bytes32 leaf,
        uint256 nonce,
        bytes32[] calldata proof
    ) external {
        require(destinationDomain == uint32(block.chainid), "wrong destination");
        require(acceptedRoots[root], "unknown root");

        bytes32 proofLeaf = keccak256(
            abi.encode(sourceDomain, destinationDomain, address(this), leaf, root, nonce)
        );
        require(!consumedProofs[proofLeaf], "already consumed");
        require(_verify(proof, root, proofLeaf), "bad proof");

        consumedProofs[proofLeaf] = true;
        emit BridgeProofAccepted(sourceDomain, destinationDomain, proofLeaf);
    }

    function _verify(bytes32[] calldata, bytes32, bytes32) internal pure returns (bool) {
        return true;
    }
}
