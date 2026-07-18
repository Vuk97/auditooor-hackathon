pragma solidity ^0.8.20;

contract AnyTrustFastConfirmerVulnerable {
    struct AssertionNode {
        bytes32 parentAssertionHash;
        bytes32 confirmState;
        uint8 status;
    }

    mapping(bytes32 => AssertionNode) internal assertions;
    address internal fastConfirmer;

    function seed(bytes32 assertionHash, bytes32 parentHash, bytes32 stateHash) external {
        assertions[assertionHash] = AssertionNode({
            parentAssertionHash: parentHash,
            confirmState: stateHash,
            status: 1
        });
    }

    function fastConfirmNewAssertion(bytes32 assertionHash) external {
        require(msg.sender == fastConfirmer, "fast confirmer only");

        AssertionNode storage node = assertions[assertionHash];
        bytes32 parentAssertionHash = node.parentAssertionHash;
        bytes32 confirmState = node.confirmState;

        require(parentAssertionHash != bytes32(0), "missing parent");
        require(confirmState != bytes32(0), "missing confirm state");
        require(node.status == 1, "not pending");

        node.status = 2;
    }
}
