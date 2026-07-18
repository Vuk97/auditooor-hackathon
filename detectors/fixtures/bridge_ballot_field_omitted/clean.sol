// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: TSS/observer consensus ballot identifier includes ALL payload fields.
// Two votes with different newPubKey values produce distinct ballot IDs.

contract CrossChainConsensusBallotClean {
    struct TssVote {
        uint256 chainId;
        address creator;
        bytes32 txHash;
        uint8 observerType;
        bytes newPubKey;
    }

    mapping(bytes32 => bytes) public payloadByBallot;
    mapping(bytes32 => uint256) public voteCount;
    uint256 public constant QUORUM = 3;

    // CLEAN: ballotIdentifier includes vote.newPubKey in the preimage.
    // Different newPubKey values produce different ballot IDs - no collision possible.
    function ballotIdentifier(TssVote calldata vote) public pure returns (bytes32) {
        return keccak256(abi.encode(
            vote.chainId,
            vote.creator,
            vote.txHash,
            vote.observerType,
            vote.newPubKey   // INCLUDED: payload field bound to identifier
        ));
    }

    function submitTssVote(TssVote calldata vote) external {
        bytes32 index = ballotIdentifier(vote);
        require(payloadByBallot[index].length == 0 || keccak256(payloadByBallot[index]) == keccak256(vote.newPubKey), "payload mismatch");
        payloadByBallot[index] = vote.newPubKey;
        voteCount[index]++;
    }

    function finalizeIfQuorum(bytes32 ballotId) external view returns (bytes memory) {
        require(voteCount[ballotId] >= QUORUM, "insufficient votes");
        return payloadByBallot[ballotId];
    }
}
