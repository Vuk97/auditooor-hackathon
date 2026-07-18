// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: TSS/observer consensus ballot identifier omits the newPubKey field
// from the keccak256 preimage. Two votes with different newPubKey values
// produce the same ballot ID, enabling payload collision/overwrite.
// Real-world basis: ZetaChain observer-consensus-vote-index-missing-payload-field-allows-collision

contract CrossChainConsensusBallotVuln {
    struct TssVote {
        uint256 chainId;
        address creator;
        bytes32 txHash;
        uint8 observerType;
        bytes newPubKey;    // KEY PAYLOAD FIELD - controls which key gets installed
    }

    mapping(bytes32 => bytes) public payloadByBallot;
    mapping(bytes32 => uint256) public voteCount;
    uint256 public constant QUORUM = 3;

    // VULN: ballotIdentifier omits vote.newPubKey from the preimage.
    // Two votes with different newPubKey values produce identical ballot IDs.
    function ballotIdentifier(TssVote calldata vote) public pure returns (bytes32) {
        return keccak256(abi.encode(
            vote.chainId,
            vote.creator,
            vote.txHash,
            vote.observerType
            // MISSING: vote.newPubKey
        ));
    }

    // Attacker can overwrite the legitimate newPubKey by submitting a vote
    // with the same (chainId, creator, txHash, observerType) but malicious newPubKey.
    function submitTssVote(TssVote calldata vote) external {
        bytes32 index = ballotIdentifier(vote);
        payloadByBallot[index] = vote.newPubKey;  // overwrites on collision
        voteCount[index]++;
    }

    function finalizeIfQuorum(bytes32 ballotId) external view returns (bytes memory) {
        require(voteCount[ballotId] >= QUORUM, "insufficient votes");
        return payloadByBallot[ballotId]; // attacker-controlled key installed
    }
}
