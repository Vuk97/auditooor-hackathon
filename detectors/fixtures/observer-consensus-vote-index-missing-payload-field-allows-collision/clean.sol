// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ObserverConsensusTssClean {
    struct TssVote {
        uint256 chainId;
        address creator;
        bytes32 txHash;
        uint8 observerType;
        bytes newPubKey;
    }

    mapping(bytes32 => bytes) public payloadByBallot;

    function ballotIdentifier(TssVote calldata vote) public pure returns (bytes32) {
        return keccak256(abi.encode(vote.chainId, vote.creator, vote.txHash, vote.observerType, vote.newPubKey));
    }

    function submitTssVote(TssVote calldata vote) external {
        bytes32 index = ballotIdentifier(vote);
        payloadByBallot[index] = vote.newPubKey;
    }
}
