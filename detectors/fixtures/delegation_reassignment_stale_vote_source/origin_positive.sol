// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DelegationReassignmentStaleVoteSourceOriginPositive {
    struct Checkpoint {
        uint256 fromBlock;
        uint256[] delegatedTokenIds;
    }

    mapping(uint256 => uint256) public delegatedTo;
    mapping(uint256 => Checkpoint[]) public checkpoints;
    mapping(uint256 => uint256) public numCheckpoints;

    function delegate(uint256 tokenId, uint256 toTokenId) external {
        uint256 oldDelegate = delegatedTo[tokenId];
        delegatedTo[tokenId] = toTokenId;

        uint256 nCheckpoints = numCheckpoints[toTokenId];
        if (nCheckpoints > 0) {
            Checkpoint storage checkpoint = checkpoints[toTokenId][nCheckpoints - 1];
            checkpoint.delegatedTokenIds.push(tokenId);
            _writeCheckpoint(toTokenId, nCheckpoints, checkpoint.delegatedTokenIds);
        } else {
            checkpoints[toTokenId].push();
            checkpoints[toTokenId][0].fromBlock = block.number;
            checkpoints[toTokenId][0].delegatedTokenIds.push(tokenId);
            numCheckpoints[toTokenId] = 1;
        }

        oldDelegate;
    }

    function _writeCheckpoint(
        uint256 toTokenId,
        uint256 nCheckpoints,
        uint256[] storage delegatedIds
    ) internal {
        if (nCheckpoints == checkpoints[toTokenId].length) {
            checkpoints[toTokenId].push();
        }
        checkpoints[toTokenId][nCheckpoints].fromBlock = block.number;
        for (uint256 i = 0; i < delegatedIds.length; i++) {
            checkpoints[toTokenId][nCheckpoints].delegatedTokenIds.push(delegatedIds[i]);
        }
        numCheckpoints[toTokenId] = nCheckpoints + 1;
    }
}
