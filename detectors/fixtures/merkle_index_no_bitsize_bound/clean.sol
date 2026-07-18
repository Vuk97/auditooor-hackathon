pragma solidity ^0.8.20;

contract MerkleIndexNoBitsizeBoundClean {
    uint256 internal constant HISTORICAL_SUMMARIES_INDEX = 27;
    uint256 internal constant HISTORICAL_SUMMARIES_TREE_HEIGHT = 24;
    uint256 internal constant BLOCK_ROOT_TREE_HEIGHT = 13;
    uint256 internal constant WITHDRAWAL_TREE_HEIGHT = 4;

    struct WithdrawalProof {
        uint64 historicalSummaryIndex;
        uint64 blockRootIndex;
        uint64 withdrawalIndex;
        bytes32[] proof;
    }

    function verifyWithdrawal(WithdrawalProof calldata proofData) external pure returns (bool) {
        require(proofData.historicalSummaryIndex < 2 ** HISTORICAL_SUMMARIES_TREE_HEIGHT, "historical summary index");
        require(proofData.blockRootIndex < 2 ** BLOCK_ROOT_TREE_HEIGHT, "block root index");
        require(proofData.withdrawalIndex < 2 ** WITHDRAWAL_TREE_HEIGHT, "withdrawal index");

        uint256 historicalBranch =
            uint256(proofData.historicalSummaryIndex) << (BLOCK_ROOT_TREE_HEIGHT + WITHDRAWAL_TREE_HEIGHT);
        uint256 compositeIndex =
            (HISTORICAL_SUMMARIES_INDEX << (HISTORICAL_SUMMARIES_TREE_HEIGHT + BLOCK_ROOT_TREE_HEIGHT + WITHDRAWAL_TREE_HEIGHT))
            | historicalBranch
            | (proofData.blockRootIndex << WITHDRAWAL_TREE_HEIGHT)
            | proofData.withdrawalIndex;

        return verifyInclusionBeacon(compositeIndex, proofData.proof);
    }

    function verifyInclusionBeacon(uint256, bytes32[] calldata) internal pure returns (bool) {
        return true;
    }
}
