pragma solidity ^0.8.20;

contract AMissedRequirementPositive {
    uint256 internal updateDistributionEventCollectionIdsState;
    uint256 internal distributionNonce;

    function updateDistributionEventCollectionIds() external returns (bool) {
        distributionNonce += 1;
        return updateDistributionEventCollectionIdsState > 0;
    }
}
