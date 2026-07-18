// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteDoubleCountStaleSourceRetentionClean {
    mapping(uint256 => address) public delegateOf;
    mapping(address => uint256[]) public delegatedSources;
    mapping(uint256 => uint256) public votingPower;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => uint256) public forVotes;

    function reassignAndRevote(uint256 proposalId, uint256 sourceId, address newDelegate) external {
        require(!hasVoted[proposalId][msg.sender], "already voted");
        hasVoted[proposalId][msg.sender] = true;

        address oldDelegate = delegateOf[sourceId];
        if (oldDelegate != address(0)) {
            _removeDelegation(oldDelegate, sourceId);
        }

        delegateOf[sourceId] = newDelegate;
        delegatedSources[newDelegate].push(sourceId);
        uint256 weight = votingPower[sourceId];
        forVotes[proposalId] += weight;
    }

    function _removeDelegation(address oldDelegate, uint256 sourceId) internal {
        uint256[] storage sources = delegatedSources[oldDelegate];
        for (uint256 i = 0; i < sources.length; i++) {
            if (sources[i] == sourceId) {
                sources[i] = sources[sources.length - 1];
                sources.pop();
                return;
            }
        }
    }
}
