pragma solidity ^0.8.20;

contract MaliciousProposalCountClean {
    enum ProposalState {
        Pending,
        Active,
        Updatable,
        Expired
    }

    mapping(address => uint256) internal latestProposalIds;
    mapping(uint256 => ProposalState) internal proposalStates;

    function updateProposal(uint256 proposalId) external {
        proposalStates[proposalId] = ProposalState.Updatable;
    }

    function checkNoActiveProp(address proposer) internal view {
        uint256 latestProposalId = latestProposalIds[proposer];
        ProposalState state = proposalStates[latestProposalId];
        require(
            state != ProposalState.Pending &&
                state != ProposalState.Active &&
                state != ProposalState.Updatable,
            "one live proposal per proposer"
        );
    }
}
