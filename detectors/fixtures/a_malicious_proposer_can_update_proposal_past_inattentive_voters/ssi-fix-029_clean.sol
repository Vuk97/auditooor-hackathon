// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProposalUpdatePastInattentiveVotersClean {
    mapping(uint256 => bytes32) internal proposalPayloadHash;
    mapping(uint256 => bool) internal voterNoticeInvalidated;

    function updateProposal(uint256 proposalId, bytes32 newPayloadHash) external {
        proposalPayloadHash[proposalId] = newPayloadHash;
        voterNoticeInvalidated[proposalId] = true;
    }

    function voterNoticeWasInvalidated(uint256 proposalId) external view returns (bool) {
        return voterNoticeInvalidated[proposalId];
    }
}
