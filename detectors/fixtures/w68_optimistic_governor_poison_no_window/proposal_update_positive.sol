// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: a proposer can replace the queued payload without invalidating
// voter notice, version, or the commitment voters reviewed.
contract OptimisticGovernorProposalUpdatePoisonVulnerable {
    mapping(uint256 => bytes32) internal proposalPayloadHash;
    mapping(uint256 => bool) internal voterNoticeInvalidated;

    function updateProposal(uint256 proposalId, bytes32 newPayloadHash) external {
        proposalPayloadHash[proposalId] = newPayloadHash;
    }

    function noticeWasInvalidated(uint256 proposalId) external view returns (bool) {
        return voterNoticeInvalidated[proposalId];
    }
}
