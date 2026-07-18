// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: replacing the payload invalidates voter notice and bumps the
// proposal version, so stale review state cannot be consumed.
contract OptimisticGovernorProposalUpdatePoisonSafe {
    mapping(uint256 => bytes32) internal proposalPayloadHash;
    mapping(uint256 => bool) internal voterNoticeInvalidated;
    mapping(uint256 => uint256) internal proposalVersion;

    function updateProposal(uint256 proposalId, bytes32 newPayloadHash) external {
        proposalPayloadHash[proposalId] = newPayloadHash;
        voterNoticeInvalidated[proposalId] = true;
        proposalVersion[proposalId] += 1;
    }

    function noticeWasInvalidated(uint256 proposalId) external view returns (bool) {
        return voterNoticeInvalidated[proposalId];
    }
}
