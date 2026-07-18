// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProposalCancelVuln {
    struct Proposal { address proposer; bool canceled; }
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalThreshold = 10_000e18;

    function getVotes(address) public pure returns (uint256) { return 10_000e18; }

    // VULN: uses `<=` instead of strict `<` against proposalThreshold.
    // Also no `msg.sender == proposer` escape hatch. Anyone can cancel
    // an at-threshold proposer's live proposal.
    function cancel(uint256 id) external {
        Proposal storage p = proposals[id];
        require(getVotes(p.proposer) <= proposalThreshold, "above threshold");
        p.canceled = true;
    }
}
