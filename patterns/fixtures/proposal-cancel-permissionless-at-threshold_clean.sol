// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProposalCancelClean {
    struct Proposal { address proposer; bool canceled; }
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalThreshold = 10_000e18;

    function getVotes(address) public pure returns (uint256) { return 10_000e18; }

    // CLEAN: proposer can always cancel; third parties can only cancel
    // once votes drop STRICTLY below threshold.
    function cancel(uint256 id) external {
        Proposal storage p = proposals[id];
        require(
            msg.sender == p.proposer || getVotes(p.proposer) < proposalThreshold,
            "not authorized"
        );
        p.canceled = true;
    }
}
