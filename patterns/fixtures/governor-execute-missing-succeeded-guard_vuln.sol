// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovernorVuln {
    enum ProposalState { Pending, Active, Defeated, Succeeded, Expired, Executed }

    struct Proposal { address target; bytes data; ProposalState state; }
    mapping(uint256 => Proposal) public proposals;

    // VULN: no check state == Succeeded
    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        (bool ok, ) = p.target.call(p.data);
        require(ok, "call fail");
        p.state = ProposalState.Executed;
    }
}
