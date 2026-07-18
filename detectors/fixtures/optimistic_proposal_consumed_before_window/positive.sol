// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProposalTarget {
    function install(bytes4 selector, address target) external;
}

contract OptimisticProposalWindowPositive {
    struct Proposal {
        address target;
        bytes data;
        bytes4 selector;
        bool consumed;
    }

    mapping(uint256 => Proposal) public proposals;
    IProposalTarget public installer;

    constructor(IProposalTarget installer_) {
        installer = installer_;
    }

    function executeProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        proposal.consumed = true;
        (bool ok, ) = proposal.target.call(proposal.data);
        require(ok, "call failed");
    }

    function applyProposal(uint256 id) external {
        Proposal storage proposal = proposals[id];
        proposal.consumed = true;
        installer.install(proposal.selector, proposal.target);
    }
}
