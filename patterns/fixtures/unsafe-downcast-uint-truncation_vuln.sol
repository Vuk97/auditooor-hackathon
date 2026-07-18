// SPDX-License-Identifier: MIT
// Fixture: unsafe-downcast-uint-truncation — VULNERABLE
pragma solidity ^0.8.20;

contract DowncastVuln {
    mapping(address => uint96) public votes;
    mapping(address => uint128) public staked;
    uint64 public proposalETA;

    // VULN: bare uint96 cast truncates if amount >= 2**96.
    function delegateMint(address to, uint256 amount) external {
        votes[to] = uint96(amount);
    }

    // VULN: bare uint128 cast on reward emission.
    function recordStake(uint256 amount) external {
        staked[msg.sender] = uint128(amount);
    }

    // VULN: bare uint64 cast on timestamp-like value.
    function scheduleProposal(uint256 eta) external {
        proposalETA = uint64(eta);
    }
}
