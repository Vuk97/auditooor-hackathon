// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Governance vote entrypoints read caller's CURRENT balance
// rather than a historical snapshot. A flash-loan within a single tx
// can inflate balanceOf(msg.sender) across the vote() boundary and
// buy arbitrary voting power for the cost of the flash-loan fee.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract VoteSnapshotVuln {
    IERC20 public immutable token;

    // Governance / gauge state. The precondition regex
    // `gauge|votes|voting|voter|delegatee` matches `votes`, `voter`,
    // `voting`, and `delegatee` here.
    mapping(uint256 => mapping(address => uint256)) public votes;
    mapping(address => address) public delegatee;
    mapping(uint256 => bool) public voting;
    mapping(address => uint256) public voter;
    mapping(bytes32 => uint256) public gauge;

    constructor(address _t) {
        token = IERC20(_t);
    }

    // VULN shape 1: `vote` reads live balanceOf(msg.sender) as weight.
    function vote(uint256 proposalId, bool support) external {
        uint256 weight = token.balanceOf(msg.sender);
        if (support) votes[proposalId][msg.sender] = weight;
    }

    // VULN shape 2: `castVote` uses mapping-style balances[msg.sender].
    // Here the "balances" is an internal bookkeeping variable, but the
    // regex is intentionally generic: attacker can still manipulate
    // the balance in a single tx via deposit / flash-mint.
    mapping(address => uint256) public balances;
    function castVote(uint256 proposalId) external {
        uint256 weight = balances[msg.sender];
        votes[proposalId][msg.sender] = weight;
    }

    // VULN shape 3: underscore-prefixed internal wrapper used as a
    // public vote entrypoint (Solidly / ve-token style).
    function _castVote(uint256 proposalId, address v) external {
        uint256 weight = token.balanceOf(v);
        votes[proposalId][v] = weight;
    }

    // VULN shape 4: submitVote / voteFor names.
    function submitVote(uint256 proposalId) external {
        uint256 weight = token.balanceOf(msg.sender);
        votes[proposalId][msg.sender] = weight;
    }
}
