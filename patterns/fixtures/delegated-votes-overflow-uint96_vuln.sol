// SPDX-License-Identifier: MIT
// Fixture: delegated-votes-overflow-uint96 — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract VulnVotesToken {
    // Precondition: contract holds vote-related state (votes, checkpoints).
    struct Checkpoint {
        uint32 fromBlock;
        uint96 votes;
    }

    mapping(address => mapping(uint32 => Checkpoint)) public checkpoints;
    mapping(address => uint32) public numCheckpoints;
    mapping(address => address) public delegates;
    mapping(address => uint96) public delegatedVotes;

    // VULN: function performs uint96 vote-weight arithmetic with no
    // SafeCast, no `require(x <= type(uint96).max)`, no supply cap.
    // Any raw arithmetic over delegatedVotes can silently truncate in
    // unchecked blocks (or revert in Solidity >=0.8) once token supply
    // crosses 2^96. No defense → detector MUST fire.
    function moveDelegate(address from, address to, uint96 amount) external {
        if (from != to && amount > 0) {
            if (from != address(0)) {
                uint96 oldFromVotes = delegatedVotes[from];
                uint96 newFromVotes = oldFromVotes - amount;
                delegatedVotes[from] = newFromVotes;
                _writeCheckpoint(from, newFromVotes);
            }
            if (to != address(0)) {
                uint96 oldToVotes = delegatedVotes[to];
                uint96 newToVotes = oldToVotes + amount;
                delegatedVotes[to] = newToVotes;
                _writeCheckpoint(to, newToVotes);
            }
        }
    }

    function _writeCheckpoint(address account, uint96 votes) internal {
        uint32 n = numCheckpoints[account];
        checkpoints[account][n] = Checkpoint({
            fromBlock: uint32(block.number),
            votes: votes
        });
        numCheckpoints[account] = n + 1;
    }
}
