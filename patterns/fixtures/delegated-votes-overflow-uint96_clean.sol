// SPDX-License-Identifier: MIT
// Fixture: delegated-votes-overflow-uint96 — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

library SafeCast {
    function toUint96(uint256 v) internal pure returns (uint96) {
        require(v <= type(uint96).max, "SafeCast: uint96 overflow");
        return uint96(v);
    }
}

contract CleanVotesToken {
    using SafeCast for uint256;

    struct Checkpoint {
        uint32 fromBlock;
        uint96 votes;
    }

    mapping(address => mapping(uint32 => Checkpoint)) public checkpoints;
    mapping(address => uint32) public numCheckpoints;
    mapping(address => address) public delegates;
    mapping(address => uint96) public delegatedVotes;

    uint256 public constant MAX_UINT96 = type(uint96).max;

    // CLEAN fix #1: route every uint96 assignment through SafeCast so an
    // overflow is a clean revert at the cast site, not a silent truncation.
    function moveDelegateSafe(address from, address to, uint256 amount) external {
        if (from != to && amount > 0) {
            if (from != address(0)) {
                uint256 oldFromVotes = delegatedVotes[from];
                uint96 newFromVotes = (oldFromVotes - amount).toUint96();
                delegatedVotes[from] = newFromVotes;
                _writeCheckpoint(from, newFromVotes);
            }
            if (to != address(0)) {
                uint256 oldToVotes = delegatedVotes[to];
                uint96 newToVotes = (oldToVotes + amount).toUint96();
                delegatedVotes[to] = newToVotes;
                _writeCheckpoint(to, newToVotes);
            }
        }
    }

    // CLEAN fix #2: enforce a supply cap so vote totals can never exceed
    // type(uint96).max. _checkMaxSupply is exactly the guard the DSL
    // negative-regex recognises.
    function mint(address to, uint256 amount) external {
        _checkMaxSupply(amount);
        delegatedVotes[to] += uint96(amount);
    }

    function _checkMaxSupply(uint256 delta) internal view {
        require(delta <= type(uint96).max, "supply cap");
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
