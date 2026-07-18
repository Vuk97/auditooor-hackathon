// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// governor-no-timelock-between-queue-and-execute detector. DO NOT DEPLOY.
///
/// This is the Beanstalk 2022 shape. `queue(id)` flips `_queued[id]` to
/// true. `execute(id)` consumes that flag and calls the proposal payload
/// with NO eta / TIMELOCK / delay / GRACE_PERIOD check in between. A
/// flashloan-voter can therefore queue AND execute in the same tx —
/// exactly what drained Beanstalk for ~$182M.
contract GovernorNoTimelockBetweenQueueAndExecuteVuln {
    struct Proposal {
        address proposer;
        uint256 forVotes;
        uint256 againstVotes;
        bytes payload;
        bool executed;
    }

    // Beanstalk-shape: a `_proposals` mapping AND a separate queued flag.
    mapping(uint256 => Proposal) internal _proposals;
    mapping(uint256 => bool) internal _queued;
    uint256 public proposalCount;

    function propose(bytes calldata payload) external returns (uint256 id) {
        id = ++proposalCount;
        _proposals[id] = Proposal({
            proposer: msg.sender,
            forVotes: 0,
            againstVotes: 0,
            payload: payload,
            executed: false
        });
    }

    function vote(uint256 id, bool support, uint256 weight) external {
        Proposal storage p = _proposals[id];
        if (support) p.forVotes += weight;
        else p.againstVotes += weight;
    }

    // The queue step sets the queued flag but writes NO eta / readyAt.
    function queue(uint256 id) external {
        Proposal storage p = _proposals[id];
        require(p.forVotes > p.againstVotes, "not passed");
        _queued[id] = true;
    }

    // VULN: execute consumes the queued flag with no time gate whatsoever.
    // No eta, no TIMELOCK_DELAY, no block.timestamp check, no guardian veto
    // window. A flashloan-voter calls queue() then execute() in the same
    // transaction and drains the treasury.
    function execute(uint256 id) external {
        Proposal storage p = _proposals[id];
        require(_queued[id] == true, "not queued");
        require(!p.executed, "already executed");
        p.executed = true;
        _queued[id] = false;
        (bool ok, ) = address(this).call(p.payload);
        require(ok, "exec failed");
    }
}
