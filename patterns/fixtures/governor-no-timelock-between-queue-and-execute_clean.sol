// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same queue-then-execute
/// governor shape as the vuln, but the execute() path REQUIRES a real
/// timelock delay to have elapsed before consuming the queued flag. The
/// `TIMELOCK_DELAY` / `eta` / `block.timestamp >= p.eta` tokens in the
/// body fail the negative regex, so the detector will not match.
contract GovernorNoTimelockBetweenQueueAndExecuteClean {
    struct Proposal {
        address proposer;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 eta;
        bytes payload;
        bool executed;
    }

    mapping(uint256 => Proposal) internal _proposals;
    mapping(uint256 => bool) internal _queued;
    uint256 public proposalCount;
    uint256 public constant TIMELOCK_DELAY = 2 days;

    function propose(bytes calldata payload) external returns (uint256 id) {
        id = ++proposalCount;
        _proposals[id] = Proposal({
            proposer: msg.sender,
            forVotes: 0,
            againstVotes: 0,
            eta: 0,
            payload: payload,
            executed: false
        });
    }

    function vote(uint256 id, bool support, uint256 weight) external {
        Proposal storage p = _proposals[id];
        if (support) p.forVotes += weight;
        else p.againstVotes += weight;
    }

    // queue() stamps the eta — this is the holder-exit window.
    function queue(uint256 id) external {
        Proposal storage p = _proposals[id];
        require(p.forVotes > p.againstVotes, "not passed");
        _queued[id] = true;
        p.eta = block.timestamp + TIMELOCK_DELAY;
    }

    // CLEAN: execute gates the queued flag behind the TIMELOCK_DELAY.
    // The regex checks for (timelock|TIMELOCK|delay|block.timestamp >= eta)
    // all present here, so the negative match fails and the detector will
    // NOT fire.
    function execute(uint256 id) external {
        Proposal storage p = _proposals[id];
        require(_queued[id] == true, "not queued");
        require(block.timestamp >= p.eta, "TIMELOCK_DELAY not elapsed");
        require(!p.executed, "already executed");
        p.executed = true;
        _queued[id] = false;
        (bool ok, ) = address(this).call(p.payload);
        require(ok, "exec failed");
    }
}
