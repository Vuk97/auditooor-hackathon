// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. This contract has all
/// the governance preconditions (proposals state var, execute function
/// whose body references Succeeded state), but it gates execution on a
/// timelock `eta` elapsing. The detector's
/// `body_not_contains_regex` on timelock-indicator tokens (timelock,
/// delay, eta, canExecute, block.timestamp >= eta) should cause the
/// match to fail.
contract GovernanceExecuteNoTimelockDelayClean {
    enum State { Pending, Active, Succeeded, Queued, Executed, Failed }

    struct Proposal {
        uint256 id;
        address proposer;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 eta;
        State state;
        bytes payload;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public constant MIN_DELAY = 2 days;
    address public governance;

    constructor() {
        governance = msg.sender;
    }

    function propose(bytes calldata payload) external returns (uint256 id) {
        id = ++proposalCount;
        proposals[id] = Proposal({
            id: id,
            proposer: msg.sender,
            endBlock: block.number + 100,
            forVotes: 0,
            againstVotes: 0,
            eta: 0,
            state: State.Active,
            payload: payload
        });
    }

    function vote(uint256 id, bool support, uint256 weight) external {
        Proposal storage p = proposals[id];
        require(p.state == State.Active, "not active");
        if (support) {
            p.forVotes += weight;
        } else {
            p.againstVotes += weight;
        }
    }

    function queue(uint256 id) external {
        Proposal storage p = proposals[id];
        require(block.number > p.endBlock, "voting not ended");
        require(p.forVotes > p.againstVotes, "not succeeded");
        p.state = State.Queued;
        p.eta = block.timestamp + MIN_DELAY;
    }

    // CLEAN: execute is gated on the timelock eta elapsing. The
    // `block.timestamp >= p.eta` check is the dissenting-holder exit
    // window; the body regex the detector looks for (timelock/delay/eta/
    // canExecute) is present, so the negative match fails and the
    // detector does NOT fire.
    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.state == State.Queued, "not queued");
        require(block.timestamp >= p.eta, "timelock delay not elapsed");
        p.state = State.Executed;
        (bool ok, ) = address(this).call(p.payload);
        require(ok, "exec failed");
    }
}
