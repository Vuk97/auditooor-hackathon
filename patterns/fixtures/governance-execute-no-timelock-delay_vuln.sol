// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// governance-execute-no-timelock-delay detector. DO NOT DEPLOY.
///
/// The contract exposes `execute(proposalId)` which flips a Succeeded
/// proposal to Executed in the same block voting ends, without any
/// timelock/delay/eta/canExecute gate. A majority voter can therefore
/// land a treasury drain or malicious upgrade immediately after the
/// vote closes, before dissenting holders can observe the outcome and
/// exit.
contract GovernanceExecuteNoTimelockDelayVuln {
    enum State { Pending, Active, Succeeded, Executed, Failed }

    struct Proposal {
        uint256 id;
        address proposer;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        State state;
        bytes payload;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
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

    function finalize(uint256 id) external {
        Proposal storage p = proposals[id];
        require(block.number > p.endBlock, "voting not ended");
        if (p.forVotes > p.againstVotes) {
            p.state = State.Succeeded;
        } else {
            p.state = State.Failed;
        }
    }

    // VULN: execute runs immediately after voting ends. No timelock,
    // no eta, no canExecute gate. The only precondition is that the
    // proposal reached Succeeded state, which `finalize` set in the
    // same or previous block. A majority voter drains here, before
    // dissenting holders can exit.
    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.state == State.Succeeded, "not succeeded");
        p.state = State.Executed;
        // Payload would be dispatched here in a real governor.
        (bool ok, ) = address(this).call(p.payload);
        require(ok, "exec failed");
    }
}
