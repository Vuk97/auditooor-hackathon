// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// timelock-immediate-execute detector. DO NOT DEPLOY.
///
/// The contract advertises a `minDelay` timelock on queued actions but
/// exposes admin-gated bypass paths (`executeImmediate`, `cancelTimelock`,
/// `overrideDelay`, `emergencyExecute`) that skip the delay entirely. Any
/// one of these turns the timelock into a marketing claim.
contract TimelockImmediateExecuteVuln {
    address public owner;
    uint256 public minDelay;
    uint256 public delay;

    struct Action {
        bytes32 id;
        uint256 eta;
        bool executed;
        bool canceled;
    }

    mapping(bytes32 => Action) public actions;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(uint256 _minDelay) {
        owner = msg.sender;
        minDelay = _minDelay;
        delay = _minDelay;
    }

    function queue(bytes32 id) external onlyOwner {
        actions[id] = Action({id: id, eta: block.timestamp + minDelay, executed: false, canceled: false});
    }

    // Honest execute path: enforces the eta.
    function execute(bytes32 id) external onlyOwner {
        Action storage a = actions[id];
        require(block.timestamp >= a.eta, "delay not elapsed");
        a.executed = true;
    }

    // VULN: admin-gated immediate execute skips the eta entirely.
    function executeImmediate(bytes32 id) external onlyOwner {
        Action storage a = actions[id];
        a.executed = true;
    }

    // VULN variant: cancelTimelock voids the pending action with no delay.
    function cancelTimelock(bytes32 id) external onlyOwner {
        Action storage a = actions[id];
        a.canceled = true;
    }

    // VULN variant: overrideDelay collapses the delay state var to zero.
    function overrideDelay(uint256 newDelay) external onlyOwner {
        delay = newDelay;
    }

    // VULN variant: emergencyExecute — same shape.
    function emergencyExecute(bytes32 id) external onlyOwner {
        Action storage a = actions[id];
        a.executed = true;
    }
}
